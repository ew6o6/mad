"""
MCP Forensics - Cursor Log Transformer
Cursor IDE log file parser

Parses Cursor IDE log files to extract MCP-related events.

Log file locations:
- Windows: %APPDATA%/Cursor/logs/
- macOS: ~/Library/Logs/Cursor/
- Linux: ~/.config/Cursor/logs/

Key log files:
- main.log: Main process log
- renderer*.log: UI renderer logs
- exthost*.log: Extension host logs (may contain MCP information)
"""

import re
import json
from pathlib import Path
from typing import Union, Optional, Dict, Any, List, Generator
from datetime import datetime

from .base import BaseTransformer
from ..models import (
    MCPEntities,
    MCPServer,
    MCPTool,
    OrphanedTool,
    Timeline,
    MCPEvent,
    ToolCallEvent,
    ToolResultEvent,
    EventType,
    EventSeverity,
    ServerType,
    TransportType,
    ArtifactSource
)


class CursorLogTransformer(BaseTransformer):
    """
    Cursor IDE Log Transformer

    Parses Cursor log files to:
    1. Extract MCP-related log entries
    2. Identify tool call/result events
    3. Extract errors and warnings
    4. Build timeline
    """
    
    def __init__(self):
        super().__init__(name="cursor_log")
        self.source = ArtifactSource.CURSOR_LOG
        
        # MCP-related keywords
        self.mcp_keywords = [
            "mcp",
            "MCP",
            "mcpServer",
            "mcpServers",
            "tools/call",
            "tools/list",
            "resources/list",
            "resources/read",
            "jsonrpc",
            "JSON-RPC",
            "streamableHttp",
            "initialize",
            "initialized"
        ]
        
        # Log level pattern
        self.log_level_pattern = re.compile(
            r'\[(info|warn|warning|error|debug)\]',
            re.IGNORECASE
        )
        
        # Timestamp patterns
        self.timestamp_patterns = [
            # ISO 8601
            re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)'),
            # Log format
            re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)'),
            # Bracket format
            re.compile(r'\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]')
        ]
        
        # JSON-RPC message pattern
        self.jsonrpc_pattern = re.compile(r'\{[^{}]*"jsonrpc"[^{}]*\}')

        # Tool call pattern
        self.tool_call_pattern = re.compile(
            r'tools/call.*?(?:name|tool)["\s:]+(["\w\-_]+)',
            re.IGNORECASE
        )

        # Tool count pattern (e.g., "Found 14 tools")
        self.tool_count_pattern = re.compile(r'Found\s+(\d+)\s+tools', re.IGNORECASE)

        # Server command pattern (e.g., "Starting new stdio process with command: ...")
        self.command_pattern = re.compile(r'Starting new stdio process with command:\s*(.+)', re.IGNORECASE)
    
    def can_process(self, artifact_path: Union[str, Path]) -> bool:
        """Check if this is a Cursor log file/directory"""
        path = Path(artifact_path)

        if path.is_dir():
            # If directory, check if it contains log files
            log_files = list(path.glob("*.log"))
            return len(log_files) > 0

        if path.is_file():
            # If file, check if it's a log file
            return path.suffix == ".log"

        return False
    
    def extract_entities(self, artifact_path: Union[str, Path]) -> MCPEntities:
        """Extract MCP entities from Cursor logs"""
        path = Path(artifact_path)
        entities = MCPEntities()
        entities.analysis_timestamp = datetime.now()
        entities.artifact_sources = [str(path)]

        # Track discovered servers and tools
        discovered_servers: Dict[str, MCPServer] = {}
        discovered_tools: Dict[str, OrphanedTool] = {}

        # Process log files
        log_files = self._get_log_files(path)

        for log_file in log_files:
            self.logger.info(f"Processing log file: {log_file}")

            # Extract server name from log filename (e.g., "MCP user-filesystem.log" -> "user-filesystem")
            server_name = self._extract_server_name_from_filename(log_file.name)
            server_command = None
            tool_count = 0

            for line in self._read_log_lines(log_file):
                # Extract server command
                cmd_match = self.command_pattern.search(line)
                if cmd_match and not server_command:
                    server_command = cmd_match.group(1).strip()

                # Extract tool count (use the last value found)
                count_match = self.tool_count_pattern.search(line)
                if count_match:
                    tool_count = int(count_match.group(1))

                # Check if line is MCP-related
                if not self._is_mcp_related(line):
                    continue

                # Extract tool information
                tool_info = self._extract_tool_info(line)
                if tool_info:
                    tool_name = tool_info.get("name", "unknown")
                    tool_server = tool_info.get("server", server_name)

                    if tool_server and tool_server in discovered_servers:
                        # Add tool to server
                        server = discovered_servers[tool_server]
                        if not any(t.name == tool_name for t in server.tools):
                            server.tools.append(MCPTool(
                                name=tool_name,
                                server_name=tool_server
                            ))
                    else:
                        # Orphaned tool
                        if tool_name not in discovered_tools:
                            discovered_tools[tool_name] = OrphanedTool(
                                name=tool_name,
                                source=ArtifactSource.CURSOR_LOG,
                                probable_server=tool_server
                            )
                        discovered_tools[tool_name].call_count += 1

            # Add server if server name exists
            if server_name:
                if server_name not in discovered_servers:
                    discovered_servers[server_name] = MCPServer(
                        name=server_name,
                        server_type=ServerType.LOCAL,
                        transport=TransportType.STDIO,
                        command=server_command,
                        sources=[ArtifactSource.CURSOR_LOG]
                    )
                else:
                    # Update command for existing server
                    if server_command:
                        discovered_servers[server_name].command = server_command

                # Save tool count (even if actual tool list is empty)
                if tool_count > 0:
                    discovered_servers[server_name].tool_count = tool_count

        # Save results
        entities.servers = list(discovered_servers.values())
        entities.orphaned_tools = list(discovered_tools.values())

        self.logger.info(f"Extracted {len(entities.servers)} servers, "
                        f"{len(entities.orphaned_tools)} orphaned tools from logs")

        return entities

    def _extract_server_name_from_filename(self, filename: str) -> Optional[str]:
        """Extract MCP server name from log filename (e.g., 'MCP user-filesystem.log' -> 'user-filesystem')"""
        # Filename pattern starting with MCP
        match = re.match(r'MCP\s+(.+)\.log', filename, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
    
    def extract_events(self, artifact_path: Union[str, Path]) -> Timeline:
        """Extract events from Cursor logs"""
        path = Path(artifact_path)
        timeline = Timeline()
        timeline.sources = [ArtifactSource.CURSOR_LOG]

        log_files = self._get_log_files(path)

        for log_file in log_files:
            self.logger.info(f"Extracting events from: {log_file}")

            for line in self._read_log_lines(log_file):
                # Check if line is MCP-related
                if not self._is_mcp_related(line):
                    continue

                # Extract event
                event = self._parse_log_line(line, log_file.name)
                if event:
                    timeline.add_event(event)

        self.logger.info(f"Extracted {len(timeline.events)} events from logs")
        return timeline
    
    def _get_log_files(self, path: Path) -> List[Path]:
        """Get list of log files"""
        if path.is_file():
            return [path]

        log_files = []

        # Priority log files first
        priority_patterns = ["main.log", "exthost*.log", "renderer*.log"]

        for pattern in priority_patterns:
            log_files.extend(path.glob(pattern))

        # Other log files
        for f in path.glob("*.log"):
            if f not in log_files:
                log_files.append(f)

        # Sort by most recent first
        log_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

        return log_files
    
    def _read_log_lines(self, log_file: Path) -> Generator[str, None, None]:
        """Read log file lines (memory efficient)"""
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    yield line.strip()
        except Exception as e:
            self.logger.error(f"Error reading log file {log_file}: {e}")
    
    def _is_mcp_related(self, line: str) -> bool:
        """Check if log line is MCP-related"""
        line_lower = line.lower()
        return any(kw.lower() in line_lower for kw in self.mcp_keywords)
    
    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        """Extract timestamp from log line"""
        for pattern in self.timestamp_patterns:
            match = pattern.search(line)
            if match:
                ts = self._parse_timestamp(match.group(1))
                if ts:
                    return ts
        return None
    
    def _extract_log_level(self, line: str) -> EventSeverity:
        """Extract log level"""
        match = self.log_level_pattern.search(line)
        if match:
            level = match.group(1).lower()
            if level in ["error"]:
                return EventSeverity.ERROR
            elif level in ["warn", "warning"]:
                return EventSeverity.WARNING
        return EventSeverity.INFO
    
    def _extract_server_info(self, line: str) -> Optional[Dict[str, str]]:
        """Extract server info from log line"""
        # Pattern: [server-name] or mcpServer: name
        patterns = [
            re.compile(r'\[mcp-server-([^\]]+)\]'),
            re.compile(r'mcpServer["\s:]+(["\w\-_]+)'),
            re.compile(r'server["\s:]+(["\w\-_]+)')
        ]
        
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                name = match.group(1).strip('"')
                return {"name": name}
        
        return None
    
    def _extract_tool_info(self, line: str) -> Optional[Dict[str, Any]]:
        """Extract tool info from log line"""
        # tools/call pattern
        if "tools/call" in line.lower():
            # Extract tool name
            name_match = re.search(r'"name"\s*:\s*"([^"]+)"', line)
            if name_match:
                result = {"name": name_match.group(1)}

                # Try to extract server name
                server_match = re.search(r'\[([^\]]+)\]', line)
                if server_match:
                    result["server"] = server_match.group(1)

                return result

        return None
    
    def _parse_log_line(self, line: str, source_file: str) -> Optional[MCPEvent]:
        """Parse log line to create event"""
        timestamp = self._extract_timestamp(line)
        if not timestamp:
            timestamp = datetime.now()  # Use current time if no timestamp
        
        severity = self._extract_log_level(line)
        server_info = self._extract_server_info(line)
        tool_info = self._extract_tool_info(line)
        
        # Determine event type
        event_type = EventType.UNKNOWN
        tool_name = None
        server_name = server_info.get("name") if server_info else None
        
        if tool_info:
            tool_name = tool_info.get("name")
            server_name = tool_info.get("server", server_name)
        
        line_lower = line.lower()
        
        if "tools/call" in line_lower:
            event_type = EventType.TOOL_CALL
        elif "tools/list" in line_lower:
            event_type = EventType.TOOL_LIST
        elif "resources/read" in line_lower:
            event_type = EventType.RESOURCE_READ
        elif "resources/list" in line_lower:
            event_type = EventType.RESOURCE_LIST
        elif "initialize" in line_lower and "initialized" not in line_lower:
            event_type = EventType.CONNECTION_INIT
        elif "initialized" in line_lower:
            event_type = EventType.CONNECTION_READY
        elif "error" in line_lower:
            event_type = EventType.TOOL_ERROR
            severity = EventSeverity.ERROR
        
        # Extract JSON-RPC ID
        request_id = None
        id_match = re.search(r'"id"\s*:\s*(\d+|"[^"]+")', line)
        if id_match:
            request_id = id_match.group(1).strip('"')
        
        event = MCPEvent(
            timestamp=timestamp,
            event_type=event_type,
            source=ArtifactSource.CURSOR_LOG,
            server_name=server_name,
            tool_name=tool_name,
            severity=severity,
            request_id=request_id,
            raw_data=line[:500],  # Maximum 500 characters
            details={
                "source_file": source_file
            }
        )
        
        return event
    
    def get_default_log_path(self) -> Optional[Path]:
        """Return default log directory path by OS"""
        import platform
        import os
        
        system = platform.system()
        
        if system == "Windows":
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                return Path(appdata) / "Cursor" / "logs"
        
        elif system == "Darwin":  # macOS
            home = Path.home()
            return home / "Library" / "Logs" / "Cursor"
        
        else:  # Linux
            home = Path.home()
            return home / ".config" / "Cursor" / "logs"
        
        return None
    
    def search_logs(self, log_path: Union[str, Path],
                    keywords: List[str] = None,
                    start_time: datetime = None,
                    end_time: datetime = None) -> List[Dict[str, Any]]:
        """Search logs"""
        path = Path(log_path)
        keywords = keywords or self.mcp_keywords
        results = []

        log_files = self._get_log_files(path)

        for log_file in log_files:
            for line in self._read_log_lines(log_file):
                # Keyword matching
                if not any(kw.lower() in line.lower() for kw in keywords):
                    continue

                # Time filter
                timestamp = self._extract_timestamp(line)
                if timestamp:
                    if start_time and timestamp < start_time:
                        continue
                    if end_time and timestamp > end_time:
                        continue

                results.append({
                    "file": log_file.name,
                    "timestamp": timestamp.isoformat() if timestamp else None,
                    "level": self._extract_log_level(line).value,
                    "line": line[:500]
                })

        return results