"""
MCP Forensics - Agent Transcript Transformer
Extract MCP tool call information from Cursor agent-transcripts JSON files

agent-transcripts structure:
[
  {"role": "user", "text": "..."},
  {"role": "assistant", "toolCalls": [{"toolName": "CallMcpTool", "args": {"server": "...", "toolName": "..."}}]},
  {"role": "tool", "toolResult": {"toolName": "CallMcpTool"}},
  {"role": "assistant", "text": "...", "thinking": "..."}
]

Server inference feature:
- When explicit CallMcpTool is not present, analyze MCP server mention patterns in user queries
- Detect patterns like "user-filesystem MCP", "filesystem server", "github mcp", etc.
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from .base import BaseTransformer
from .server_inference import infer_server_from_text, format_estimated_server
from ..models import (
    MCPEntities,
    MCPServer,
    MCPTool,
    Timeline,
    MCPEvent,
    ToolCallEvent,
    EventType,
    EventSeverity,
    ArtifactSource,
    ServerType,
    TransportType
)

logger = logging.getLogger("transformer.agent_transcript")


class AgentTranscriptTransformer(BaseTransformer):
    """
    Cursor agent-transcripts JSON Transformer

    Extracts MCP tool calls by server to provide accurate server-tool mapping.
    When server info is not available, infers MCP server from user queries.

    Supported formats:
    1. CallMcpTool format: {"toolName": "CallMcpTool", "args": {"server": "...", "toolName": "..."}}
    2. mcp_ prefix format: {"toolName": "mcp_Notion_notion-get-self", "args": {...}}
    """

    name = "agent_transcript"
    source = ArtifactSource.CURSOR_STATE_DB  # Similar source type

    # Pattern to parse mcp_{Server}_{tool} format
    MCP_TOOL_PATTERN = re.compile(r'^mcp_([^_]+)_(.+)$')

    def can_process(self, artifact_path: str) -> bool:
        """Check if agent-transcripts JSON file can be processed"""
        path = Path(artifact_path)

        # Check if it's in agent-transcripts folder
        if "agent-transcripts" in str(path):
            return path.suffix == ".json"

        # Check file content for agent transcript structure
        if path.suffix == ".json" and path.exists():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read(1000)  # Read first 1000 chars
                    # Check for typical agent transcript markers
                    if '"role"' in content and ('"toolCalls"' in content or '"toolName"' in content):
                        return True
            except:
                pass

        return False

    def _parse_mcp_tool_name(self, tool_name: str) -> Optional[Tuple[str, str]]:
        """
        Parse MCP tool name to extract server and tool

        Formats supported:
        - mcp_Notion_notion-get-self -> (Notion, notion-get-self)
        - mcp_github_search_code -> (github, search_code)
        - CallMcpTool -> None (handled separately)
        """
        if not tool_name:
            return None

        match = self.MCP_TOOL_PATTERN.match(tool_name)
        if match:
            server_name = match.group(1)
            actual_tool = match.group(2)
            return (server_name, actual_tool)

        return None

    def extract_entities(self, artifact_path: Path) -> MCPEntities:
        """Extract MCP server and tool entities"""
        entities = MCPEntities()
        entities.artifact_sources.append(self.source)

        try:
            transcript = self._load_transcript(artifact_path)
            if not transcript:
                return entities

            # Track servers and their tools
            servers_map: Dict[str, MCPServer] = {}

            for entry in transcript:
                if entry.get("role") == "assistant" and entry.get("toolCalls"):
                    for tool_call in entry["toolCalls"]:
                        raw_tool_name = tool_call.get("toolName", "")
                        args = tool_call.get("args", {})

                        server_name = None
                        tool_name = None

                        # Format 1: CallMcpTool with server/toolName in args
                        if raw_tool_name == "CallMcpTool":
                            server_name = args.get("server")
                            tool_name = args.get("toolName")

                        # Format 2: mcp_{Server}_{tool} pattern
                        else:
                            parsed = self._parse_mcp_tool_name(raw_tool_name)
                            if parsed:
                                server_name, tool_name = parsed

                        if server_name and tool_name:
                            # Get or create server
                            if server_name not in servers_map:
                                servers_map[server_name] = MCPServer(
                                    name=server_name,
                                    server_type=ServerType.LOCAL,
                                    transport=TransportType.STDIO,
                                    sources=[self.source]
                                )

                            server = servers_map[server_name]

                            # Add tool if not exists
                            existing_tools = {t.name for t in server.tools}
                            if tool_name not in existing_tools:
                                server.tools.append(MCPTool(
                                    name=tool_name,
                                    server_name=server_name,
                                    call_count=1
                                ))
                            else:
                                # Increment call count
                                for t in server.tools:
                                    if t.name == tool_name:
                                        t.call_count += 1
                                        break

                            server.total_tool_calls += 1

            entities.servers = list(servers_map.values())
            logger.info(f"Extracted {len(entities.servers)} servers from agent transcript")

        except Exception as e:
            logger.error(f"Error extracting entities: {e}")

        return entities

    def extract_events(self, artifact_path: Path) -> Timeline:
        """Extract timeline events"""
        timeline = Timeline()
        timeline.sources.append(self.source)

        try:
            transcript = self._load_transcript(artifact_path)
            if not transcript:
                return timeline

            # Get file modification time as base timestamp
            file_mtime = datetime.fromtimestamp(artifact_path.stat().st_mtime)

            # Track inferred server from conversation context
            current_inferred_server = None
            current_inference_source = None

            for idx, entry in enumerate(transcript):
                role = entry.get("role")

                if role == "user":
                    # User query event
                    text = entry.get("text", "")
                    # Extract actual query from <user_query> tags if present
                    if "<user_query>" in text:
                        match = re.search(r'<user_query>\s*(.*?)\s*</user_query>', text, re.DOTALL)
                        if match:
                            text = match.group(1).strip()

                    # Try to infer MCP server from user query
                    server_inference = infer_server_from_text(text)
                    if server_inference:
                        current_inferred_server, current_inference_source = server_inference

                    details = {
                        "text": text,
                        "entry_index": idx
                    }

                    # Add server inference info if available
                    if current_inferred_server:
                        details["server_estimated"] = current_inferred_server
                        details["estimation_source"] = f"user_query: \"{current_inference_source}\""

                    event = MCPEvent(
                        timestamp=file_mtime,
                        event_type=EventType.USER_QUERY,
                        source=self.source,
                        server_name=format_estimated_server(current_inferred_server) if current_inferred_server else None,
                        details=details
                    )
                    timeline.add_event(event)

                elif role == "assistant":
                    # Check for tool calls
                    tool_calls = entry.get("toolCalls", [])
                    mcp_calls = []
                    confirmed_servers = set()

                    for tc in tool_calls:
                        raw_tool_name = tc.get("toolName", "")
                        args = tc.get("args", {})

                        server_name = None
                        tool_name = None
                        tool_args = args

                        # Format 1: CallMcpTool with server/toolName in args
                        if raw_tool_name == "CallMcpTool":
                            server_name = args.get("server")
                            tool_name = args.get("toolName")
                            tool_args = {k: v for k, v in args.items()
                                        if k not in ["server", "toolName"]}

                        # Format 2: mcp_{Server}_{tool} pattern
                        else:
                            parsed = self._parse_mcp_tool_name(raw_tool_name)
                            if parsed:
                                server_name, tool_name = parsed
                                tool_args = args  # All args are tool arguments

                        if server_name and tool_name:
                            confirmed_servers.add(server_name)
                            mcp_calls.append({
                                "server": server_name,
                                "tool": tool_name,
                                "server_confirmed": True,
                                "args": tool_args
                            })

                            # Create tool call event (confirmed server)
                            event = ToolCallEvent(
                                timestamp=file_mtime,
                                event_type=EventType.TOOL_CALL,
                                source=self.source,
                                server_name=server_name,
                                tool_name=tool_name,
                                arguments=tool_args,
                                details={
                                    "entry_index": idx,
                                    "from_agent_transcript": True,
                                    "server_confirmed": True
                                }
                            )
                            timeline.add_event(event)

                    # Determine server info for AI response
                    servers_used = list(confirmed_servers)
                    server_status = "confirmed" if confirmed_servers else None

                    # If no confirmed server but we have inference, use it
                    if not servers_used and current_inferred_server:
                        servers_used = [format_estimated_server(current_inferred_server)]
                        server_status = "estimated"

                    # Assistant response with text
                    if entry.get("text"):
                        details = {
                            "text": entry["text"],
                            "thinking": entry.get("thinking"),
                            "mcp_tool_calls": mcp_calls,
                            "mcp_servers_used": servers_used,
                            "entry_index": idx
                        }

                        if server_status == "estimated":
                            details["server_estimated"] = current_inferred_server
                            details["estimation_source"] = f"user_query: \"{current_inference_source}\""
                        elif server_status == "confirmed":
                            details["server_confirmed"] = True

                        event = MCPEvent(
                            timestamp=file_mtime,
                            event_type=EventType.AI_RESPONSE,
                            source=self.source,
                            server_name=servers_used[0] if len(servers_used) == 1 else None,
                            details=details
                        )
                        timeline.add_event(event)

            logger.info(f"Extracted {len(timeline.events)} events from agent transcript")

        except Exception as e:
            logger.error(f"Error extracting events: {e}")

        return timeline

    def _load_transcript(self, path: Path) -> Optional[List[Dict]]:
        """Load and parse agent transcript JSON"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error in {path}: {e}")
        except Exception as e:
            logger.error(f"Error loading transcript {path}: {e}")
        return None

    def get_mcp_tool_calls(self, artifact_path: Path) -> List[Dict]:
        """Extract MCP tool calls only (grouped by server)"""
        result = []

        transcript = self._load_transcript(Path(artifact_path))
        if not transcript:
            return result

        for entry in transcript:
            if entry.get("role") == "assistant" and entry.get("toolCalls"):
                for tc in entry["toolCalls"]:
                    raw_tool_name = tc.get("toolName", "")
                    args = tc.get("args", {})

                    server_name = None
                    tool_name = None
                    tool_args = args

                    # Format 1: CallMcpTool with server/toolName in args
                    if raw_tool_name == "CallMcpTool":
                        server_name = args.get("server")
                        tool_name = args.get("toolName")
                        tool_args = {k: v for k, v in args.items()
                                    if k not in ["server", "toolName"]}

                    # Format 2: mcp_{Server}_{tool} pattern
                    else:
                        parsed = self._parse_mcp_tool_name(raw_tool_name)
                        if parsed:
                            server_name, tool_name = parsed

                    if server_name and tool_name:
                        result.append({
                            "server": server_name,
                            "tool": tool_name,
                            "arguments": tool_args
                        })

        return result
