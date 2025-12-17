"""
MCP Forensics - Config Transformer
mcp.json configuration file parser

Parses Cursor IDE MCP configuration files to extract MCP server entities.

Config file locations:
- Windows: %APPDATA%/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/mcp.json
- macOS: ~/Library/Application Support/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/mcp.json
- Linux: ~/.config/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/mcp.json
"""

import json
from pathlib import Path
from typing import Union, Optional, Dict, Any, List
from datetime import datetime

from .base import BaseTransformer
from ..models import (
    MCPEntities,
    MCPServer,
    MCPClient,
    MCPTool,
    Timeline,
    MCPEvent,
    EventType,
    ServerType,
    TransportType,
    ArtifactSource
)


class ConfigTransformer(BaseTransformer):
    """
    mcp.json configuration file Transformer

    Parses Cursor IDE MCP configuration files to:
    1. Extract configured MCP server list
    2. Determine server types (Local/Remote)
    3. Identify transport methods
    """
    
    def __init__(self):
        super().__init__(name="config")
        self.source = ArtifactSource.CONFIG_FILE
        
        # Known Official Remote server domains
        self.official_remote_domains = [
            "notion.so",
            "mcp.notion.so",
            "github.com",
            "api.github.com",
            "linear.app",
            "sentry.io",
            "slack.com"
        ]
        
        # Known Official server packages
        self.official_packages = [
            "@modelcontextprotocol/server-filesystem",
            "@modelcontextprotocol/server-git",
            "@modelcontextprotocol/server-github",
            "@modelcontextprotocol/server-sqlite",
            "@modelcontextprotocol/server-postgres",
            "@modelcontextprotocol/server-brave-search",
            "@modelcontextprotocol/server-puppeteer",
            "@notionhq/notion-mcp-server"
        ]
    
    def can_process(self, artifact_path: Union[str, Path]) -> bool:
        """Check if this is an mcp.json file"""
        path = Path(artifact_path)

        # Check file existence
        if not path.exists():
            return False

        # Check filename
        if path.name == "mcp.json":
            return True

        # Check if JSON file contains mcpServers key
        if path.suffix == ".json":
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return "mcpServers" in data
            except:
                return False
        
        return False
    
    def extract_entities(self, artifact_path: Union[str, Path]) -> MCPEntities:
        """Extract MCP entities from mcp.json"""
        path = Path(artifact_path)
        entities = MCPEntities()
        entities.analysis_timestamp = datetime.now()
        entities.artifact_sources = [str(path)]

        # Client information
        entities.client = MCPClient(
            name="cursor",
            config_path=str(path)
        )
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to parse config file: {e}")
            return entities
        
        # Parse mcpServers
        mcp_servers = config.get("mcpServers", {})
        
        for server_name, server_config in mcp_servers.items():
            server = self._parse_server_config(server_name, server_config)
            if server:
                entities.servers.append(server)
                entities.client.connected_servers.append(server_name)
        
        self.logger.info(f"Extracted {len(entities.servers)} servers from config")
        return entities
    
    def _parse_server_config(self, name: str, config: Dict[str, Any]) -> Optional[MCPServer]:
        """Parse individual server configuration"""

        # Determine transport and server type
        transport_str = config.get("transport", "")
        url = config.get("url", "")
        command = config.get("command", "")
        args = config.get("args", [])
        
        # Determine transport
        if transport_str == "streamableHttp" or url:
            transport = TransportType.STREAMABLE_HTTP
        elif transport_str == "sse":
            transport = TransportType.SSE
        else:
            transport = TransportType.STDIO
        
        # Determine server type
        server_type = self._determine_server_type(config, url, command, args)
        
        server = MCPServer(
            name=name,
            server_type=server_type,
            transport=transport,
            url=url if url else None,
            command=command if command else None,
            args=args if args else None,
            sources=[ArtifactSource.CONFIG_FILE]
        )
        
        # Additional metadata
        if "headers" in config:
            server.client_info = {"headers": config["headers"]}

        if "env" in config:
            # Environment variables (mask API keys, etc.)
            env_info = {}
            for key, value in config.get("env", {}).items():
                if "key" in key.lower() or "token" in key.lower() or "secret" in key.lower():
                    env_info[key] = "***MASKED***"
                else:
                    env_info[key] = value
            server.server_info = {"env": env_info}

        # Extract description
        if "description" in config:
            server.server_info = server.server_info or {}
            server.server_info["description"] = config["description"]
        
        return server
    
    def _determine_server_type(self, config: Dict, url: str,
                               command: str, args: List[str]) -> ServerType:
        """Determine server type"""

        # If URL exists, it's Remote
        if url:
            # Check Official Remote domains
            for domain in self.official_remote_domains:
                if domain in url:
                    return ServerType.OFFICIAL_REMOTE

            # localhost or 127.0.0.1 is Custom Remote
            if "localhost" in url or "127.0.0.1" in url:
                return ServerType.CUSTOM_REMOTE

            # ngrok and other tunneling services are Custom Remote
            if "ngrok" in url or "tunnel" in url:
                return ServerType.CUSTOM_REMOTE

            # Other URLs are classified as Official Remote for now
            return ServerType.OFFICIAL_REMOTE

        # If command exists, it's Local
        if command:
            # Check for Official package usage
            args_str = " ".join(args) if args else ""
            for pkg in self.official_packages:
                if pkg in args_str or pkg in command:
                    return ServerType.LOCAL

            # Commands like npx, node are Local
            if command in ["npx", "node", "python", "python3", "uv"]:
                return ServerType.LOCAL

        # Default value
        return ServerType.LOCAL
    
    def extract_events(self, artifact_path: Union[str, Path]) -> Timeline:
        """
        Events are not directly extracted from config files.
        Returns an empty timeline.
        """
        timeline = Timeline()
        timeline.sources = [ArtifactSource.CONFIG_FILE]

        # Config file modification time can be added as an event
        path = Path(artifact_path)
        if path.exists():
            mtime = datetime.fromtimestamp(path.stat().st_mtime)
            event = MCPEvent(
                timestamp=mtime,
                event_type=EventType.UNKNOWN,
                source=ArtifactSource.CONFIG_FILE,
                details={"action": "config_file_modified", "path": str(path)}
            )
            timeline.add_event(event)
        
        return timeline
    
    def get_default_config_path(self) -> Optional[Path]:
        """Return default config file path by OS"""
        import platform
        import os
        
        system = platform.system()
        
        if system == "Windows":
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                return Path(appdata) / "Cursor" / "User" / "globalStorage" / \
                       "saoudrizwan.claude-dev" / "settings" / "mcp.json"
        
        elif system == "Darwin":  # macOS
            home = Path.home()
            return home / "Library" / "Application Support" / "Cursor" / "User" / \
                   "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "mcp.json"
        
        else:  # Linux
            home = Path.home()
            return home / ".config" / "Cursor" / "User" / "globalStorage" / \
                   "saoudrizwan.claude-dev" / "settings" / "mcp.json"
        
        return None
    
    def analyze_config_summary(self, config_path: Union[str, Path]) -> Dict[str, Any]:
        """Analyze and summarize configuration file"""
        entities = self.extract_entities(config_path)
        
        summary = {
            "config_path": str(config_path),
            "total_servers": len(entities.servers),
            "servers_by_type": {
                "local": 0,
                "custom_remote": 0,
                "official_remote": 0
            },
            "servers_by_transport": {
                "stdio": 0,
                "streamableHttp": 0,
                "sse": 0
            },
            "servers": []
        }
        
        for server in entities.servers:
            summary["servers_by_type"][server.server_type.value] += 1
            summary["servers_by_transport"][server.transport.value] += 1
            
            summary["servers"].append({
                "name": server.name,
                "type": server.server_type.value,
                "transport": server.transport.value,
                "url": server.url,
                "command": server.command
            })
        
        return summary