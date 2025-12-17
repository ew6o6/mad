"""
MCP Forensics - Entity Models
Entity definitions for MCP servers, clients, tools, etc.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class ServerType(Enum):
    """MCP server type"""
    LOCAL = "local"                    # STDIO-based local server
    CUSTOM_REMOTE = "custom_remote"    # Custom HTTP server
    OFFICIAL_REMOTE = "official_remote"  # Official Remote server (e.g., Notion, GitHub)


class TransportType(Enum):
    """MCP Transport type"""
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamableHttp"
    SSE = "sse"  # Server-Sent Events (legacy)


class ArtifactSource(Enum):
    """Artifact source"""
    CURSOR_LOG = "cursor_log"
    SERVER_LOG = "server_log"
    NETWORK_CAPTURE = "network_capture"
    CONFIG_FILE = "config_file"
    PROXY_LOG = "proxy_log"
    CURSOR_STATE_DB = "cursor_state_db"  # state.vscdb


@dataclass
class MCPTool:
    """MCP tool definition"""
    name: str
    description: Optional[str] = None
    input_schema: Optional[Dict[str, Any]] = None
    server_name: Optional[str] = None  # Parent server

    # Metadata
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    call_count: int = 0
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "server_name": self.server_name,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "call_count": self.call_count
        }


@dataclass
class MCPResource:
    """MCP resource definition"""
    name: str
    uri: str
    mime_type: Optional[str] = None
    description: Optional[str] = None
    server_name: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "uri": self.uri,
            "mime_type": self.mime_type,
            "description": self.description,
            "server_name": self.server_name
        }


@dataclass
class MCPServer:
    """MCP server entity"""
    name: str
    server_type: ServerType
    transport: TransportType

    # Connection information
    url: Optional[str] = None  # For Remote servers
    command: Optional[str] = None  # For Local servers
    args: Optional[List[str]] = None

    # Capabilities
    tools: List[MCPTool] = field(default_factory=list)
    resources: List[MCPResource] = field(default_factory=list)

    # Session information
    session_id: Optional[str] = None
    client_info: Optional[Dict[str, str]] = None  # name, version
    server_info: Optional[Dict[str, Any]] = None  # name, version, websiteUrl, icons

    # Remote MCP additional information
    display_name: Optional[str] = None  # Server-reported name (e.g., "Notion MCP")
    version: Optional[str] = None  # Server version
    protocol_version: Optional[str] = None  # MCP protocol version
    capabilities: Optional[Dict[str, Any]] = None  # Server capabilities

    # Forensic metadata (user/account info extracted from Remote MCP)
    forensic_metadata: Optional[Dict[str, Any]] = None

    # Timestamps
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    # Statistics
    total_requests: int = 0
    total_tool_calls: int = 0
    total_errors: int = 0
    tool_count: int = 0  # Tool count extracted from logs (when tool list unavailable)

    # Sources
    sources: List[ArtifactSource] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "server_type": self.server_type.value,
            "transport": self.transport.value,
            "url": self.url,
            "command": self.command,
            "args": self.args,
            "tools": [t.to_dict() for t in self.tools],
            "resources": [r.to_dict() for r in self.resources],
            "session_id": self.session_id,
            "client_info": self.client_info,
            "server_info": self.server_info,
            "version": self.version,
            "protocol_version": self.protocol_version,
            "capabilities": self.capabilities,
            "forensic_metadata": self.forensic_metadata,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "total_requests": self.total_requests,
            "total_tool_calls": self.total_tool_calls,
            "total_errors": self.total_errors,
            "tool_count": self.tool_count or len(self.tools),
            "sources": [s.value for s in self.sources]
        }


@dataclass
class MCPClient:
    """MCP client entity (Cursor IDE)"""
    name: str = "cursor"
    version: Optional[str] = None

    # Connected servers
    connected_servers: List[str] = field(default_factory=list)

    # Metadata
    config_path: Optional[str] = None
    log_path: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version,
            "connected_servers": self.connected_servers,
            "config_path": self.config_path,
            "log_path": self.log_path
        }


@dataclass
class OrphanedTool:
    """Tool not linked to any server (found only in logs)"""
    name: str
    source: ArtifactSource
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    call_count: int = 0

    # Estimated information
    probable_server: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "source": self.source.value,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "call_count": self.call_count,
            "probable_server": self.probable_server
        }


@dataclass
class MCPEntities:
    """Complete MCP entity container"""
    servers: List[MCPServer] = field(default_factory=list)
    client: Optional[MCPClient] = None
    orphaned_tools: List[OrphanedTool] = field(default_factory=list)

    # Analysis metadata
    analysis_timestamp: Optional[datetime] = None
    artifact_sources: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "servers": [s.to_dict() for s in self.servers],
            "client": self.client.to_dict() if self.client else None,
            "orphaned_tools": [t.to_dict() for t in self.orphaned_tools],
            "analysis_timestamp": self.analysis_timestamp.isoformat() if self.analysis_timestamp else None,
            "artifact_sources": self.artifact_sources
        }
    
    def get_server_by_name(self, name: str) -> Optional[MCPServer]:
        """Find server by name"""
        for server in self.servers:
            if server.name == name:
                return server
        return None

    def get_all_tools(self) -> List[MCPTool]:
        """Get all tools from all servers"""
        tools = []
        for server in self.servers:
            tools.extend(server.tools)
        return tools

    def summary(self) -> Dict:
        """Summary statistics"""
        return {
            "total_servers": len(self.servers),
            "servers_by_type": {
                "local": len([s for s in self.servers if s.server_type == ServerType.LOCAL]),
                "custom_remote": len([s for s in self.servers if s.server_type == ServerType.CUSTOM_REMOTE]),
                "official_remote": len([s for s in self.servers if s.server_type == ServerType.OFFICIAL_REMOTE])
            },
            "total_tools": sum(len(s.tools) for s in self.servers),
            "total_resources": sum(len(s.resources) for s in self.servers),
            "orphaned_tools": len(self.orphaned_tools),
            "total_tool_calls": sum(s.total_tool_calls for s in self.servers)
        }