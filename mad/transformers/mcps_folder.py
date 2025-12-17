"""
MCPS Folder Transformer - Parse MCP Server Tool Definitions
Parses tool definition JSON files from Cursor's mcps folder structure

Folder structure:
- {project}/.cursor/projects/{project-path}/mcps/{server-name}/tools/*.json

Each tool JSON contains:
- name: Tool name
- description: Tool description
- arguments: JSON schema for tool arguments
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from dataclasses import dataclass, field
import logging

from .base import BaseTransformer
from ..models import (
    MCPEntities,
    MCPServer,
    MCPTool,
    ServerType,
    TransportType,
    ArtifactSource,
    Timeline
)


@dataclass
class ToolDefinition:
    """Tool definition from JSON file"""
    name: str
    description: Optional[str] = None
    arguments: Optional[Dict[str, Any]] = None
    server_name: Optional[str] = None
    file_path: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "arguments": self.arguments,
            "server_name": self.server_name,
            "file_path": self.file_path
        }


@dataclass
class MCPSFolderAnalysis:
    """Analysis result from mcps folder"""
    servers: Dict[str, List[ToolDefinition]] = field(default_factory=dict)
    total_tools: int = 0
    source_path: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "servers": {
                server_name: [t.to_dict() for t in tools]
                for server_name, tools in self.servers.items()
            },
            "total_tools": self.total_tools,
            "server_count": len(self.servers),
            "source_path": self.source_path
        }


class MCPSFolderTransformer(BaseTransformer):
    """
    Transformer for Cursor mcps folder

    Parses tool definitions from:
    - {project}/.cursor/projects/{project-path}/mcps/{server-name}/tools/*.json

    Extracts:
    - Server names from folder names
    - Tool definitions from JSON files
    - Input schemas for each tool
    """

    def __init__(self):
        super().__init__(name="mcps_folder_transformer")
        self.source = ArtifactSource.CONFIG_FILE
        self.analysis = MCPSFolderAnalysis()

    def can_process(self, artifact_path: Union[str, Path]) -> bool:
        """Check if this is an mcps folder or contains mcps structure"""
        path = Path(artifact_path)

        # Direct mcps folder
        if path.is_dir() and path.name == "mcps":
            return True

        # Check if it contains mcps subfolder
        if path.is_dir():
            mcps_path = path / "mcps"
            if mcps_path.exists():
                return True

            # Check for server folder structure (has tools/ subfolder)
            tools_path = path / "tools"
            if tools_path.exists() and any(tools_path.glob("*.json")):
                return True

        # Single JSON file in tools folder
        if path.is_file() and path.suffix == ".json":
            if path.parent.name == "tools":
                return True

        return False

    def find_mcps_folder(self, start_path: Union[str, Path]) -> Optional[Path]:
        """Find mcps folder from various starting points"""
        path = Path(start_path)

        # Direct mcps folder
        if path.name == "mcps" and path.is_dir():
            return path

        # Check for mcps subfolder
        mcps_path = path / "mcps"
        if mcps_path.exists():
            return mcps_path

        # Check parent directories
        for parent in path.parents:
            mcps_path = parent / "mcps"
            if mcps_path.exists():
                return mcps_path

            # Also check .cursor/projects path
            cursor_path = parent / ".cursor" / "projects"
            if cursor_path.exists():
                for project_dir in cursor_path.iterdir():
                    if project_dir.is_dir():
                        mcps_in_project = project_dir / "mcps"
                        if mcps_in_project.exists():
                            return mcps_in_project

        return None

    def process(self, artifact_path: Union[str, Path]) -> Dict[str, Any]:
        """Process the mcps folder or tool files"""
        path = Path(artifact_path)

        if not self.can_process(path):
            return {
                "success": False,
                "error": f"Cannot process {path}",
                "entities": MCPEntities().to_dict(),
                "timeline": Timeline().to_dict(),
                "stats": self.stats
            }

        try:
            # Parse folder structure
            self._parse_folder(path)

            # Extract entities
            entities = self.extract_entities(path)
            self.stats["entities_extracted"] = len(entities.servers)

            self.stats["servers_found"] = len(self.analysis.servers)
            self.stats["tools_extracted"] = self.analysis.total_tools

            return {
                "success": True,
                "entities": entities.to_dict(),
                "timeline": Timeline().to_dict(),  # No events from static files
                "stats": self.stats,
                "mcps_analysis": self.analysis.to_dict()
            }

        except Exception as e:
            self.logger.exception(f"Error processing mcps folder: {path}")
            self.stats["errors"] += 1
            return {
                "success": False,
                "error": str(e),
                "entities": MCPEntities().to_dict(),
                "timeline": Timeline().to_dict(),
                "stats": self.stats
            }

    def extract_entities(self, artifact_path: Union[str, Path]) -> MCPEntities:
        """Extract MCP entities from mcps folder"""
        if not self.analysis.servers:
            self._parse_folder(Path(artifact_path))

        entities = MCPEntities()
        entities.artifact_sources.append(str(artifact_path))

        for server_name, tools in self.analysis.servers.items():
            # Create MCPTool objects
            mcp_tools = []
            for tool_def in tools:
                mcp_tool = MCPTool(
                    name=tool_def.name,
                    description=tool_def.description,
                    input_schema=tool_def.arguments,
                    server_name=server_name
                )
                mcp_tools.append(mcp_tool)

            # Create server entity
            server = MCPServer(
                name=server_name,
                server_type=ServerType.LOCAL,  # mcps folder = local server
                transport=TransportType.STDIO,
                tools=mcp_tools,
                tool_count=len(mcp_tools),
                sources=[ArtifactSource.CONFIG_FILE]
            )
            entities.servers.append(server)

        return entities

    def extract_events(self, artifact_path: Union[str, Path]) -> Timeline:
        """Extract events from mcps folder - returns empty timeline as static files have no events"""
        return Timeline()

    def _parse_folder(self, path: Path):
        """Parse mcps folder structure"""
        self.analysis = MCPSFolderAnalysis()
        self.analysis.source_path = str(path)

        # Determine root folder
        if path.name == "mcps":
            mcps_root = path
        elif (path / "mcps").exists():
            mcps_root = path / "mcps"
        elif path.name == "tools" and any(path.glob("*.json")):
            # Single server's tools folder
            server_name = path.parent.name
            self._parse_server_tools(server_name, path)
            return
        else:
            # Try to find mcps folder
            mcps_root = self.find_mcps_folder(path)
            if not mcps_root:
                self.logger.warning(f"Could not find mcps folder from {path}")
                return

        # Parse each server folder
        for server_dir in mcps_root.iterdir():
            if not server_dir.is_dir():
                continue

            server_name = server_dir.name
            tools_dir = server_dir / "tools"

            if tools_dir.exists():
                self._parse_server_tools(server_name, tools_dir)

    def _parse_server_tools(self, server_name: str, tools_dir: Path):
        """Parse tool definitions from a server's tools folder"""
        tools = []

        for json_file in tools_dir.glob("*.json"):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                tool = ToolDefinition(
                    name=data.get("name", json_file.stem),
                    description=data.get("description"),
                    arguments=data.get("arguments"),
                    server_name=server_name,
                    file_path=str(json_file)
                )
                tools.append(tool)
                self.stats["files_processed"] += 1
                self.analysis.total_tools += 1

            except Exception as e:
                self.logger.error(f"Error parsing tool file {json_file}: {e}")
                self.stats["errors"] += 1

        if tools:
            self.analysis.servers[server_name] = tools
            self.logger.info(f"Found {len(tools)} tools for server: {server_name}")

    def get_tool_by_name(self, tool_name: str) -> Optional[ToolDefinition]:
        """Find a tool by name across all servers"""
        for server_name, tools in self.analysis.servers.items():
            for tool in tools:
                if tool.name == tool_name:
                    return tool
        return None

    def get_server_tools(self, server_name: str) -> List[ToolDefinition]:
        """Get all tools for a specific server"""
        return self.analysis.servers.get(server_name, [])
