"""
VSCDB Transformer - Cursor IDE State Database Parser
Parses state.vscdb SQLite database for MCP and conversation artifacts
"""

import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from dataclasses import dataclass, field
import logging

from .server_inference import infer_server_from_text, format_estimated_server

from ..models import (
    MCPEntities,
    MCPServer,
    ServerType,
    TransportType,
    ArtifactSource,
    Timeline,
    MCPEvent,
    EventType,
    EventSeverity
)


@dataclass
class MCPToolCall:
    """MCP tool call extracted from conversation"""
    server_name: str
    tool_name: str
    status: Optional[str] = None
    tool_call_id: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "server_name": self.server_name,
            "tool_name": self.tool_name,
            "status": self.status,
            "tool_call_id": self.tool_call_id
        }


@dataclass
class ConversationMessage:
    """Single message in a conversation"""
    bubble_id: str
    conversation_id: str
    message_type: str  # 'user' or 'assistant'
    text: str
    thinking: Optional[str] = None
    timestamp: Optional[datetime] = None
    model_name: Optional[str] = None
    tool_results: List[Dict] = field(default_factory=list)
    is_agentic: bool = False
    request_id: Optional[str] = None
    mcp_tool_calls: List[MCPToolCall] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "bubble_id": self.bubble_id,
            "conversation_id": self.conversation_id,
            "message_type": self.message_type,
            "text": self.text[:500] + "..." if len(self.text) > 500 else self.text,
            "full_text_length": len(self.text),
            "thinking": self.thinking[:300] + "..." if self.thinking and len(self.thinking) > 300 else self.thinking,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "model_name": self.model_name,
            "tool_results_count": len(self.tool_results),
            "is_agentic": self.is_agentic,
            "request_id": self.request_id,
            "mcp_tool_calls": [tc.to_dict() for tc in self.mcp_tool_calls],
            "mcp_servers_used": list(set(tc.server_name for tc in self.mcp_tool_calls))
        }


@dataclass
class MCPServerConfig:
    """MCP Server configuration from vscdb"""
    server_id: str
    server_url: Optional[str] = None
    code_verifier: Optional[str] = None
    has_tokens: bool = False
    has_client_info: bool = False

    def to_dict(self) -> Dict:
        return {
            "server_id": self.server_id,
            "server_url": self.server_url,
            "code_verifier_present": bool(self.code_verifier),
            "has_tokens": self.has_tokens,
            "has_client_info": self.has_client_info
        }


@dataclass
class VSCDBAnalysis:
    """Complete analysis result from vscdb"""
    mcp_servers: List[MCPServerConfig] = field(default_factory=list)
    conversations: Dict[str, List[ConversationMessage]] = field(default_factory=dict)
    known_server_ids: List[str] = field(default_factory=list)
    total_messages: int = 0
    total_user_queries: int = 0
    total_ai_responses: int = 0
    ai_code_tracking: Dict[str, Any] = field(default_factory=dict)
    mcp_server_usage: Dict[str, int] = field(default_factory=dict)  # server_name -> call_count

    def to_dict(self) -> Dict:
        # Calculate MCP server usage from conversations
        server_usage = {}
        for conv_id, messages in self.conversations.items():
            for msg in messages:
                for tc in msg.mcp_tool_calls:
                    server_usage[tc.server_name] = server_usage.get(tc.server_name, 0) + 1

        return {
            "mcp_servers": [s.to_dict() for s in self.mcp_servers],
            "known_server_ids": self.known_server_ids,
            "conversation_count": len(self.conversations),
            "total_messages": self.total_messages,
            "total_user_queries": self.total_user_queries,
            "total_ai_responses": self.total_ai_responses,
            "ai_code_tracking": self.ai_code_tracking,
            "mcp_server_usage": server_usage,
            "conversations": {
                conv_id: [m.to_dict() for m in messages[:10]]
                for conv_id, messages in list(self.conversations.items())[:20]
            }
        }


class VSCDBTransformer:
    """
    Transformer for Cursor IDE state.vscdb SQLite database

    Extracts:
    - MCP server configurations from ItemTable
    - Conversation history from cursorDiskKV (bubbleId entries)
    - AI code tracking statistics
    """

    def __init__(self):
        self.name = "vscdb_transformer"
        self.source = ArtifactSource.CURSOR_STATE_DB
        self.logger = logging.getLogger(f"transformer.{self.name}")
        self.supported_extensions = [".vscdb", ".db", ".sqlite"]
        self.analysis = VSCDBAnalysis()
        self.stats = {
            "files_processed": 0,
            "entities_extracted": 0,
            "events_extracted": 0,
            "errors": 0
        }

    def can_process(self, artifact_path: Union[str, Path]) -> bool:
        """Check if this transformer can handle the artifact"""
        path = Path(artifact_path)
        if path.suffix.lower() in self.supported_extensions:
            # Additional check: try to open as SQLite
            try:
                conn = sqlite3.connect(str(path))
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                conn.close()
                # Must have cursorDiskKV or ItemTable
                return "cursorDiskKV" in tables or "ItemTable" in tables
            except:
                return False
        if "state.vscdb" in path.name.lower():
            return True
        return False

    def process(self, artifact_path: Union[str, Path]) -> Dict[str, Any]:
        """Process the vscdb file"""
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
            # Parse database
            self._parse_database(path)

            # Extract entities
            entities = self.extract_entities(path)
            self.stats["entities_extracted"] = len(entities.servers)

            # Extract events
            timeline = self.extract_events(path)
            self.stats["events_extracted"] = len(timeline.events)

            self.stats["files_processed"] += 1

            return {
                "success": True,
                "entities": entities.to_dict(),
                "timeline": timeline.to_dict(),
                "stats": self.stats,
                "vscdb_analysis": self.analysis.to_dict()
            }

        except Exception as e:
            self.logger.exception(f"Error processing vscdb: {path}")
            self.stats["errors"] += 1
            return {
                "success": False,
                "error": str(e),
                "entities": MCPEntities().to_dict(),
                "timeline": Timeline().to_dict(),
                "stats": self.stats
            }

    def extract_entities(self, artifact_path: Union[str, Path]) -> MCPEntities:
        """Extract MCP entities from vscdb"""
        if not self.analysis.mcp_servers:
            self._parse_database(Path(artifact_path))

        entities = MCPEntities()
        entities.artifact_sources.append(str(artifact_path))

        # Convert MCP server configs to MCPServer entities
        for mcp_config in self.analysis.mcp_servers:
            # Determine server type based on URL presence
            if mcp_config.server_url:
                # Check if it's an official remote server by URL pattern
                url_lower = mcp_config.server_url.lower()
                if any(domain in url_lower for domain in ['mcp.notion.com', 'mcp.github.com', 'anthropic.com']):
                    server_type = ServerType.OFFICIAL_REMOTE
                else:
                    server_type = ServerType.CUSTOM_REMOTE
            else:
                server_type = ServerType.LOCAL

            transport = TransportType.STREAMABLE_HTTP if mcp_config.server_url else TransportType.STDIO

            server = MCPServer(
                name=mcp_config.server_id,
                server_type=server_type,
                transport=transport,
                command=None,
                args=[],
                url=mcp_config.server_url,
                sources=[ArtifactSource.CURSOR_STATE_DB]
            )
            entities.servers.append(server)

        return entities

    def extract_events(self, artifact_path: Union[str, Path]) -> Timeline:
        """Extract timeline events from vscdb conversations"""
        if not self.analysis.conversations:
            self._parse_database(Path(artifact_path))

        timeline = Timeline()

        for conv_id, messages in self.analysis.conversations.items():
            # Track inferred server within conversation context
            current_inferred_server = None
            current_inference_source = None

            for msg in messages:
                event_type = EventType.USER_QUERY if msg.message_type == "user" else EventType.AI_RESPONSE

                # Get MCP servers used from tool calls (confirmed)
                mcp_servers_used = list(set(tc.server_name for tc in msg.mcp_tool_calls))
                server_confirmed = len(mcp_servers_used) > 0

                # For user messages, try to infer server from text
                if msg.message_type == "user" and msg.text:
                    inference = infer_server_from_text(msg.text)
                    if inference:
                        current_inferred_server, current_inference_source = inference

                # Build details
                details = {
                    "bubble_id": msg.bubble_id,
                    "conversation_id": conv_id,
                    "text": msg.text if msg.text else "",  # Full text for expand
                    "is_agentic": msg.is_agentic,
                    "model_name": msg.model_name,
                    "has_thinking": bool(msg.thinking),
                    "thinking_text": msg.thinking[:500] if msg.thinking else None,
                    "tool_results_count": len(msg.tool_results),
                    "mcp_tool_calls": [tc.to_dict() for tc in msg.mcp_tool_calls]
                }

                # Determine server info
                server_name = None
                if server_confirmed:
                    details["mcp_servers_used"] = mcp_servers_used
                    details["server_confirmed"] = True
                    server_name = mcp_servers_used[0] if len(mcp_servers_used) == 1 else None
                elif current_inferred_server:
                    # Use inferred server with (estimated) marker
                    estimated_name = format_estimated_server(current_inferred_server)
                    details["mcp_servers_used"] = [estimated_name]
                    details["server_estimated"] = current_inferred_server
                    details["estimation_source"] = f"user_query: \"{current_inference_source}\""
                    server_name = estimated_name
                else:
                    details["mcp_servers_used"] = []

                event = MCPEvent(
                    timestamp=msg.timestamp or datetime.now(),
                    event_type=event_type,
                    source=ArtifactSource.CURSOR_STATE_DB,
                    server_name=server_name,
                    details=details,
                    severity=EventSeverity.INFO
                )
                timeline.add_event(event)

        return timeline

    def _parse_database(self, db_path: Path) -> VSCDBAnalysis:
        """Parse the vscdb SQLite database"""
        self.analysis = VSCDBAnalysis()

        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Parse ItemTable for MCP config
            self._parse_item_table(cursor)

            # Parse cursorDiskKV for conversations
            self._parse_cursor_disk_kv(cursor)

            conn.close()

        except Exception as e:
            self.logger.error(f"Error parsing vscdb: {e}")

        return self.analysis

    def _parse_item_table(self, cursor: sqlite3.Cursor):
        """Parse ItemTable for MCP and other settings"""
        try:
            # Get known server IDs
            cursor.execute("SELECT value FROM ItemTable WHERE key = 'mcpService.knownServerIds'")
            row = cursor.fetchone()
            if row and row[0]:
                try:
                    value = row[0] if isinstance(row[0], str) else row[0].decode('utf-8')
                    self.analysis.known_server_ids = json.loads(value)
                except:
                    pass

            # Get MCP server configs
            cursor.execute("SELECT value FROM ItemTable WHERE key = 'anysphere.cursor-mcp'")
            row = cursor.fetchone()
            mcp_data = {}
            if row and row[0]:
                try:
                    value = row[0] if isinstance(row[0], str) else row[0].decode('utf-8')
                    mcp_data = json.loads(value)
                except:
                    pass

            # Parse MCP config (also creates entries from known_server_ids)
            self._parse_mcp_config(mcp_data)

            # Check for secret keys (tokens, client info)
            cursor.execute("SELECT key FROM ItemTable WHERE key LIKE 'secret://%cursor-mcp%'")
            for row in cursor.fetchall():
                key = row[0]
                if "mcp_tokens" in key:
                    for server in self.analysis.mcp_servers:
                        if server.server_id in key:
                            server.has_tokens = True
                elif "mcp_client_information" in key:
                    for server in self.analysis.mcp_servers:
                        if server.server_id in key:
                            server.has_client_info = True

            # Get AI code tracking stats
            cursor.execute("SELECT key, value FROM ItemTable WHERE key LIKE 'aiCodeTracking%'")
            for row in cursor.fetchall():
                try:
                    key = row[0]
                    value = row[1] if isinstance(row[1], str) else row[1].decode('utf-8')
                    if value.startswith('{') or value.startswith('['):
                        self.analysis.ai_code_tracking[key] = json.loads(value)
                    else:
                        self.analysis.ai_code_tracking[key] = value
                except:
                    pass

        except Exception as e:
            self.logger.error(f"Error parsing ItemTable: {e}")

    def _parse_mcp_config(self, mcp_data: Dict):
        """Parse MCP configuration data"""
        servers_found = {}

        # First, create entries for all known servers
        for server_id in self.analysis.known_server_ids:
            servers_found[server_id] = MCPServerConfig(server_id=server_id)

        # Then, enrich with config data from anysphere.cursor-mcp
        for key, value in mcp_data.items():
            # Keys are like "[user-Github] mcp_server_url"
            if "] " in key:
                server_part = key.split("] ")[0].replace("[", "")
                field_name = key.split("] ")[1]

                if server_part not in servers_found:
                    servers_found[server_part] = MCPServerConfig(server_id=server_part)

                if field_name == "mcp_server_url":
                    servers_found[server_part].server_url = value
                elif field_name == "mcp_code_verifier":
                    servers_found[server_part].code_verifier = value

        self.analysis.mcp_servers = list(servers_found.values())

    def _parse_cursor_disk_kv(self, cursor: sqlite3.Cursor):
        """Parse cursorDiskKV for conversation bubbles"""
        try:
            cursor.execute("SELECT key, value FROM cursorDiskKV WHERE key LIKE 'bubbleId:%'")

            for row in cursor.fetchall():
                try:
                    key = row[0]
                    value = row[1]

                    # Decode value
                    if isinstance(value, bytes):
                        value = value.decode('utf-8')

                    bubble_data = json.loads(value)

                    # Extract conversation ID and bubble ID from key
                    # Format: bubbleId:conversation_id:bubble_id
                    parts = key.split(":")
                    if len(parts) >= 3:
                        conv_id = parts[1]
                        bubble_id = parts[2]
                    else:
                        continue

                    # Parse message
                    message = self._parse_bubble(bubble_data, conv_id, bubble_id)
                    if message:
                        if conv_id not in self.analysis.conversations:
                            self.analysis.conversations[conv_id] = []
                        self.analysis.conversations[conv_id].append(message)

                        self.analysis.total_messages += 1
                        if message.message_type == "user":
                            self.analysis.total_user_queries += 1
                        else:
                            self.analysis.total_ai_responses += 1

                except Exception as e:
                    continue

            # Sort messages within each conversation by timestamp
            for conv_id in self.analysis.conversations:
                self.analysis.conversations[conv_id].sort(
                    key=lambda m: m.timestamp or datetime.min
                )

        except Exception as e:
            self.logger.error(f"Error parsing cursorDiskKV: {e}")

    def _parse_bubble(self, data: Dict, conv_id: str, bubble_id: str) -> Optional[ConversationMessage]:
        """Parse a single bubble (message) from conversation data"""
        try:
            msg_type_num = data.get("type", 0)
            msg_type = "user" if msg_type_num == 1 else "assistant" if msg_type_num == 2 else "unknown"

            if msg_type == "unknown":
                return None

            # Get text content
            text = data.get("text", "")
            if not text and "richText" in data:
                try:
                    rich = json.loads(data["richText"]) if isinstance(data["richText"], str) else data["richText"]
                    text = self._extract_text_from_rich(rich)
                except:
                    pass

            # Get thinking/reasoning
            thinking = None
            if "thinking" in data and isinstance(data["thinking"], dict):
                thinking = data["thinking"].get("text", "")

            # Parse timestamp
            timestamp = None
            if "createdAt" in data:
                try:
                    ts_str = data["createdAt"]
                    if ts_str.endswith("Z"):
                        ts_str = ts_str[:-1] + "+00:00"
                    timestamp = datetime.fromisoformat(ts_str)
                except:
                    pass

            # Get model info
            model_name = None
            if "modelInfo" in data and isinstance(data["modelInfo"], dict):
                model_name = data["modelInfo"].get("modelName")

            # Get tool results
            tool_results = data.get("toolResults", [])

            # Extract MCP tool calls from toolFormerData
            mcp_tool_calls = []
            tool_former = data.get("toolFormerData")
            if tool_former and isinstance(tool_former, dict):
                tool_call = self._extract_mcp_tool_call(tool_former)
                if tool_call:
                    mcp_tool_calls.append(tool_call)

            return ConversationMessage(
                bubble_id=bubble_id,
                conversation_id=conv_id,
                message_type=msg_type,
                text=text,
                thinking=thinking,
                timestamp=timestamp,
                model_name=model_name,
                tool_results=tool_results,
                is_agentic=data.get("isAgentic", False),
                request_id=data.get("requestId"),
                mcp_tool_calls=mcp_tool_calls
            )

        except Exception as e:
            return None

    def _extract_text_from_rich(self, rich: Dict) -> str:
        """Extract plain text from richText JSON structure"""
        texts = []

        def extract_recursive(node):
            if isinstance(node, dict):
                if node.get("type") == "text" and "text" in node:
                    texts.append(node["text"])
                for key in ["children", "root"]:
                    if key in node:
                        extract_recursive(node[key])
            elif isinstance(node, list):
                for item in node:
                    extract_recursive(item)

        extract_recursive(rich)
        return " ".join(texts)

    def _extract_mcp_tool_call(self, tool_former: Dict) -> Optional[MCPToolCall]:
        """Extract MCP tool call info from toolFormerData"""
        try:
            name = tool_former.get("name", "")

            # Check if this is an MCP tool call (name starts with mcp_)
            if not name.startswith("mcp_"):
                return None

            # Parse server name and tool name from name field
            # Format: mcp_{serverName}_{toolName} (e.g., mcp_filesystem_list_directory)
            parts = name[4:].split("_", 1)  # Remove "mcp_" prefix and split
            if len(parts) < 2:
                return None

            server_name = parts[0]
            tool_name = parts[1]

            # Try to get more accurate server name from additionalData
            additional = tool_former.get("additionalData", {})
            if isinstance(additional, dict):
                review_data = additional.get("reviewData", {})
                if isinstance(review_data, dict):
                    server_id = review_data.get("serverId")
                    if server_id:
                        server_name = server_id
                    tool_name_from_review = review_data.get("toolName")
                    if tool_name_from_review:
                        tool_name = tool_name_from_review

            return MCPToolCall(
                server_name=server_name,
                tool_name=tool_name,
                status=tool_former.get("status"),
                tool_call_id=tool_former.get("toolCallId")
            )

        except Exception as e:
            self.logger.warning(f"Error extracting MCP tool call: {e}")
            return None

    def get_full_analysis(self, db_path: Path) -> VSCDBAnalysis:
        """Get complete analysis result"""
        if not self.analysis.conversations:
            self._parse_database(db_path)
        return self.analysis
