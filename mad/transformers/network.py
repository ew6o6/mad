"""
MCP Forensics - Network Transformer
Network capture file (pcap, HAR) parser

Parses Wireshark pcap and HTTP Archive (HAR) files
to extract MCP HTTP communications.

Supported formats:
- pcap/pcapng (Wireshark) - requires pyshark
- HAR (HTTP Archive, mitmproxy, etc.)
"""

import json
import re
from pathlib import Path
from typing import Union, Optional, Dict, Any, List
from datetime import datetime
from urllib.parse import urlparse

from .base import BaseTransformer
from ..models import (
    MCPEntities,
    MCPServer,
    MCPTool,
    Timeline,
    MCPEvent,
    HTTPEvent,
    ToolCallEvent,
    ToolResultEvent,
    EventType,
    EventSeverity,
    ServerType,
    TransportType,
    ArtifactSource
)


class NetworkTransformer(BaseTransformer):
    """
    Network Capture Transformer
    """
    
    def __init__(self):
        super().__init__(name="network")
        self.source = ArtifactSource.NETWORK_CAPTURE

        # Official Remote MCP endpoints
        self.official_mcp_domains = [
            "mcp.notion.com",
            "mcp.notion.so",
            "mcp.github.com",
            "mcp.anthropic.com",
        ]

        self.mcp_url_patterns = [
            "/mcp", "/sse", "modelcontextprotocol",
            *self.official_mcp_domains
        ]

        # SSE response parsing pattern
        self.sse_data_pattern = re.compile(r'^data:\s*(.+)$', re.MULTILINE)
    
    def can_process(self, artifact_path: Union[str, Path]) -> bool:
        """Check if this is a network capture file"""
        path = Path(artifact_path)
        
        if path.is_file():
            suffix = path.suffix.lower()
            if suffix in [".pcap", ".pcapng", ".cap", ".har"]:
                return True
            if suffix == ".json":
                return self._is_har_file(path)
        
        if path.is_dir():
            for ext in ["*.pcap", "*.pcapng", "*.har"]:
                if list(path.glob(ext)):
                    return True
        
        return False
    
    def _is_har_file(self, path: Path) -> bool:
        """Check if JSON file is in HAR format"""
        try:
            # Handle UTF-8 BOM encoding (common in Fiddler exports)
            with open(path, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)
                return "log" in data and "entries" in data.get("log", {})
        except:
            return False
    
    def extract_entities(self, artifact_path: Union[str, Path]) -> MCPEntities:
        """Extract MCP entities from network capture"""
        path = Path(artifact_path)
        entities = MCPEntities()
        entities.analysis_timestamp = datetime.now()
        entities.artifact_sources = [str(path)]
        
        discovered_servers: Dict[str, MCPServer] = {}
        discovered_tools: Dict[str, MCPTool] = {}
        
        for capture_file in self._get_capture_files(path):
            if capture_file.suffix.lower() in [".har", ".json"]:
                self._process_har_entities(capture_file, discovered_servers, discovered_tools)
            elif capture_file.suffix.lower() in [".pcap", ".pcapng", ".cap"]:
                self._process_pcap_entities(capture_file, discovered_servers, discovered_tools)
        
        entities.servers = list(discovered_servers.values())
        
        for tool in discovered_tools.values():
            if tool.server_name and tool.server_name in discovered_servers:
                discovered_servers[tool.server_name].tools.append(tool)
        
        return entities
    
    def extract_events(self, artifact_path: Union[str, Path]) -> Timeline:
        """Extract events from network capture"""
        path = Path(artifact_path)
        timeline = Timeline()
        timeline.sources = [ArtifactSource.NETWORK_CAPTURE]
        
        for capture_file in self._get_capture_files(path):
            if capture_file.suffix.lower() in [".har", ".json"]:
                events = self._process_har_events(capture_file)
            elif capture_file.suffix.lower() in [".pcap", ".pcapng", ".cap"]:
                events = self._process_pcap_events(capture_file)
            else:
                continue
            
            for event in events:
                timeline.add_event(event)
        
        return timeline
    
    def _get_capture_files(self, path: Path) -> List[Path]:
        """Get list of capture files"""
        if path.is_file():
            return [path]
        
        files = []
        for ext in ["*.pcap", "*.pcapng", "*.cap", "*.har"]:
            files.extend(path.glob(ext))
        
        for json_file in path.glob("*.json"):
            if self._is_har_file(json_file):
                files.append(json_file)
        
        files.sort(key=lambda f: f.stat().st_mtime)
        return files
    
    # ==================== HAR Processing ====================

    def _process_har_entities(self, har_file: Path, servers: Dict, tools: Dict):
        """Extract entities from HAR file"""
        try:
            # Handle UTF-8 BOM encoding (common in Fiddler exports)
            with open(har_file, 'r', encoding='utf-8-sig') as f:
                har_data = json.load(f)
        except Exception as e:
            self.logger.error(f"Error reading HAR: {e}")
            return
        
        entries = har_data.get("log", {}).get("entries", [])
        
        for entry in entries:
            request = entry.get("request", {})
            response = entry.get("response", {})
            url = request.get("url", "")
            
            if not self._is_mcp_traffic(url, request, response):
                continue
            
            parsed_url = urlparse(url)
            server_name = self._get_server_name_from_url(url)
            
            if server_name not in servers:
                servers[server_name] = MCPServer(
                    name=server_name,
                    server_type=self._determine_server_type_from_url(url),
                    transport=TransportType.STREAMABLE_HTTP,
                    url=f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}",
                    sources=[ArtifactSource.NETWORK_CAPTURE]
                )
            
            servers[server_name].total_requests += 1

            # Extract tool information (apply SSE parsing for responses)
            req_body = self._get_har_body(request)
            res_body = self._get_har_body_parsed(response, parse_sse=True)

            if req_body:
                self._extract_tools_from_jsonrpc(req_body, server_name, tools)
                # Extract server info from initialize response
                self._extract_server_info_from_initialize(req_body, res_body, servers, server_name)
                # Extract forensic metadata (from tools/call results)
                self._extract_forensic_metadata(req_body, res_body, servers, server_name)

            if res_body:
                self._extract_tools_from_jsonrpc(res_body, server_name, tools)
    
    def _process_har_events(self, har_file: Path) -> List[MCPEvent]:
        """Extract events from HAR file"""
        events = []

        # Storage for pending calls for request-response correlation
        pending_calls: Dict[str, ToolCallEvent] = {}

        try:
            # Handle UTF-8 BOM encoding (common in Fiddler exports)
            with open(har_file, 'r', encoding='utf-8-sig') as f:
                har_data = json.load(f)
        except Exception as e:
            self.logger.error(f"Error reading HAR: {e}")
            return events

        entries = har_data.get("log", {}).get("entries", [])
        
        for entry in entries:
            request = entry.get("request", {})
            response = entry.get("response", {})
            url = request.get("url", "")
            
            if not self._is_mcp_traffic(url, request, response):
                continue
            
            started = entry.get("startedDateTime")
            timestamp = self._parse_timestamp(started) if started else datetime.now()
            server_name = self._get_server_name_from_url(url)
            time_ms = entry.get("time", 0)
            
            # Request event
            request_body = self._get_har_body(request)
            events.append(HTTPEvent(
                timestamp=timestamp,
                event_type=EventType.HTTP_REQUEST,
                source=ArtifactSource.NETWORK_CAPTURE,
                method=request.get("method", "POST"),
                url=url,
                headers=self._har_headers_to_dict(request.get("headers", [])),
                body=request_body[:1000] if request_body else None,
                server_name=server_name,
                details={"source_file": har_file.name}
            ))
            
            # Parse JSON-RPC request
            if request_body:
                events.extend(self._parse_jsonrpc_body(
                    request_body, timestamp, server_name, har_file.name,
                    is_request=True, pending_calls=pending_calls
                ))

            # Response event (apply SSE parsing)
            response_body_raw = self._get_har_body(response)
            response_body_parsed = self._get_har_body_parsed(response, parse_sse=True)
            status_code = response.get("status")

            events.append(HTTPEvent(
                timestamp=timestamp,
                event_type=EventType.HTTP_RESPONSE,
                source=ArtifactSource.NETWORK_CAPTURE,
                method=request.get("method", "POST"),
                url=url,
                status_code=status_code,
                headers=self._har_headers_to_dict(response.get("headers", [])),
                response_body=response_body_raw[:1000] if response_body_raw else None,
                duration_ms=time_ms,
                server_name=server_name,
                severity=EventSeverity.ERROR if status_code and status_code >= 400 else EventSeverity.INFO,
                details={
                    "source_file": har_file.name,
                    "is_sse": 'data:' in (response_body_raw or '')
                }
            ))

            # Parse JSON-RPC response (use SSE-parsed body)
            if response_body_parsed:
                events.extend(self._parse_jsonrpc_body(
                    response_body_parsed, timestamp, server_name, har_file.name,
                    is_request=False, pending_calls=pending_calls
                ))
        
        return events
    
    def _get_har_body(self, message: Dict) -> Optional[str]:
        """Extract body from HAR request/response"""
        post_data = message.get("postData", {})
        if post_data:
            return post_data.get("text")

        content = message.get("content", {})
        if content:
            return content.get("text")

        return None

    def _parse_sse_response(self, body: str) -> Optional[str]:
        """
        Extract JSON data from SSE (Server-Sent Events) response

        Remote MCP servers respond in SSE format:
        event: message
        data: {"jsonrpc":"2.0","id":0,"result":{...}}
        """
        if not body:
            return None

        # Check for SSE format
        if 'data:' not in body:
            return body  # Return original if not SSE

        # Extract JSON from all data: lines
        matches = self.sse_data_pattern.findall(body)
        if matches:
            # Return first valid JSON
            for match in matches:
                match = match.strip()
                if match.startswith('{'):
                    return match
        return None

    def _get_har_body_parsed(self, message: Dict, parse_sse: bool = True) -> Optional[str]:
        """Extract and parse HAR body with SSE handling"""
        body = self._get_har_body(message)
        if body and parse_sse:
            parsed = self._parse_sse_response(body)
            if parsed:
                return parsed
        return body
    
    def _har_headers_to_dict(self, headers: List[Dict]) -> Dict[str, str]:
        """Convert HAR headers to dictionary"""
        return {h.get("name", ""): h.get("value", "") for h in headers}
    
    # ==================== PCAP Processing ====================

    def _process_pcap_entities(self, pcap_file: Path, servers: Dict, tools: Dict):
        """Extract entities from PCAP file (including HTTP body parsing)"""
        try:
            import pyshark
        except ImportError:
            self.logger.warning("pyshark not installed. Install: pip install pyshark")
            servers["unknown-pcap"] = MCPServer(
                name="unknown-pcap",
                server_type=ServerType.CUSTOM_REMOTE,
                transport=TransportType.STREAMABLE_HTTP,
                sources=[ArtifactSource.NETWORK_CAPTURE],
                server_info={"note": "pyshark required for detailed PCAP parsing"}
            )
            return

        # Temporary storage for HTTP stream reassembly
        http_streams: Dict[str, Dict] = {}

        try:
            # Filter HTTP traffic only, include file data
            cap = pyshark.FileCapture(
                str(pcap_file),
                display_filter='http',
                use_json=True,
                include_raw=True
            )

            for packet in cap:
                if not hasattr(packet, 'http'):
                    continue

                # HTTP request handling
                if hasattr(packet.http, 'request_uri'):
                    host = getattr(packet.http, 'host', 'unknown')
                    uri = packet.http.request_uri
                    method = getattr(packet.http, 'request_method', 'GET')

                    # Determine scheme by port for HTTPS
                    port = getattr(packet.tcp, 'dstport', '80') if hasattr(packet, 'tcp') else '80'
                    scheme = 'https' if port == '443' else 'http'
                    url = f"{scheme}://{host}{uri}"

                    if not self._is_mcp_url(url):
                        # Check for JSON-RPC body
                        body = self._extract_pcap_body(packet)
                        if not (body and '"jsonrpc"' in body):
                            continue

                    server_name = self._get_server_name_from_url(url)
                    if server_name not in servers:
                        servers[server_name] = MCPServer(
                            name=server_name,
                            server_type=self._determine_server_type_from_url(url),
                            transport=TransportType.STREAMABLE_HTTP,
                            url=url,
                            sources=[ArtifactSource.NETWORK_CAPTURE]
                        )
                    servers[server_name].total_requests += 1

                    # Extract tool information from request body
                    req_body = self._extract_pcap_body(packet)
                    if req_body:
                        self._extract_tools_from_jsonrpc(req_body, server_name, tools)

                        # Prepare request-response matching by stream ID
                        stream_id = self._get_pcap_stream_id(packet)
                        if stream_id:
                            http_streams[stream_id] = {
                                "req_body": req_body,
                                "server_name": server_name,
                                "url": url
                            }

                # HTTP response handling
                elif hasattr(packet.http, 'response_code'):
                    res_body = self._extract_pcap_body(packet)

                    # Parse SSE response
                    if res_body:
                        res_body_parsed = self._parse_sse_response(res_body)
                        if res_body_parsed:
                            res_body = res_body_parsed

                    # Match with request by stream ID
                    stream_id = self._get_pcap_stream_id(packet)
                    if stream_id and stream_id in http_streams:
                        stream_data = http_streams[stream_id]
                        server_name = stream_data["server_name"]
                        req_body = stream_data["req_body"]

                        # Extract tool and server information
                        if res_body:
                            self._extract_tools_from_jsonrpc(res_body, server_name, tools)
                            self._extract_server_info_from_initialize(req_body, res_body, servers, server_name)
                            self._extract_forensic_metadata(req_body, res_body, servers, server_name)

            cap.close()
        except Exception as e:
            self.logger.error(f"Error processing PCAP: {e}")

    def _extract_pcap_body(self, packet) -> Optional[str]:
        """Extract HTTP body from PCAP packet"""
        try:
            # Try various pyshark methods to access body
            if hasattr(packet.http, 'file_data'):
                return packet.http.file_data

            if hasattr(packet.http, 'data'):
                # Convert hex data to string
                data = packet.http.data
                if isinstance(data, str) and ':' in data:
                    # Hex format: "7b:22:6a:73..."
                    try:
                        hex_str = data.replace(':', '')
                        return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
                    except:
                        pass
                return data

            # Alternative method for JSON-RPC request detection
            if hasattr(packet, 'data'):
                raw = getattr(packet.data, 'data', None)
                if raw:
                    try:
                        return bytes.fromhex(raw.replace(':', '')).decode('utf-8', errors='ignore')
                    except:
                        pass

        except Exception:
            pass
        return None

    def _get_pcap_stream_id(self, packet) -> Optional[str]:
        """Extract TCP stream ID from PCAP packet"""
        try:
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'stream'):
                return str(packet.tcp.stream)
        except:
            pass
        return None
    
    def _process_pcap_events(self, pcap_file: Path) -> List[MCPEvent]:
        """Extract events from PCAP file (including HTTP body parsing)"""
        events = []

        try:
            import pyshark
        except ImportError:
            return events

        # Stream storage for request-response matching
        pending_requests: Dict[str, Dict] = {}

        try:
            cap = pyshark.FileCapture(
                str(pcap_file),
                display_filter='http',
                use_json=True,
                include_raw=True
            )

            for packet in cap:
                if not hasattr(packet, 'http'):
                    continue

                timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp))

                # HTTP request handling
                if hasattr(packet.http, 'request_uri'):
                    host = getattr(packet.http, 'host', 'unknown')
                    uri = packet.http.request_uri
                    method = getattr(packet.http, 'request_method', 'GET')

                    port = getattr(packet.tcp, 'dstport', '80') if hasattr(packet, 'tcp') else '80'
                    scheme = 'https' if port == '443' else 'http'
                    url = f"{scheme}://{host}{uri}"

                    req_body = self._extract_pcap_body(packet)

                    # Filter MCP traffic
                    is_mcp = self._is_mcp_url(url) or (req_body and '"jsonrpc"' in req_body)
                    if not is_mcp:
                        continue

                    server_name = self._get_server_name_from_url(url)

                    # HTTP request event
                    events.append(HTTPEvent(
                        timestamp=timestamp,
                        event_type=EventType.HTTP_REQUEST,
                        source=ArtifactSource.NETWORK_CAPTURE,
                        method=method,
                        url=url,
                        body=req_body[:1000] if req_body else None,
                        server_name=server_name,
                        client_ip=getattr(packet.ip, 'src', None) if hasattr(packet, 'ip') else None,
                        server_ip=getattr(packet.ip, 'dst', None) if hasattr(packet, 'ip') else None,
                        details={"source_file": pcap_file.name}
                    ))

                    # Parse JSON-RPC request
                    if req_body:
                        events.extend(self._parse_jsonrpc_body(
                            req_body, timestamp, server_name, pcap_file.name, is_request=True
                        ))

                        # Save for response matching
                        stream_id = self._get_pcap_stream_id(packet)
                        if stream_id:
                            pending_requests[stream_id] = {
                                "req_body": req_body,
                                "server_name": server_name,
                                "url": url,
                                "timestamp": timestamp
                            }

                # HTTP response handling
                elif hasattr(packet.http, 'response_code'):
                    status_code = int(packet.http.response_code)
                    res_body_raw = self._extract_pcap_body(packet)

                    # SSE parsing
                    res_body = res_body_raw
                    is_sse = res_body_raw and 'data:' in res_body_raw
                    if is_sse:
                        parsed = self._parse_sse_response(res_body_raw)
                        if parsed:
                            res_body = parsed

                    # Stream matching
                    stream_id = self._get_pcap_stream_id(packet)
                    server_name = None
                    url = None

                    if stream_id and stream_id in pending_requests:
                        req_data = pending_requests[stream_id]
                        server_name = req_data["server_name"]
                        url = req_data["url"]

                    # HTTP response event
                    events.append(HTTPEvent(
                        timestamp=timestamp,
                        event_type=EventType.HTTP_RESPONSE,
                        source=ArtifactSource.NETWORK_CAPTURE,
                        url=url,
                        status_code=status_code,
                        response_body=res_body_raw[:1000] if res_body_raw else None,
                        server_name=server_name,
                        severity=EventSeverity.ERROR if status_code >= 400 else EventSeverity.INFO,
                        details={
                            "source_file": pcap_file.name,
                            "is_sse": is_sse
                        }
                    ))

                    # Parse JSON-RPC response
                    if res_body and server_name:
                        events.extend(self._parse_jsonrpc_body(
                            res_body, timestamp, server_name, pcap_file.name, is_request=False
                        ))

            cap.close()
        except Exception as e:
            self.logger.error(f"Error processing PCAP: {e}")

        return events
    
    # ==================== Common Utilities ====================

    def _is_mcp_traffic(self, url: str, request: Dict, response: Dict) -> bool:
        """Check if traffic is MCP-related"""
        if self._is_mcp_url(url):
            return True

        body = self._get_har_body(request)
        if body and '"jsonrpc"' in body:
            return True

        return False
    
    def _is_mcp_url(self, url: str) -> bool:
        """Check if URL is MCP-related"""
        url_lower = url.lower()
        return any(pattern.lower() in url_lower for pattern in self.mcp_url_patterns)
    
    def _get_server_name_from_url(self, url: str) -> str:
        """Extract server name from URL - generic approach using domain"""
        parsed = urlparse(url)
        host = parsed.netloc

        # Remove port if present
        if ":" in host:
            host = host.split(":")[0]

        if "localhost" in host or "127.0.0.1" in host:
            return f"local-{parsed.port or 80}"

        # Use the subdomain or main domain as server name
        # e.g., mcp.notion.com -> mcp-notion, api.github.com -> api-github
        parts = host.split(".")
        if len(parts) >= 2:
            # Use subdomain.domain format (excluding TLD)
            return "-".join(parts[:-1]) if parts[0] != "www" else parts[1]

        return host.replace(".", "-")
    
    def _determine_server_type_from_url(self, url: str) -> ServerType:
        """Determine server type from URL"""
        url_lower = url.lower()

        if "localhost" in url_lower or "127.0.0.1" in url_lower:
            return ServerType.CUSTOM_REMOTE
        if "ngrok" in url_lower:
            return ServerType.CUSTOM_REMOTE

        # Official Remote MCP providers
        official_domains = [
            "mcp.notion.com", "notion.so", "notion.com",
            "mcp.github.com", "github.com",
            "mcp.anthropic.com", "anthropic.com",
        ]
        if any(d in url_lower for d in official_domains):
            return ServerType.OFFICIAL_REMOTE

        return ServerType.CUSTOM_REMOTE
    
    def _extract_server_info_from_initialize(
        self, req_body: str, res_body: Optional[str],
        servers: Dict, server_name: str
    ):
        """Extract server info from initialize request/response"""
        try:
            req_data = json.loads(req_body)
        except:
            return

        if req_data.get("method") != "initialize":
            return

        # Client information
        client_info = req_data.get("params", {}).get("clientInfo", {})
        if server_name in servers:
            servers[server_name].client_info = client_info

        # Extract server info from response
        if not res_body:
            return

        try:
            res_data = json.loads(res_body)
        except:
            return

        result = res_data.get("result", {})
        if server_name in servers:
            server = servers[server_name]
            # Server information
            server_info = result.get("serverInfo", {})
            if server_info:
                server.server_info = server_info
                if server_info.get("name"):
                    server.display_name = server_info["name"]
                if server_info.get("version"):
                    server.version = server_info["version"]

            # Protocol version
            protocol_version = result.get("protocolVersion")
            if protocol_version:
                server.protocol_version = protocol_version

            # capabilities
            capabilities = result.get("capabilities", {})
            if capabilities:
                server.capabilities = capabilities

    def _extract_forensic_metadata(
        self, req_body: str, res_body: Optional[str],
        servers: Dict, server_name: str
    ):
        """
        Extract forensic metadata from tools/call results (generic)

        Common extraction for all Remote MCP servers:
        - Tool call records (tool_name, arguments, timestamp)
        - User/account related information (pattern matching)
        - Resource access records
        """
        try:
            req_data = json.loads(req_body)
        except:
            return

        if req_data.get("method") != "tools/call":
            return

        tool_name = req_data.get("params", {}).get("name")
        tool_args = req_data.get("params", {}).get("arguments", {})
        if not tool_name:
            return

        # Parse response
        if not res_body:
            return

        try:
            res_data = json.loads(res_body)
        except:
            return

        result = res_data.get("result", {})
        content = result.get("content", []) if isinstance(result, dict) else []

        # Extract text type data from content
        text_content = None
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text_content = item.get("text")
                break

        if server_name not in servers:
            return

        server = servers[server_name]
        if server.forensic_metadata is None:
            server.forensic_metadata = {
                "tool_calls": [],  # All tool call records
                "identity_info": {},  # User/bot identification info
                "accessed_resources": [],  # Accessed resources
                "sensitive_data": []  # Sensitive data detection
            }

        # Tool call record (generic)
        call_record = {
            "tool": tool_name,
            "arguments": tool_args,
            "has_result": text_content is not None
        }
        server.forensic_metadata["tool_calls"].append(call_record)

        # Exit here if no text_content
        if not text_content:
            return

        # Try JSON parsing
        tool_result = None
        try:
            tool_result = json.loads(text_content)
        except:
            # Analyze original text if not JSON
            pass

        # === Generic pattern-based metadata extraction ===

        # 1. User/bot identity info patterns (get-self, get-user, whoami, etc.)
        identity_patterns = ["get-self", "get-user", "whoami", "me", "current-user", "profile"]
        if any(p in tool_name.lower() for p in identity_patterns):
            if tool_result and isinstance(tool_result, dict):
                identity = self._extract_identity_info(tool_result)
                if identity:
                    server.forensic_metadata["identity_info"].update(identity)

        # 2. Team/workspace info patterns
        team_patterns = ["get-teams", "get-workspace", "list-teams", "organizations"]
        if any(p in tool_name.lower() for p in team_patterns):
            if tool_result and isinstance(tool_result, dict):
                teams = self._extract_team_info(tool_result)
                if teams:
                    server.forensic_metadata["teams"] = teams

        # 3. Extract resources from search/list results
        search_patterns = ["search", "list", "query", "find", "get-all"]
        if any(p in tool_name.lower() for p in search_patterns):
            if tool_result:
                resources = self._extract_resource_list(tool_result, tool_name)
                if resources:
                    if "accessed_resources" not in server.forensic_metadata:
                        server.forensic_metadata["accessed_resources"] = []
                    server.forensic_metadata["accessed_resources"].extend(resources[:50])

        # 4. Sensitive data detection (email, API keys, etc.)
        if text_content:
            sensitive = self._detect_sensitive_data(text_content, tool_name)
            if sensitive:
                server.forensic_metadata["sensitive_data"].extend(sensitive)

    def _extract_identity_info(self, data: Dict) -> Dict:
        """Extract user/bot identification info"""
        identity = {}
        # Extract common fields
        for key in ["id", "user_id", "bot_id", "account_id"]:
            if key in data:
                identity["id"] = data[key]
                break
        for key in ["name", "username", "display_name", "bot_name"]:
            if key in data:
                identity["name"] = data[key]
                break
        for key in ["email", "email_address"]:
            if key in data:
                identity["email"] = data[key]
                break
        for key in ["avatar", "avatar_url", "profile_image"]:
            if key in data:
                identity["avatar"] = data[key]
                break
        if "object" in data:
            identity["type"] = data["object"]
        return identity

    def _extract_team_info(self, data: Dict) -> List[Dict]:
        """Extract team/workspace info"""
        teams = []
        # Support various structures
        team_lists = []
        for key in ["joinedTeams", "teams", "workspaces", "organizations", "results"]:
            if key in data and isinstance(data[key], list):
                team_lists = data[key]
                break

        for team in team_lists:
            if isinstance(team, dict):
                teams.append({
                    "id": team.get("id") or team.get("team_id"),
                    "name": team.get("name") or team.get("team_name"),
                    "role": team.get("role") or team.get("permission"),
                    "type": team.get("type")
                })
        return teams

    def _extract_resource_list(self, data: Any, tool_name: str) -> List[Dict]:
        """Extract resource info from search/list results"""
        resources = []

        # Find result list
        items = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            for key in ["results", "items", "data", "entries", "files", "pages", "documents"]:
                if key in data and isinstance(data[key], list):
                    items = data[key]
                    break

        for item in items[:50]:  # Maximum 50 items
            if isinstance(item, dict):
                resource = {
                    "source_tool": tool_name
                }
                # Title/name
                for key in ["title", "name", "filename", "subject"]:
                    if key in item:
                        resource["title"] = item[key]
                        break
                # URL/path
                for key in ["url", "uri", "path", "link", "href"]:
                    if key in item:
                        resource["url"] = item[key]
                        break
                # ID
                for key in ["id", "page_id", "file_id", "document_id"]:
                    if key in item:
                        resource["id"] = item[key]
                        break
                # Type
                for key in ["type", "object", "kind"]:
                    if key in item:
                        resource["type"] = item[key]
                        break

                if resource.get("title") or resource.get("url") or resource.get("id"):
                    resources.append(resource)

        return resources

    def _detect_sensitive_data(self, content: str, tool_name: str) -> List[Dict]:
        """Detect sensitive information"""
        sensitive = []
        import re

        # Email pattern
        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', content)
        for email in set(emails[:10]):
            sensitive.append({"type": "email", "value": email, "source_tool": tool_name})

        # API key patterns (common formats)
        api_patterns = [
            (r'sk-[a-zA-Z0-9]{20,}', "api_key_openai"),
            (r'ghp_[a-zA-Z0-9]{36}', "github_token"),
            (r'xox[baprs]-[a-zA-Z0-9-]+', "slack_token"),
        ]
        for pattern, key_type in api_patterns:
            matches = re.findall(pattern, content)
            for match in matches[:5]:
                # Mask sensitive data
                masked = match[:8] + "..." + match[-4:]
                sensitive.append({"type": key_type, "value": masked, "source_tool": tool_name})

        return sensitive

    def _extract_tools_from_jsonrpc(self, body: str, server_name: str, tools: Dict):
        """Extract tool info from JSON-RPC body"""
        try:
            data = json.loads(body)
        except:
            return

        if data.get("method") == "tools/call":
            tool_name = data.get("params", {}).get("name")
            if tool_name and tool_name not in tools:
                tools[tool_name] = MCPTool(name=tool_name, server_name=server_name)

        result = data.get("result", {})
        if "tools" in result:
            for tool_def in result.get("tools", []):
                tool_name = tool_def.get("name")
                if tool_name and tool_name not in tools:
                    tools[tool_name] = MCPTool(
                        name=tool_name,
                        description=tool_def.get("description"),
                        input_schema=tool_def.get("inputSchema"),
                        server_name=server_name
                    )
    
    def _parse_jsonrpc_body(self, body: str, timestamp: datetime,
                           server_name: str, source_file: str,
                           is_request: bool,
                           pending_calls: Optional[Dict] = None) -> List[MCPEvent]:
        """Parse JSON-RPC body to create events"""
        events = []

        try:
            data = json.loads(body)
        except:
            return events

        if is_request and "method" in data:
            method = data.get("method")
            params = data.get("params", {})
            request_id = data.get("id")

            if method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})

                # Extract user intent
                user_intent, query_text = self._extract_user_intent(tool_name, arguments)

                event = ToolCallEvent(
                    timestamp=timestamp,
                    event_type=EventType.TOOL_CALL,
                    source=ArtifactSource.NETWORK_CAPTURE,
                    server_name=server_name,
                    tool_name=tool_name,
                    arguments=arguments,
                    user_intent=user_intent,
                    query_text=query_text,
                    request_id=str(request_id) if request_id else None,
                    details={"source_file": source_file}
                )
                events.append(event)

                # Store for result correlation
                if pending_calls is not None and request_id is not None:
                    pending_calls[str(request_id)] = event

        elif not is_request and ("result" in data or "error" in data):
            request_id = data.get("id")
            is_error = "error" in data

            # error field can be string or dict
            error_data = data.get("error")
            if isinstance(error_data, dict):
                error_message = error_data.get("message")
            elif isinstance(error_data, str):
                error_message = error_data
            else:
                error_message = str(error_data) if error_data else None

            # Extract result summary and link to original call
            result_summary = None
            result_count = None
            if not is_error and pending_calls and str(request_id) in pending_calls:
                original_call = pending_calls[str(request_id)]
                result_summary, result_count = self._extract_result_summary(
                    data.get("result"), original_call.tool_name
                )
                # Add result summary to original call event
                original_call.result_summary = result_summary
                original_call.result_count = result_count

            events.append(ToolResultEvent(
                timestamp=timestamp,
                event_type=EventType.TOOL_RESULT if not is_error else EventType.TOOL_ERROR,
                source=ArtifactSource.NETWORK_CAPTURE,
                server_name=server_name,
                result=data.get("result"),
                is_error=is_error,
                error_message=error_message,
                request_id=str(request_id) if request_id else None,
                severity=EventSeverity.ERROR if is_error else EventSeverity.INFO,
                details={
                    "source_file": source_file,
                    "result_summary": result_summary,
                    "result_count": result_count
                }
            ))

        return events

    def _extract_user_intent(self, tool_name: str, arguments: Dict) -> tuple:
        """Extract user intent from tool call"""
        if not tool_name:
            return None, None

        tool_lower = tool_name.lower()
        query_text = None
        user_intent = None

        # Search tools
        if "search" in tool_lower:
            query_text = arguments.get("query") or arguments.get("q") or arguments.get("keyword")
            if query_text:
                if query_text == "*":
                    user_intent = "List all items"
                else:
                    user_intent = f"Search for '{query_text}'"
            else:
                user_intent = "Perform search"

        # Retrieve tools
        elif "get" in tool_lower or "fetch" in tool_lower or "read" in tool_lower:
            if "self" in tool_lower or "me" in tool_lower:
                user_intent = "Get current user info"
            elif "user" in tool_lower:
                user_id = arguments.get("user_id") or arguments.get("id")
                user_intent = "Get user info" + (f" (ID: {user_id[:8]}...)" if user_id else "")
            elif "team" in tool_lower:
                user_intent = "Get team/workspace info"
            elif "page" in tool_lower or "document" in tool_lower:
                page_id = arguments.get("page_id") or arguments.get("id")
                user_intent = "Get page/document" + (f" (ID: {page_id[:8]}...)" if page_id else "")
            elif "comment" in tool_lower:
                user_intent = "Get comments"
            else:
                # General retrieval
                target = tool_lower.replace("get-", "").replace("fetch-", "").replace("-", " ")
                user_intent = f"Get {target}"

        # Create tools
        elif "create" in tool_lower or "add" in tool_lower:
            if "page" in tool_lower:
                title = arguments.get("title") or arguments.get("name")
                user_intent = "Create new page" + (f": '{title[:30]}...'" if title and len(title) > 30 else f": '{title}'" if title else "")
            elif "comment" in tool_lower:
                user_intent = "Add comment"
            elif "database" in tool_lower:
                user_intent = "Create database"
            else:
                target = tool_lower.replace("create-", "").replace("add-", "").replace("-", " ")
                user_intent = f"Create {target}"

        # Update tools
        elif "update" in tool_lower or "edit" in tool_lower or "modify" in tool_lower:
            if "page" in tool_lower:
                user_intent = "Update page"
            else:
                target = tool_lower.replace("update-", "").replace("edit-", "").replace("-", " ")
                user_intent = f"Update {target}"

        # Delete tools
        elif "delete" in tool_lower or "remove" in tool_lower:
            target = tool_lower.replace("delete-", "").replace("remove-", "").replace("-", " ")
            user_intent = f"Delete {target}"

        # Move/duplicate tools
        elif "move" in tool_lower:
            user_intent = "Move page/item"
        elif "duplicate" in tool_lower or "copy" in tool_lower:
            user_intent = "Duplicate page/item"

        # Other
        else:
            # Infer intent from tool name
            user_intent = tool_name.replace("-", " ").replace("_", " ")

        return user_intent, query_text

    def _extract_result_summary(self, result: Any, tool_name: str) -> tuple:
        """Extract summary info from result"""
        if not result:
            return None, None

        summary = None
        count = None

        # If result is a dict
        if isinstance(result, dict):
            content = result.get("content", [])
            if content and isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text = item.get("text", "")
                        try:
                            parsed = json.loads(text)
                            return self._summarize_parsed_result(parsed, tool_name)
                        except:
                            # Non-JSON text
                            if len(text) > 100:
                                summary = f"Text response ({len(text)} characters)"
                            else:
                                summary = text[:100]
                            return summary, None

        return summary, count

    def _summarize_parsed_result(self, data: Any, tool_name: str) -> tuple:
        """Summarize parsed result data"""
        if not data:
            return None, None

        tool_lower = tool_name.lower() if tool_name else ""

        # List-type result
        if isinstance(data, list):
            count = len(data)
            if count > 0 and isinstance(data[0], dict):
                first_title = data[0].get("title") or data[0].get("name") or "item"
                return f"{count} results (first: {first_title[:30]}...)" if len(str(first_title)) > 30 else f"{count} results (first: {first_title})", count
            return f"{count} results", count

        # Dict-type result
        if isinstance(data, dict):
            # Search results
            if "results" in data:
                results = data["results"]
                count = len(results)
                if count > 0:
                    titles = [r.get("title") or r.get("name") or "?" for r in results[:3]]
                    preview = ", ".join(str(t)[:20] for t in titles)
                    return f"{count} results: {preview}...", count
                return "No results", 0

            # User information
            if "name" in data and ("id" in data or "user_id" in data):
                name = data.get("name")
                obj_type = data.get("object") or data.get("type") or "item"
                return f"{obj_type}: {name}", 1

            # Team information
            if "joinedTeams" in data:
                teams = data["joinedTeams"]
                count = len(teams)
                names = [t.get("name") for t in teams[:3]]
                return f"{count} teams: {', '.join(filter(None, names))}", count

            # General object
            if "id" in data:
                title = data.get("title") or data.get("name") or data.get("id")[:8]
                return f"Object: {title}", 1

        return None, None

    def get_traffic_summary(self, artifact_path: Union[str, Path]) -> Dict[str, Any]:
        """Network traffic summary"""
        entities = self.extract_entities(artifact_path)
        timeline = self.extract_events(artifact_path)
        
        http_events = [e for e in timeline.events if isinstance(e, HTTPEvent)]
        
        return {
            "total_servers": len(entities.servers),
            "servers": [s.name for s in entities.servers],
            "total_http_events": len(http_events),
            "requests": len([e for e in http_events if e.event_type == EventType.HTTP_REQUEST]),
            "responses": len([e for e in http_events if e.event_type == EventType.HTTP_RESPONSE]),
            "errors": len([e for e in http_events if e.severity == EventSeverity.ERROR]),
            "tool_calls": len([e for e in timeline.events if isinstance(e, ToolCallEvent)])
        }