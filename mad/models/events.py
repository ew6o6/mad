"""
MCP Forensics - Event Models
MCP event and timeline definitions
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union
from datetime import datetime
from enum import Enum

from .entities import ArtifactSource


def _normalize_timestamp(ts):
    """Normalize timestamp for comparison (handle timezone-aware/naive mix)"""
    if ts is None:
        return datetime.min
    if hasattr(ts, 'tzinfo') and ts.tzinfo is not None:
        return ts.replace(tzinfo=None)
    return ts


class EventType(Enum):
    """Event type"""
    # Connection lifecycle
    CONNECTION_INIT = "connection_init"
    CONNECTION_READY = "connection_ready"
    CONNECTION_CLOSE = "connection_close"
    CONNECTION_ERROR = "connection_error"

    # Tool related
    TOOL_LIST = "tool_list"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    TOOL_ERROR = "tool_error"

    # Resource related
    RESOURCE_LIST = "resource_list"
    RESOURCE_READ = "resource_read"

    # File access (server log)
    FILE_ACCESS = "file_access"
    FILE_ACCESS_DENIED = "file_access_denied"

    # Network
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"

    # Conversation (vscdb)
    USER_QUERY = "user_query"
    AI_RESPONSE = "ai_response"

    # Other
    NOTIFICATION = "notification"
    UNKNOWN = "unknown"


class EventSeverity(Enum):
    """Event severity"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    SECURITY = "security"  # Security-related event


@dataclass
class MCPEvent:
    """Base MCP event"""
    timestamp: datetime
    event_type: EventType
    source: ArtifactSource

    # Related information
    server_name: Optional[str] = None
    tool_name: Optional[str] = None

    # Details
    details: Optional[Dict[str, Any]] = None
    raw_data: Optional[str] = None  # Original log line

    # Correlation
    request_id: Optional[str] = None  # JSON-RPC id
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None  # Manual correlation

    # Metadata
    severity: EventSeverity = EventSeverity.INFO
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "source": self.source.value,
            "server_name": self.server_name,
            "tool_name": self.tool_name,
            "details": self.details,
            "raw_data": self.raw_data,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
            "severity": self.severity.value
        }


@dataclass
class ToolCallEvent(MCPEvent):
    """Tool call event"""
    arguments: Optional[Dict[str, Any]] = None

    # User intent inference (extracted from arguments)
    user_intent: Optional[str] = None  # e.g., "Search documents about zlib"
    query_text: Optional[str] = None   # Search query or key argument

    # Result summary
    result_summary: Optional[str] = None  # e.g., "3 results about 'zlib.decompress' from 40 total"
    result_count: Optional[int] = None

    def __post_init__(self):
        self.event_type = EventType.TOOL_CALL

    def to_dict(self) -> Dict:
        base = super().to_dict()
        base["arguments"] = self.arguments
        base["user_intent"] = self.user_intent
        base["query_text"] = self.query_text
        base["result_summary"] = self.result_summary
        base["result_count"] = self.result_count
        return base


@dataclass
class ToolResultEvent(MCPEvent):
    """Tool result event"""
    result: Optional[Any] = None
    is_error: bool = False
    error_message: Optional[str] = None
    duration_ms: Optional[float] = None  # Execution time
    
    def __post_init__(self):
        self.event_type = EventType.TOOL_RESULT if not self.is_error else EventType.TOOL_ERROR
        if self.is_error:
            self.severity = EventSeverity.ERROR
    
    def to_dict(self) -> Dict:
        base = super().to_dict()
        base.update({
            "result": self.result,
            "is_error": self.is_error,
            "error_message": self.error_message,
            "duration_ms": self.duration_ms
        })
        return base


@dataclass
class FileAccessEvent(MCPEvent):
    """File access event (from server log)"""
    path: str = ""
    operation: str = "read"  # read, write, list, delete
    success: bool = True
    size_bytes: Optional[int] = None
    error: Optional[str] = None
    client_ip: Optional[str] = None

    def __post_init__(self):
        self.event_type = EventType.FILE_ACCESS if self.success else EventType.FILE_ACCESS_DENIED
        if not self.success:
            self.severity = EventSeverity.WARNING
            # Path traversal attempts etc. are security events
            if self.error and "scope" in self.error.lower():
                self.severity = EventSeverity.SECURITY
    
    def to_dict(self) -> Dict:
        base = super().to_dict()
        base.update({
            "path": self.path,
            "operation": self.operation,
            "success": self.success,
            "size_bytes": self.size_bytes,
            "error": self.error,
            "client_ip": self.client_ip
        })
        return base


@dataclass
class HTTPEvent(MCPEvent):
    """HTTP request/response event"""
    method: str = "POST"
    url: str = ""
    status_code: Optional[int] = None
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    response_body: Optional[str] = None
    duration_ms: Optional[float] = None

    # IP information
    client_ip: Optional[str] = None
    server_ip: Optional[str] = None
    
    def __post_init__(self):
        if self.status_code:
            self.event_type = EventType.HTTP_RESPONSE
            if self.status_code >= 400:
                self.severity = EventSeverity.ERROR
        else:
            self.event_type = EventType.HTTP_REQUEST
    
    def to_dict(self) -> Dict:
        base = super().to_dict()
        base.update({
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "response_body": self.response_body,
            "duration_ms": self.duration_ms,
            "client_ip": self.client_ip,
            "server_ip": self.server_ip
        })
        return base


@dataclass
class Timeline:
    """Event timeline"""
    events: List[MCPEvent] = field(default_factory=list)

    # Time range
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    # Analysis metadata
    sources: List[ArtifactSource] = field(default_factory=list)

    def add_event(self, event: MCPEvent):
        """Add event and maintain sorted order"""
        self.events.append(event)
        self.events.sort(key=lambda e: _normalize_timestamp(e.timestamp))

        # Update time range
        ts = _normalize_timestamp(event.timestamp)
        if not self.start_time or ts < _normalize_timestamp(self.start_time):
            self.start_time = event.timestamp
        if not self.end_time or ts > _normalize_timestamp(self.end_time):
            self.end_time = event.timestamp

        # Add source
        if event.source not in self.sources:
            self.sources.append(event.source)

    def filter_by_server(self, server_name: str) -> List[MCPEvent]:
        """Filter events by server"""
        return [e for e in self.events if e.server_name == server_name]

    def filter_by_type(self, event_type: EventType) -> List[MCPEvent]:
        """Filter events by type"""
        return [e for e in self.events if e.event_type == event_type]

    def filter_by_source(self, source: ArtifactSource) -> List[MCPEvent]:
        """Filter events by source"""
        return [e for e in self.events if e.source == source]

    def filter_by_severity(self, severity: EventSeverity) -> List[MCPEvent]:
        """Filter events by severity"""
        return [e for e in self.events if e.severity == severity]

    def get_security_events(self) -> List[MCPEvent]:
        """Get security-related events only"""
        return self.filter_by_severity(EventSeverity.SECURITY)

    def get_tool_calls(self) -> List[ToolCallEvent]:
        """Get tool call events only"""
        return [e for e in self.events if isinstance(e, ToolCallEvent)]

    def get_file_accesses(self) -> List[FileAccessEvent]:
        """Get file access events only"""
        return [e for e in self.events if isinstance(e, FileAccessEvent)]
    
    def deduplicate(self, time_tolerance_seconds: float = 1.0):
        """Remove duplicate events based on timestamp and content"""
        if not self.events:
            return 0

        removed_count = 0

        # Phase 1: Remove exact duplicates (same timestamp + content)
        seen_keys = set()
        phase1_events = []

        for event in self.events:
            ts = _normalize_timestamp(event.timestamp)
            ts_rounded = ts.replace(microsecond=0)  # Round to second

            # Get content identifier
            content_id = self._get_content_id(event)

            # Create dedup key
            dedup_key = (
                ts_rounded.isoformat() if ts != datetime.min else "unknown",
                event.event_type.value,
                event.server_name or "",
                content_id
            )

            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                phase1_events.append(event)

        removed_count += len(self.events) - len(phase1_events)

        # Phase 2: Remove content duplicates (same text, different timestamp)
        # This catches cases where identical content appears at different times
        seen_content = set()
        phase2_events = []

        for event in phase1_events:
            content_key = self._get_content_key_for_dedup(event)

            if content_key and content_key in seen_content:
                # Skip duplicate content
                continue

            if content_key:
                seen_content.add(content_key)
            phase2_events.append(event)

        removed_count += len(phase1_events) - len(phase2_events)

        # Update events list
        self.events = phase2_events

        return removed_count

    def _get_content_id(self, event: MCPEvent) -> str:
        """Get content identifier for deduplication"""
        if event.details:
            # Use bubble_id if available (most reliable)
            if event.details.get("bubble_id"):
                return event.details["bubble_id"]
            # Otherwise use full text hash
            elif event.details.get("text"):
                text = event.details["text"]
                return str(hash(text))
            # Or conversation_id + type combo
            elif event.details.get("conversation_id"):
                return f"{event.details['conversation_id']}_{event.event_type.value}"

        # If no content_id from details, try raw_data
        if event.raw_data:
            return str(hash(event.raw_data))

        return ""

    def _get_content_key_for_dedup(self, event: MCPEvent) -> Optional[str]:
        """Get content-only key for cross-timestamp deduplication"""
        # Only deduplicate events with actual text content
        if event.details and event.details.get("text"):
            text = event.details["text"].strip()
            if len(text) > 50:  # Only dedupe substantial content
                return f"{event.event_type.value}:{hash(text)}"
        return None

    def to_dict(self) -> Dict:
        return {
            "events": [e.to_dict() for e in self.events],
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "sources": [s.value for s in self.sources],
            "total_events": len(self.events)
        }
    
    def summary(self) -> Dict:
        """Timeline summary"""
        event_counts = {}
        for event in self.events:
            et = event.event_type.value
            event_counts[et] = event_counts.get(et, 0) + 1
        
        severity_counts = {}
        for event in self.events:
            sev = event.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        server_counts = {}
        for event in self.events:
            if event.server_name:
                server_counts[event.server_name] = server_counts.get(event.server_name, 0) + 1
        
        return {
            "total_events": len(self.events),
            "time_range": {
                "start": self.start_time.isoformat() if self.start_time else None,
                "end": self.end_time.isoformat() if self.end_time else None,
                "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else None
            },
            "events_by_type": event_counts,
            "events_by_severity": severity_counts,
            "events_by_server": server_counts,
            "sources": [s.value for s in self.sources]
        }


@dataclass
class CorrelatedEventGroup:
    """Event group linked by correlation"""
    correlation_id: str
    events: List[MCPEvent] = field(default_factory=list)

    # Group information
    server_name: Optional[str] = None
    tool_name: Optional[str] = None

    # Time information
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    
    def add_event(self, event: MCPEvent):
        self.events.append(event)
        self.events.sort(key=lambda e: _normalize_timestamp(e.timestamp))

        # Update time range
        if self.events:
            self.start_time = self.events[0].timestamp
            self.end_time = self.events[-1].timestamp
            start_norm = _normalize_timestamp(self.start_time)
            end_norm = _normalize_timestamp(self.end_time)
            self.duration_ms = (end_norm - start_norm).total_seconds() * 1000

        # Extract common information
        if not self.server_name and event.server_name:
            self.server_name = event.server_name
        if not self.tool_name and event.tool_name:
            self.tool_name = event.tool_name
    
    def to_dict(self) -> Dict:
        return {
            "correlation_id": self.correlation_id,
            "events": [e.to_dict() for e in self.events],
            "server_name": self.server_name,
            "tool_name": self.tool_name,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms
        }