"""
MCP Forensics - Correlation Engine
Event and entity correlation analysis

Reference Section 3.2:
- Request ID matching
- Session ID matching
- Server name matching
- Time proximity matching
"""

from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass, field
import uuid


def _normalize_event_timestamp(event):
    """Normalize event timestamp for comparison (handle timezone-aware/naive mix)"""
    ts = event.timestamp
    if ts is None:
        return datetime.min
    if hasattr(ts, 'tzinfo') and ts.tzinfo is not None:
        return ts.replace(tzinfo=None)
    return ts


from ..models import (
    MCPEntities,
    MCPServer,
    MCPTool,
    OrphanedTool,
    Timeline,
    MCPEvent,
    ToolCallEvent,
    ToolResultEvent,
    CorrelatedEventGroup,
    EventType,
    ArtifactSource
)


@dataclass
class CorrelationConfig:
    """Correlation analysis configuration"""
    # Time proximity threshold (milliseconds)
    time_proximity_threshold_ms: int = 5000  # 5 seconds

    # Server name fuzzy matching
    fuzzy_server_matching: bool = True

    # Request ID based matching
    use_request_id: bool = True

    # Session ID based matching
    use_session_id: bool = True

    # Tool name based matching
    use_tool_name: bool = True


class CorrelationEngine:
    """
    Correlation Engine

    Connects events and entities extracted from multiple artifact sources.
    """

    def __init__(self, config: CorrelationConfig = None):
        self.config = config or CorrelationConfig()
        self.logger = logging.getLogger("correlation.engine")

        # Correlation statistics
        self.stats = {
            "request_id_matches": 0,
            "session_id_matches": 0,
            "server_name_matches": 0,
            "time_proximity_matches": 0,
            "tool_name_matches": 0,
            "total_groups_created": 0
        }

    def correlate_entities(self, *entities_list: MCPEntities) -> MCPEntities:
        """
        Merge and correlate entities from multiple sources

        Args:
            entities_list: List of MCPEntities to merge

        Returns:
            Merged MCPEntities
        """
        merged = MCPEntities()
        merged.analysis_timestamp = datetime.now()

        # Merge servers
        servers_by_name: Dict[str, MCPServer] = {}

        for entities in entities_list:
            merged.artifact_sources.extend(entities.artifact_sources)

            for server in entities.servers:
                if server.name in servers_by_name:
                    # Merge info into existing server
                    existing = servers_by_name[server.name]
                    self._merge_server_info(existing, server)
                    self.stats["server_name_matches"] += 1
                else:
                    servers_by_name[server.name] = server

            # Merge client info
            if entities.client:
                if merged.client:
                    # Merge client info
                    if entities.client.version and not merged.client.version:
                        merged.client.version = entities.client.version
                    merged.client.connected_servers.extend(
                        s for s in entities.client.connected_servers
                        if s not in merged.client.connected_servers
                    )
                else:
                    merged.client = entities.client

            # Collect orphaned tools
            merged.orphaned_tools.extend(entities.orphaned_tools)

        merged.servers = list(servers_by_name.values())

        # Attempt to connect orphaned tools to servers
        self._resolve_orphaned_tools(merged)

        return merged

    def correlate_timelines(self, *timelines: Timeline) -> Timeline:
        """
        Merge multiple timelines and correlate events

        Args:
            timelines: List of Timelines to merge

        Returns:
            Merged Timeline
        """
        merged = Timeline()

        # Collect all events
        all_events: List[MCPEvent] = []
        for timeline in timelines:
            all_events.extend(timeline.events)
            merged.sources.extend(
                s for s in timeline.sources if s not in merged.sources
            )

        # Sort by time (handle timezone-aware/naive mix)
        all_events.sort(key=_normalize_event_timestamp)

        # Create correlation groups
        groups = self._create_correlation_groups(all_events)

        # Assign correlation_id to events in groups
        for group in groups:
            for event in group.events:
                event.correlation_id = group.correlation_id

        # Add to merged timeline
        for event in all_events:
            merged.add_event(event)

        self.stats["total_groups_created"] = len(groups)

        return merged

    def _merge_server_info(self, existing: MCPServer, new: MCPServer):
        """Merge server information"""
        # Merge tools
        existing_tool_names = {t.name for t in existing.tools}
        for tool in new.tools:
            if tool.name not in existing_tool_names:
                existing.tools.append(tool)
            else:
                # Update existing tool info
                for existing_tool in existing.tools:
                    if existing_tool.name == tool.name:
                        if tool.description and not existing_tool.description:
                            existing_tool.description = tool.description
                        if tool.input_schema and not existing_tool.input_schema:
                            existing_tool.input_schema = tool.input_schema
                        existing_tool.call_count += tool.call_count
                        break

        # Merge resources
        existing_resource_names = {r.name for r in existing.resources}
        for resource in new.resources:
            if resource.name not in existing_resource_names:
                existing.resources.append(resource)

        # Update URL info
        if new.url and not existing.url:
            existing.url = new.url

        # Update command info
        if new.command and not existing.command:
            existing.command = new.command

        # Update tool_count (count extracted from logs when actual tool list is unavailable)
        if new.tool_count > 0 and existing.tool_count == 0:
            existing.tool_count = new.tool_count

        # Update timestamps
        if new.first_seen:
            if not existing.first_seen or new.first_seen < existing.first_seen:
                existing.first_seen = new.first_seen
        if new.last_seen:
            if not existing.last_seen or new.last_seen > existing.last_seen:
                existing.last_seen = new.last_seen

        # Merge statistics
        existing.total_requests += new.total_requests
        existing.total_tool_calls += new.total_tool_calls
        existing.total_errors += new.total_errors

        # Merge sources
        for source in new.sources:
            if source not in existing.sources:
                existing.sources.append(source)

    def _resolve_orphaned_tools(self, entities: MCPEntities):
        """Attempt to connect orphaned tools to servers"""
        resolved_tools = []

        for orphan in entities.orphaned_tools:
            matched_server = None

            # Try probable_server first if available
            if orphan.probable_server:
                matched_server = entities.get_server_by_name(orphan.probable_server)

            # Tool name based matching
            if not matched_server and self.config.use_tool_name:
                for server in entities.servers:
                    # Check if tool name is related to server capabilities
                    if self._tool_matches_server(orphan.name, server):
                        matched_server = server
                        self.stats["tool_name_matches"] += 1
                        break

            if matched_server:
                # Add tool to server
                if not any(t.name == orphan.name for t in matched_server.tools):
                    matched_server.tools.append(MCPTool(
                        name=orphan.name,
                        server_name=matched_server.name,
                        first_seen=orphan.first_seen,
                        last_seen=orphan.last_seen,
                        call_count=orphan.call_count
                    ))
                resolved_tools.append(orphan)

        # Remove resolved tools
        for resolved in resolved_tools:
            entities.orphaned_tools.remove(resolved)

    def _tool_matches_server(self, tool_name: str, server: MCPServer) -> bool:
        """Check if tool matches a server"""
        tool_lower = tool_name.lower()
        server_lower = server.name.lower()

        # Server name is contained in tool name
        if server_lower in tool_lower:
            return True

        # Common pattern matching
        patterns = {
            "filesystem": ["read_file", "write_file", "list", "directory", "file"],
            "git": ["commit", "push", "pull", "branch", "clone"],
            "github": ["issue", "pr", "pull_request", "repo"],
            "notion": ["page", "database", "block"],
            "browser": ["navigate", "click", "screenshot", "playwright"]
        }

        for server_pattern, tool_patterns in patterns.items():
            if server_pattern in server_lower:
                if any(tp in tool_lower for tp in tool_patterns):
                    return True

        return False

    def _create_correlation_groups(self, events: List[MCPEvent]) -> List[CorrelatedEventGroup]:
        """Create event correlation groups"""
        groups: List[CorrelatedEventGroup] = []
        grouped_events: set = set()

        for i, event in enumerate(events):
            if id(event) in grouped_events:
                continue

            # Start new group
            group = CorrelatedEventGroup(
                correlation_id=str(uuid.uuid4())[:8]
            )
            group.add_event(event)
            grouped_events.add(id(event))

            # Find related events
            for j, other in enumerate(events):
                if i == j or id(other) in grouped_events:
                    continue

                if self._events_correlate(event, other):
                    group.add_event(other)
                    grouped_events.add(id(other))

            # Only store groups with 2 or more events
            if len(group.events) > 1:
                groups.append(group)

        return groups

    def _events_correlate(self, event1: MCPEvent, event2: MCPEvent) -> bool:
        """Check if two events are correlated"""
        # Request ID matching
        if self.config.use_request_id:
            if event1.request_id and event1.request_id == event2.request_id:
                self.stats["request_id_matches"] += 1
                return True

        # Session ID matching
        if self.config.use_session_id:
            if event1.session_id and event1.session_id == event2.session_id:
                # Also check time proximity within the same session
                if self._time_proximity(event1, event2):
                    self.stats["session_id_matches"] += 1
                    return True

        # Request-response matching for same server, same tool
        if event1.server_name and event1.server_name == event2.server_name:
            if event1.tool_name and event1.tool_name == event2.tool_name:
                # Match TOOL_CALL with TOOL_RESULT
                if self._is_request_response_pair(event1, event2):
                    if self._time_proximity(event1, event2):
                        self.stats["time_proximity_matches"] += 1
                        return True

        return False

    def _time_proximity(self, event1: MCPEvent, event2: MCPEvent) -> bool:
        """Check time proximity"""
        ts1 = event1.timestamp.replace(tzinfo=None) if event1.timestamp and hasattr(event1.timestamp, 'tzinfo') and event1.timestamp.tzinfo else event1.timestamp
        ts2 = event2.timestamp.replace(tzinfo=None) if event2.timestamp and hasattr(event2.timestamp, 'tzinfo') and event2.timestamp.tzinfo else event2.timestamp
        if not ts1 or not ts2:
            return False
        delta = abs((ts1 - ts2).total_seconds() * 1000)
        return delta <= self.config.time_proximity_threshold_ms

    def _is_request_response_pair(self, event1: MCPEvent, event2: MCPEvent) -> bool:
        """Check if two events form a request-response pair"""
        request_types = {EventType.TOOL_CALL, EventType.RESOURCE_READ, EventType.CONNECTION_INIT}
        response_types = {EventType.TOOL_RESULT, EventType.TOOL_ERROR, EventType.CONNECTION_READY}

        e1_is_request = event1.event_type in request_types
        e2_is_request = event2.event_type in request_types
        e1_is_response = event1.event_type in response_types
        e2_is_response = event2.event_type in response_types

        return (e1_is_request and e2_is_response) or (e1_is_response and e2_is_request)

    def get_correlation_stats(self) -> Dict:
        """Return correlation statistics"""
        return self.stats.copy()

    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            "request_id_matches": 0,
            "session_id_matches": 0,
            "server_name_matches": 0,
            "time_proximity_matches": 0,
            "tool_name_matches": 0,
            "total_groups_created": 0
        }

    def find_related_events(self, target_event: MCPEvent,
                           timeline: Timeline) -> List[MCPEvent]:
        """Find all events related to a specific event"""
        related = []

        for event in timeline.events:
            if event is target_event:
                continue
            if self._events_correlate(target_event, event):
                related.append(event)

        return related

    def build_event_chains(self, timeline: Timeline) -> List[List[MCPEvent]]:
        """Build event chains (request -> response sequences)"""
        chains: List[List[MCPEvent]] = []

        # Request ID based chains
        request_id_map: Dict[str, List[MCPEvent]] = {}

        for event in timeline.events:
            if event.request_id:
                if event.request_id not in request_id_map:
                    request_id_map[event.request_id] = []
                request_id_map[event.request_id].append(event)

        for request_id, events in request_id_map.items():
            if len(events) > 1:
                events.sort(key=_normalize_event_timestamp)
                chains.append(events)

        return chains

    def normalize_server_names(self, entities: MCPEntities, timeline: Timeline) -> int:
        """
        Normalize estimated/derived server names to match confirmed servers

        Maps inferred names (e.g., "notion", "filesystem") and URL-derived names
        (e.g., "mcp-notion") to actual configured server names (e.g., "user-Notion").

        Args:
            entities: Merged entities with confirmed server names
            timeline: Timeline with events to normalize

        Returns:
            Number of server names normalized
        """
        if not entities.servers:
            return 0

        # Build mapping from canonical patterns to confirmed server names
        # e.g., "notion" -> "user-Notion", "filesystem" -> "user-filesystem"
        canonical_to_confirmed: Dict[str, str] = {}

        for server in entities.servers:
            server_lower = server.name.lower()
            # Extract canonical part (e.g., "user-Notion" -> "notion")
            for pattern in ['notion', 'filesystem', 'github', 'git', 'browser',
                           'slack', 'database', 'search', 'memory', 'fetch',
                           'docker', 'kubernetes', 'aws', 'obsidian']:
                if pattern in server_lower:
                    canonical_to_confirmed[pattern] = server.name
                    # Also add variations
                    canonical_to_confirmed[f"mcp-{pattern}"] = server.name
                    canonical_to_confirmed[f"{pattern}-official"] = server.name
                    break

        if not canonical_to_confirmed:
            return 0

        normalized_count = 0

        for event in timeline.events:
            original_name = event.server_name
            if not original_name:
                continue

            # Skip already confirmed servers
            if original_name in [s.name for s in entities.servers]:
                continue

            # Try to match to confirmed server
            name_lower = original_name.lower()

            # Remove "(estimated)" suffix for matching
            name_for_match = name_lower.replace(' (estimated)', '').replace('(estimated)', '')

            matched_server = None
            for canonical, confirmed in canonical_to_confirmed.items():
                if canonical in name_for_match or name_for_match in canonical:
                    matched_server = confirmed
                    break

            if matched_server:
                event.server_name = matched_server
                # Update details.mcp_servers_used if present
                if hasattr(event, 'details') and event.details:
                    if 'mcp_servers_used' in event.details:
                        event.details['mcp_servers_used'] = [
                            matched_server if (s.lower().replace(' (estimated)', '') in canonical_to_confirmed
                                              or any(c in s.lower() for c in canonical_to_confirmed))
                            else s
                            for s in event.details['mcp_servers_used']
                        ]
                    # Keep original for reference
                    event.details['original_server_name'] = original_name
                normalized_count += 1

        self.logger.info(f"Normalized {normalized_count} server names in timeline")
        return normalized_count
