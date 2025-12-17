"""
MCP Forensics - Comparative Analyzer
Forensic comparison analysis between Local vs Remote MCP servers

Reference:
- Artifact availability matrix
- Forensic capability matrix
- Differentiation analysis (research vs Cursor IDE)
"""

from typing import List, Dict, Optional, Any
from datetime import datetime
import logging

from ..models import (
    MCPEntities,
    MCPServer,
    Timeline,
    MCPEvent,
    ServerType,
    ArtifactSource,
    EventType,
    EventSeverity,
    AvailabilityLevel,
    ForensicValue,
    ServerArtifactProfile,
    ComparisonResult,
    STANDARD_ARTIFACTS,
    STANDARD_CAPABILITIES
)


class ComparativeAnalyzer:
    """
    Comparative Analyzer

    Compares and analyzes forensic availability and capabilities
    of Local STDIO, Custom Remote, and Official Remote servers.
    """

    def __init__(self):
        self.logger = logging.getLogger("analysis.comparative")

        # Default artifact availability by server type (research-based)
        self.default_availability = {
            ServerType.LOCAL: {
                "mcp_config": AvailabilityLevel.FULL,
                "cursor_main_log": AvailabilityLevel.FULL,
                "cursor_ext_log": AvailabilityLevel.FULL,
                "server_request_log": AvailabilityLevel.NONE,
                "server_response_log": AvailabilityLevel.NONE,
                "file_access_log": AvailabilityLevel.NONE,
                "network_capture": AvailabilityLevel.NONE,
                "session_id": AvailabilityLevel.NONE,
                "json_rpc_trace": AvailabilityLevel.PARTIAL,
                "tool_definitions": AvailabilityLevel.FULL,
                "error_log": AvailabilityLevel.PARTIAL
            },
            ServerType.CUSTOM_REMOTE: {
                "mcp_config": AvailabilityLevel.FULL,
                "cursor_main_log": AvailabilityLevel.FULL,
                "cursor_ext_log": AvailabilityLevel.FULL,
                "server_request_log": AvailabilityLevel.FULL,
                "server_response_log": AvailabilityLevel.FULL,
                "file_access_log": AvailabilityLevel.FULL,
                "network_capture": AvailabilityLevel.FULL,
                "session_id": AvailabilityLevel.FULL,
                "json_rpc_trace": AvailabilityLevel.FULL,
                "tool_definitions": AvailabilityLevel.FULL,
                "error_log": AvailabilityLevel.FULL
            },
            ServerType.OFFICIAL_REMOTE: {
                "mcp_config": AvailabilityLevel.FULL,
                "cursor_main_log": AvailabilityLevel.FULL,
                "cursor_ext_log": AvailabilityLevel.FULL,
                "server_request_log": AvailabilityLevel.NONE,
                "server_response_log": AvailabilityLevel.NONE,
                "file_access_log": AvailabilityLevel.NONE,
                "network_capture": AvailabilityLevel.PARTIAL,  # Encrypted
                "session_id": AvailabilityLevel.PARTIAL,
                "json_rpc_trace": AvailabilityLevel.PARTIAL,
                "tool_definitions": AvailabilityLevel.FULL,
                "error_log": AvailabilityLevel.PARTIAL
            }
        }

        # Default forensic capabilities by server type (research-based)
        self.default_capabilities = {
            ServerType.LOCAL: {
                "timeline_reconstruction": ForensicValue.MEDIUM,
                "action_attribution": ForensicValue.LOW,
                "data_exfiltration_tracking": ForensicValue.LOW,
                "tool_usage_analysis": ForensicValue.MEDIUM,
                "session_correlation": ForensicValue.LOW,
                "error_analysis": ForensicValue.LOW,
                "security_event_detection": ForensicValue.LOW
            },
            ServerType.CUSTOM_REMOTE: {
                "timeline_reconstruction": ForensicValue.HIGH,
                "action_attribution": ForensicValue.HIGH,
                "data_exfiltration_tracking": ForensicValue.HIGH,
                "tool_usage_analysis": ForensicValue.HIGH,
                "session_correlation": ForensicValue.HIGH,
                "error_analysis": ForensicValue.HIGH,
                "security_event_detection": ForensicValue.HIGH
            },
            ServerType.OFFICIAL_REMOTE: {
                "timeline_reconstruction": ForensicValue.MEDIUM,
                "action_attribution": ForensicValue.MEDIUM,
                "data_exfiltration_tracking": ForensicValue.LOW,
                "tool_usage_analysis": ForensicValue.MEDIUM,
                "session_correlation": ForensicValue.MEDIUM,
                "error_analysis": ForensicValue.LOW,
                "security_event_detection": ForensicValue.LOW
            }
        }

    def analyze(self, entities: MCPEntities, timeline: Timeline) -> ComparisonResult:
        """
        Perform comparison analysis based on entities and timeline

        Args:
            entities: Analyzed MCP entities
            timeline: Event timeline

        Returns:
            Comparison analysis result
        """
        result = ComparisonResult()
        result.analysis_timestamp = datetime.now()

        # Create profile for each server
        for server in entities.servers:
            profile = self._create_server_profile(server, timeline)
            result.add_profile(profile)

        # Create default profiles if no servers exist
        if not entities.servers:
            for server_type in ServerType:
                profile = self._create_default_profile(server_type)
                result.add_profile(profile)

        # Generate analysis findings
        result.generate_findings()

        # Additional analysis
        self._add_cursor_specific_findings(result, entities, timeline)

        return result

    def _create_server_profile(self, server: MCPServer,
                               timeline: Timeline) -> ServerArtifactProfile:
        """Create artifact profile for each server"""
        profile = ServerArtifactProfile(
            server_name=server.name,
            server_type=server.server_type
        )

        # Set default artifact availability
        default_avail = self.default_availability.get(server.server_type, {})
        for artifact_name, availability in default_avail.items():
            profile.set_artifact(artifact_name, availability)

        # Update based on actual data
        self._update_profile_from_server(profile, server)
        self._update_profile_from_timeline(profile, timeline, server.name)

        # Set default forensic capabilities
        default_caps = self.default_capabilities.get(server.server_type, {})
        for cap_name, value in default_caps.items():
            profile.set_capability(cap_name, value)

        # Adjust capabilities based on actual data
        self._adjust_capabilities(profile, timeline, server.name)

        return profile

    def _create_default_profile(self, server_type: ServerType) -> ServerArtifactProfile:
        """Create default profile (when no server exists)"""
        profile = ServerArtifactProfile(
            server_name=f"default_{server_type.value}",
            server_type=server_type
        )

        # Default artifact availability
        default_avail = self.default_availability.get(server_type, {})
        for artifact_name, availability in default_avail.items():
            profile.set_artifact(artifact_name, availability)

        # Default forensic capabilities
        default_caps = self.default_capabilities.get(server_type, {})
        for cap_name, value in default_caps.items():
            profile.set_capability(cap_name, value)

        return profile

    def _update_profile_from_server(self, profile: ServerArtifactProfile,
                                     server: MCPServer):
        """Update profile with server information"""
        # Check tool definitions
        if server.tools:
            profile.artifacts["tool_definitions"].sample_count = len(server.tools)
            profile.artifacts["tool_definitions"].availability = AvailabilityLevel.FULL

        # Adjust availability by source
        for source in server.sources:
            if source == ArtifactSource.SERVER_LOG:
                profile.artifacts["server_request_log"].availability = AvailabilityLevel.FULL
                profile.artifacts["server_response_log"].availability = AvailabilityLevel.FULL

            if source == ArtifactSource.NETWORK_CAPTURE:
                profile.artifacts["network_capture"].availability = AvailabilityLevel.FULL

        # Update statistics
        profile.tool_calls = server.total_tool_calls
        profile.errors = server.total_errors

    def _update_profile_from_timeline(self, profile: ServerArtifactProfile,
                                       timeline: Timeline, server_name: str):
        """Update profile with timeline data"""
        server_events = timeline.filter_by_server(server_name)
        profile.total_events = len(server_events)

        # Count by event type
        tool_calls = [e for e in server_events if e.event_type == EventType.TOOL_CALL]
        errors = [e for e in server_events if e.event_type == EventType.TOOL_ERROR]
        security = [e for e in server_events if e.severity == EventSeverity.SECURITY]

        profile.tool_calls = max(profile.tool_calls, len(tool_calls))
        profile.errors = max(profile.errors, len(errors))
        profile.security_events = len(security)

        # Update sample count by source
        for source in timeline.sources:
            source_events = [e for e in server_events if e.source == source]
            if source == ArtifactSource.CURSOR_LOG:
                profile.artifacts["cursor_main_log"].sample_count = len(source_events)
            elif source == ArtifactSource.SERVER_LOG:
                profile.artifacts["server_request_log"].sample_count = len(source_events)
            elif source == ArtifactSource.NETWORK_CAPTURE:
                profile.artifacts["network_capture"].sample_count = len(source_events)

    def _adjust_capabilities(self, profile: ServerArtifactProfile,
                             timeline: Timeline, server_name: str):
        """Adjust forensic capabilities based on actual data"""
        # Timeline reconstruction capability
        if profile.total_events > 10:
            current = profile.capabilities.get("timeline_reconstruction", ForensicValue.LOW)
            if current == ForensicValue.LOW:
                profile.capabilities["timeline_reconstruction"] = ForensicValue.MEDIUM
            elif current == ForensicValue.MEDIUM:
                profile.capabilities["timeline_reconstruction"] = ForensicValue.HIGH

        # Security event detection capability
        if profile.security_events > 0:
            profile.capabilities["security_event_detection"] = ForensicValue.HIGH

        # Error analysis capability
        if profile.errors > 0:
            current = profile.capabilities.get("error_analysis", ForensicValue.LOW)
            if current == ForensicValue.LOW:
                profile.capabilities["error_analysis"] = ForensicValue.MEDIUM

    def _add_cursor_specific_findings(self, result: ComparisonResult,
                                       entities: MCPEntities,
                                       timeline: Timeline):
        """Add Cursor IDE specific analysis findings"""
        # Cursor client information
        if entities.client:
            result.findings.append(
                f"Cursor IDE client detected (version: {entities.client.version or 'unknown'})"
            )

        # Local vs Remote comparison
        local_servers = [p for p in result.profiles if p.server_type == ServerType.LOCAL]
        remote_servers = [p for p in result.profiles
                         if p.server_type in (ServerType.CUSTOM_REMOTE, ServerType.OFFICIAL_REMOTE)]

        if local_servers and remote_servers:
            local_events = sum(p.total_events for p in local_servers)
            remote_events = sum(p.total_events for p in remote_servers)

            if remote_events > local_events:
                result.findings.append(
                    f"Remote servers have more events ({remote_events}) than local ({local_events})"
                )

        # Custom Remote server recommendation
        custom_remote = [p for p in result.profiles
                        if p.server_type == ServerType.CUSTOM_REMOTE]
        if not custom_remote:
            result.recommendations.append(
                "Consider using a custom remote MCP server for comprehensive forensic logging"
            )

        # Orphaned tool warning
        if entities.orphaned_tools:
            result.findings.append(
                f"Found {len(entities.orphaned_tools)} orphaned tools not linked to any server"
            )

    def compare_platforms(self, cursor_result: ComparisonResult,
                         claude_result: ComparisonResult = None) -> Dict[str, Any]:
        """
        Compare Cursor IDE and Claude Desktop platforms

        Args:
            cursor_result: Cursor IDE analysis result
            claude_result: Claude Desktop analysis result (optional)

        Returns:
            Platform comparison result
        """
        comparison = {
            "cursor": {
                "platform": "Cursor IDE",
                "summary": cursor_result.summary(),
                "artifact_matrix": cursor_result.artifact_matrix,
                "capability_matrix": cursor_result.capability_matrix
            }
        }

        if claude_result:
            comparison["claude"] = {
                "platform": "Claude Desktop",
                "summary": claude_result.summary(),
                "artifact_matrix": claude_result.artifact_matrix,
                "capability_matrix": claude_result.capability_matrix
            }

            # Difference analysis
            differences = []

            # Artifact differences
            cursor_artifacts = set(cursor_result.artifact_matrix.keys())
            claude_artifacts = set(claude_result.artifact_matrix.keys())

            only_cursor = cursor_artifacts - claude_artifacts
            only_claude = claude_artifacts - cursor_artifacts

            if only_cursor:
                differences.append(f"Cursor-only artifacts: {', '.join(only_cursor)}")
            if only_claude:
                differences.append(f"Claude-only artifacts: {', '.join(only_claude)}")

            comparison["differences"] = differences

        return comparison

    def generate_report(self, result: ComparisonResult) -> Dict[str, Any]:
        """Generate analysis report"""
        return {
            "title": "MCP Forensics Comparative Analysis Report",
            "generated_at": datetime.now().isoformat(),
            "platform": "Cursor IDE",
            "summary": result.summary(),
            "profiles": [p.to_dict() for p in result.profiles],
            "artifact_availability_matrix": result.artifact_matrix,
            "forensic_capability_matrix": result.capability_matrix,
            "key_findings": result.findings,
            "recommendations": result.recommendations,
            "methodology": {
                "framework": "MCP Forensics Analyzer",
                "description": "Cursor IDE specific analysis",
                "artifacts_analyzed": list(result.artifact_matrix.keys()),
                "capabilities_evaluated": list(result.capability_matrix.keys())
            }
        }

    def get_artifact_descriptions(self) -> Dict[str, str]:
        """Return artifact descriptions"""
        return {
            "mcp_config": "MCP server configuration (mcp.json)",
            "cursor_main_log": "Cursor IDE main process logs",
            "cursor_ext_log": "Cursor IDE extension host logs",
            "server_request_log": "MCP server request logs (JSON-RPC)",
            "server_response_log": "MCP server response logs (JSON-RPC)",
            "file_access_log": "File access tracking logs",
            "network_capture": "Network traffic captures (pcap/HAR)",
            "session_id": "MCP session identifiers",
            "json_rpc_trace": "Complete JSON-RPC message traces",
            "tool_definitions": "MCP tool definitions and schemas",
            "error_log": "Error and exception logs"
        }

    def get_capability_descriptions(self) -> Dict[str, str]:
        """Return forensic capability descriptions"""
        return {
            "timeline_reconstruction": "Ability to reconstruct event timelines",
            "action_attribution": "Ability to attribute actions to users/LLMs",
            "data_exfiltration_tracking": "Ability to track data exfiltration",
            "tool_usage_analysis": "Ability to analyze tool usage patterns",
            "session_correlation": "Ability to correlate events across sessions",
            "error_analysis": "Ability to analyze errors and exceptions",
            "security_event_detection": "Ability to detect security-related events"
        }
