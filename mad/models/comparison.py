"""
MCP Forensics - Comparison Models
Local vs Remote comparison analysis models
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

from .entities import ServerType, ArtifactSource


class AvailabilityLevel(Enum):
    """Artifact availability level"""
    FULL = "full"           # Fully available
    PARTIAL = "partial"     # Partially available
    NONE = "none"           # Not available
    UNKNOWN = "unknown"     # Verification required


class ForensicValue(Enum):
    """Forensic value assessment"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class ArtifactAvailability:
    """Availability of a specific artifact"""
    artifact_name: str
    availability: AvailabilityLevel
    description: Optional[str] = None

    # Details
    sample_count: int = 0
    quality_notes: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "artifact_name": self.artifact_name,
            "availability": self.availability.value,
            "description": self.description,
            "sample_count": self.sample_count,
            "quality_notes": self.quality_notes
        }


@dataclass
class ServerArtifactProfile:
    """Server artifact profile"""
    server_name: str
    server_type: ServerType

    # Artifact availability
    artifacts: Dict[str, ArtifactAvailability] = field(default_factory=dict)

    # Forensic capabilities
    capabilities: Dict[str, ForensicValue] = field(default_factory=dict)

    # Statistics
    total_events: int = 0
    tool_calls: int = 0
    errors: int = 0
    security_events: int = 0

    def set_artifact(self, name: str, availability: AvailabilityLevel,
                    description: str = None, sample_count: int = 0):
        """Set artifact availability"""
        self.artifacts[name] = ArtifactAvailability(
            artifact_name=name,
            availability=availability,
            description=description,
            sample_count=sample_count
        )

    def set_capability(self, name: str, value: ForensicValue):
        """Set forensic capability"""
        self.capabilities[name] = value
    
    def to_dict(self) -> Dict:
        return {
            "server_name": self.server_name,
            "server_type": self.server_type.value,
            "artifacts": {k: v.to_dict() for k, v in self.artifacts.items()},
            "capabilities": {k: v.value for k, v in self.capabilities.items()},
            "statistics": {
                "total_events": self.total_events,
                "tool_calls": self.tool_calls,
                "errors": self.errors,
                "security_events": self.security_events
            }
        }


@dataclass
class ComparisonResult:
    """Comparison analysis result"""

    # Comparison targets
    profiles: List[ServerArtifactProfile] = field(default_factory=list)

    # Analysis time
    analysis_timestamp: Optional[datetime] = None

    # Artifact comparison matrix
    artifact_matrix: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # e.g., {"request_log": {"local": "partial", "custom_remote": "full", "official_remote": "none"}}

    # Forensic capability comparison matrix
    capability_matrix: Dict[str, Dict[str, str]] = field(default_factory=dict)

    # Summary conclusions
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def add_profile(self, profile: ServerArtifactProfile):
        """Add profile"""
        self.profiles.append(profile)
        self._update_matrices()

    def _update_matrices(self):
        """Update matrices"""
        # Artifact matrix
        all_artifacts = set()
        for profile in self.profiles:
            all_artifacts.update(profile.artifacts.keys())

        for artifact_name in all_artifacts:
            self.artifact_matrix[artifact_name] = {}
            for profile in self.profiles:
                if artifact_name in profile.artifacts:
                    self.artifact_matrix[artifact_name][profile.server_name] = \
                        profile.artifacts[artifact_name].availability.value
                else:
                    self.artifact_matrix[artifact_name][profile.server_name] = "unknown"

        # Forensic capability matrix
        all_capabilities = set()
        for profile in self.profiles:
            all_capabilities.update(profile.capabilities.keys())

        for cap_name in all_capabilities:
            self.capability_matrix[cap_name] = {}
            for profile in self.profiles:
                if cap_name in profile.capabilities:
                    self.capability_matrix[cap_name][profile.server_name] = \
                        profile.capabilities[cap_name].value
                else:
                    self.capability_matrix[cap_name][profile.server_name] = "unknown"

    def generate_findings(self):
        """Automatically generate analysis findings"""
        self.findings = []
        self.recommendations = []

        # Artifact availability analysis
        for artifact_name, availability in self.artifact_matrix.items():
            full_count = sum(1 for v in availability.values() if v == "full")
            partial_count = sum(1 for v in availability.values() if v == "partial")
            none_count = sum(1 for v in availability.values() if v == "none")

            if full_count > 0 and none_count > 0:
                full_servers = [k for k, v in availability.items() if v == "full"]
                none_servers = [k for k, v in availability.items() if v == "none"]
                self.findings.append(
                    f"'{artifact_name}' is fully available in {', '.join(full_servers)} "
                    f"but unavailable in {', '.join(none_servers)}"
                )

        # Forensic capability analysis
        for cap_name, values in self.capability_matrix.items():
            high_count = sum(1 for v in values.values() if v == "high")
            if high_count == 0:
                self.recommendations.append(
                    f"Consider using custom logging for better '{cap_name}' capability"
                )

        # Custom Remote server recommendations
        custom_profiles = [p for p in self.profiles if p.server_type == ServerType.CUSTOM_REMOTE]
        if custom_profiles:
            for profile in custom_profiles:
                full_artifacts = sum(1 for a in profile.artifacts.values()
                                   if a.availability == AvailabilityLevel.FULL)
                total_artifacts = len(profile.artifacts)
                if full_artifacts == total_artifacts and total_artifacts > 0:
                    self.findings.append(
                        f"Custom server '{profile.server_name}' provides complete artifact coverage"
                    )
    
    def to_dict(self) -> Dict:
        return {
            "profiles": [p.to_dict() for p in self.profiles],
            "analysis_timestamp": self.analysis_timestamp.isoformat() if self.analysis_timestamp else None,
            "artifact_matrix": self.artifact_matrix,
            "capability_matrix": self.capability_matrix,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": self.summary()
        }
    
    def summary(self) -> Dict:
        """Comparison summary"""
        return {
            "total_servers_analyzed": len(self.profiles),
            "servers_by_type": {
                "local": len([p for p in self.profiles if p.server_type == ServerType.LOCAL]),
                "custom_remote": len([p for p in self.profiles if p.server_type == ServerType.CUSTOM_REMOTE]),
                "official_remote": len([p for p in self.profiles if p.server_type == ServerType.OFFICIAL_REMOTE])
            },
            "total_artifacts_tracked": len(self.artifact_matrix),
            "total_capabilities_tracked": len(self.capability_matrix),
            "findings_count": len(self.findings),
            "recommendations_count": len(self.recommendations)
        }


# Predefined artifact list
STANDARD_ARTIFACTS = [
    "mcp_config",           # mcp.json configuration
    "cursor_main_log",      # Cursor main log
    "cursor_ext_log",       # Cursor extension host log
    "server_request_log",   # Server-side request log
    "server_response_log",  # Server-side response log
    "file_access_log",      # File access log
    "network_capture",      # Network capture
    "session_id",           # Session ID
    "json_rpc_trace",       # JSON-RPC message trace
    "tool_definitions",     # Tool definitions
    "error_log"             # Error log
]

# Predefined forensic capability list
STANDARD_CAPABILITIES = [
    "timeline_reconstruction",      # Timeline reconstruction
    "action_attribution",           # Action attribution
    "data_exfiltration_tracking",   # Data exfiltration tracking
    "tool_usage_analysis",          # Tool usage analysis
    "session_correlation",          # Session correlation
    "error_analysis",               # Error analysis
    "security_event_detection"      # Security event detection
]