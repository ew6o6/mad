"""
MCP Forensics - Base Transformer
Base class for all Transformers
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
import logging

from ..models import (
    MCPEntities,
    MCPServer,
    MCPEvent,
    Timeline,
    ArtifactSource
)


class BaseTransformer(ABC):
    """
    Transformer base class

    Each Transformer processes a specific artifact source (Cursor logs, server logs, network captures, etc.)
    to extract MCP entities and events.
    """

    def __init__(self, name: str = "base"):
        self.name = name
        self.logger = logging.getLogger(f"transformer.{name}")
        self.source: ArtifactSource = ArtifactSource.CONFIG_FILE

        # Processing statistics
        self.stats = {
            "files_processed": 0,
            "entities_extracted": 0,
            "events_extracted": 0,
            "errors": 0
        }
    
    @abstractmethod
    def can_process(self, artifact_path: Union[str, Path]) -> bool:
        """
        Check if this Transformer can process the given artifact

        Args:
            artifact_path: Artifact file/directory path

        Returns:
            Whether the artifact can be processed
        """
        pass

    @abstractmethod
    def extract_entities(self, artifact_path: Union[str, Path]) -> MCPEntities:
        """
        Extract MCP entities from artifact

        Args:
            artifact_path: Artifact file/directory path

        Returns:
            Extracted MCP entities
        """
        pass

    @abstractmethod
    def extract_events(self, artifact_path: Union[str, Path]) -> Timeline:
        """
        Extract events from artifact

        Args:
            artifact_path: Artifact file/directory path

        Returns:
            Extracted event timeline
        """
        pass

    def process(self, artifact_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Process entire artifact

        Args:
            artifact_path: Artifact file/directory path

        Returns:
            Processing result (entities, timeline, stats)
        """
        path = Path(artifact_path)

        if not self.can_process(path):
            self.logger.warning(f"Cannot process artifact: {path}")
            return {
                "success": False,
                "error": f"Transformer '{self.name}' cannot process this artifact",
                "entities": MCPEntities().to_dict(),
                "timeline": Timeline().to_dict(),
                "stats": self.stats
            }

        try:
            self.logger.info(f"Processing artifact: {path}")

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
                "stats": self.stats
            }
            
        except Exception as e:
            self.logger.exception(f"Error processing artifact: {path}")
            self.stats["errors"] += 1
            return {
                "success": False,
                "error": str(e),
                "entities": MCPEntities().to_dict(),
                "timeline": Timeline().to_dict(),
                "stats": self.stats
            }
    
    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            "files_processed": 0,
            "entities_extracted": 0,
            "events_extracted": 0,
            "errors": 0
        }

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """
        Parse timestamps in various formats

        Supported formats:
        - ISO 8601: 2024-12-14T10:30:00Z
        - ISO 8601 with microseconds: 2024-12-14T10:30:00.123456Z
        - ISO 8601 with timezone: 2024-12-14T10:30:00.123456+09:00
        - High precision (Fiddler): 2024-12-14T10:30:00.1234567+09:00
        - Log format: 2024-12-14 10:30:00
        """
        import re

        if not timestamp_str:
            return None

        # Handle timezone offset (+09:00, -05:00, etc.)
        # Python 3.11+ handles this better with fromisoformat, but manual processing for compatibility
        tz_match = re.search(r'([+-]\d{2}:\d{2})$', timestamp_str)
        tz_offset = None
        if tz_match:
            timestamp_str = timestamp_str[:tz_match.start()]
            # Remove timezone info and return naive datetime

        # Handle high precision microseconds (truncate 7 digits to 6)
        if '.' in timestamp_str:
            parts = timestamp_str.split('.')
            if len(parts) == 2:
                base, frac = parts
                # Remove Z
                frac = frac.rstrip('Z')
                # Limit microseconds to 6 digits
                if len(frac) > 6:
                    frac = frac[:6]
                elif len(frac) < 6:
                    frac = frac.ljust(6, '0')
                timestamp_str = f"{base}.{frac}"

        # Remove Z
        timestamp_str = timestamp_str.rstrip('Z')

        formats = [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S"
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue

        self.logger.warning(f"Could not parse timestamp: {timestamp_str}")
        return None
    
    def _safe_json_loads(self, json_str: str) -> Optional[Dict]:
        """Safe JSON parsing"""
        import json
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            self.logger.warning(f"JSON parse error: {e}")
            return None