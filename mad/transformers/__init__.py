"""
MCP Forensics - Transformers
Artifact-specific transformers for extracting MCP entities and events
"""

from .base import BaseTransformer
from .config import ConfigTransformer
from .cursor_log import CursorLogTransformer
from .server_log import ServerLogTransformer
from .network import NetworkTransformer
from .vscdb import VSCDBTransformer
from .mcps_folder import MCPSFolderTransformer
from .agent_transcript import AgentTranscriptTransformer

__all__ = [
    "BaseTransformer",
    "ConfigTransformer",
    "CursorLogTransformer",
    "ServerLogTransformer",
    "NetworkTransformer",
    "VSCDBTransformer",
    "MCPSFolderTransformer",
    "AgentTranscriptTransformer"
]


def get_transformer_for_artifact(artifact_path: str) -> BaseTransformer:
    """
    Automatically select appropriate Transformer for artifact path

    Args:
        artifact_path: Artifact file/directory path

    Returns:
        Appropriate Transformer instance
    """
    transformers = [
        AgentTranscriptTransformer(),  # Check agent-transcripts first (has server info)
        VSCDBTransformer(),  # Check vscdb
        MCPSFolderTransformer(),  # Check mcps folder
        ConfigTransformer(),
        CursorLogTransformer(),
        ServerLogTransformer(),
        NetworkTransformer()
    ]

    for transformer in transformers:
        if transformer.can_process(artifact_path):
            return transformer

    raise ValueError(f"No transformer found for artifact: {artifact_path}")


def get_all_transformers():
    """Return all Transformer instances"""
    return [
        ConfigTransformer(),
        CursorLogTransformer(),
        ServerLogTransformer(),
        NetworkTransformer(),
        VSCDBTransformer(),
        MCPSFolderTransformer(),
        AgentTranscriptTransformer()
    ]
