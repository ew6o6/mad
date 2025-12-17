"""
MCP Server Inference Utility
Utility to infer MCP server mentions from user queries

Pattern examples:
- "User-filesystem MCP list_allowed_directories"
- "filesystem server read file"
- "github mcp check issues"
- "MCP-browser open page"
"""

import re
from typing import Optional, Tuple, List


# Known MCP server name patterns (extensible)
KNOWN_SERVER_PATTERNS: List[Tuple[str, str]] = [
    # Filesystem variants
    (r'(?:user[_-]?)?filesystem', 'filesystem'),
    (r'file[_-]?system', 'filesystem'),
    # GitHub
    (r'github', 'github'),
    # Git
    (r'\bgit\b(?![hub])', 'git'),
    # Notion
    (r'notion', 'notion'),
    # Browser/Playwright
    (r'browser|playwright', 'browser'),
    # Slack
    (r'slack', 'slack'),
    # Database
    (r'postgres|postgresql|mysql|sqlite|database|db', 'database'),
    # Search
    (r'brave[_-]?search|tavily|search', 'search'),
    # Memory
    (r'memory', 'memory'),
    # Fetch/HTTP
    (r'\bfetch\b|http[_-]?client', 'fetch'),
    # Sequential thinking
    (r'sequential[_-]?thinking', 'sequential-thinking'),
    # Puppeteer
    (r'puppeteer', 'puppeteer'),
    # Docker
    (r'docker', 'docker'),
    # Kubernetes
    (r'kubernetes|k8s', 'kubernetes'),
    # AWS
    (r'aws|amazon', 'aws'),
    # Google
    (r'google[_-]?drive|gdrive', 'google-drive'),
    (r'google[_-]?sheets', 'google-sheets'),
    # Obsidian
    (r'obsidian', 'obsidian'),
    # Raycast
    (r'raycast', 'raycast'),
]


def infer_server_from_text(text: str) -> Optional[Tuple[str, str]]:
    """
    Infer MCP server mention from text

    Args:
        text: User query or conversation text

    Returns:
        (inferred_server_name, matched_text) or None
    """
    if not text:
        return None

    text_lower = text.lower()

    # Pattern 1: "XXX MCP" or "XXX mcp" (e.g., "User-filesystem MCP")
    mcp_match = re.search(r'([a-zA-Z0-9_-]+)\s*[Mm][Cc][Pp]', text)
    if mcp_match:
        server_hint = mcp_match.group(1).lower()
        for pattern, canonical_name in KNOWN_SERVER_PATTERNS:
            if re.search(pattern, server_hint, re.IGNORECASE):
                return (canonical_name, mcp_match.group(0))
        # Only return if it matches a known pattern (no fallback)

    # Pattern 2: "MCP XXX" or "mcp-XXX" or "MCP-XXX"
    mcp_prefix_match = re.search(r'[Mm][Cc][Pp][_-]?\s*([a-zA-Z0-9_-]+)', text)
    if mcp_prefix_match:
        server_hint = mcp_prefix_match.group(1).lower()
        for pattern, canonical_name in KNOWN_SERVER_PATTERNS:
            if re.search(pattern, server_hint, re.IGNORECASE):
                return (canonical_name, mcp_prefix_match.group(0))
        # Only return if it matches a known pattern (no fallback)

    # Pattern 3: "XXX server" (supports both English "server" and Korean "서버")
    # Only match if XXX is a known server pattern
    server_match = re.search(r'([a-zA-Z0-9_-]+)\s*(?:server|서버)', text, re.IGNORECASE)
    if server_match:
        server_hint = server_match.group(1).lower()
        for pattern, canonical_name in KNOWN_SERVER_PATTERNS:
            if re.search(pattern, server_hint, re.IGNORECASE):
                return (canonical_name, server_match.group(0))
        # Only return if it matches a known pattern (no fallback)

    # Pattern 4: Direct mention of known servers with MCP context
    # Only if "mcp" or "server" or "tool" appears somewhere in text (supports Korean terms)
    if 'mcp' in text_lower or 'server' in text_lower or 'tool' in text_lower or '서버' in text or '도구' in text:
        for pattern, canonical_name in KNOWN_SERVER_PATTERNS:
            match = re.search(pattern, text_lower)
            if match:
                return (canonical_name, match.group(0))

    return None


def format_estimated_server(server_name: str) -> str:
    """Format estimated server name"""
    return f"{server_name} (estimated)"


def is_confirmed_server(server_name: str) -> bool:
    """Check if server is confirmed"""
    return server_name and "(estimated)" not in server_name
