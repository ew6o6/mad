# MAD - MCP Artifact Digger

A forensic analysis framework for Model Context Protocol (MCP) artifacts in AI-assisted IDE environments.

## Overview

MAD (MCP Artifact Digger) extracts and analyzes MCP server activity from various artifact sources in Cursor IDE environments. It supports multiple artifact formats, automatic server inference, event correlation, and provides a web-based visualization dashboard.

### Key Features

- **Multi-source Artifact Analysis**: Supports mcp.json, Cursor logs, state.vscdb, agent-transcripts, server JSONL logs, and HAR network captures
- **Generic MCP Server Support**: Works with any MCP server (filesystem, github, notion, browser, database, etc.)
- **Server Name Inference**: Automatically detects MCP server mentions in user queries when explicit server info is unavailable (e.g., "filesystem MCP" → `filesystem (estimated)`)
- **Event Deduplication**: Removes duplicate events based on timestamp + content matching for enhanced readability
- **Event Correlation**: Matches events across sources using Request ID, Session ID, and time proximity
- **Comparison Analysis**: Compare Local STDIO vs Custom Remote vs Official Remote server forensic capabilities
- **Web Dashboard**: Responsive UI with light theme, expandable events, and server filtering

## Project Structure

```
mad/
├── mad/                        # Core Python package
│   ├── __init__.py
│   ├── api.py                  # FastAPI server & endpoints
│   ├── models/
│   │   ├── entities.py         # MCP Server, Tool, Resource models
│   │   ├── events.py           # Timeline events (with deduplication)
│   │   └── comparison.py       # Comparison matrix
│   ├── transformers/
│   │   ├── config.py           # mcp.json parser
│   │   ├── cursor_log.py       # Cursor MCP log parser
│   │   ├── vscdb.py            # state.vscdb SQLite parser
│   │   ├── agent_transcript.py # agent-transcripts JSON parser
│   │   ├── network.py          # HAR network capture parser
│   │   └── server_inference.py # MCP server inference utility
│   ├── correlation/
│   │   └── engine.py           # Event correlation engine
│   └── analysis/
│       └── comparative.py      # Local vs Remote analysis
├── web/                        # Web dashboard
│   ├── index.html
│   ├── css/style.css
│   └── js/
│       ├── app.js
│       ├── timeline.js
│       └── comparison.js
├── samples/                    # Sample artifacts for testing
├── tests/                      # Test suite
├── pyproject.toml              # Project configuration
├── requirements.txt
├── run_server.py               # Development server runner
└── README.md
```

## Installation

### Requirements

- Python 3.11+

### Quick Start

```bash
# Clone repository
git clone https://github.com/your-username/mad.git
cd mad

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Run server
python run_server.py
```

### Install as Package

```bash
pip install -e .
```

### Access

- **Web Dashboard**: http://localhost:8000/app
- **API Docs**: http://localhost:8000/api/docs
- **Health Check**: http://localhost:8000/health

## Supported Artifacts

### 1. state.vscdb (Cursor State Database)
- **Location**: `%APPDATA%\Cursor\User\workspaceStorage\<workspace-id>\state.vscdb`
- **Content**: Conversation history, MCP server settings, tool call records
- **Extracted Info**: User queries, AI responses, MCP tool calls, server mappings

### 2. MCP Server Logs
- **Location**: `%APPDATA%\Cursor\logs\<date>\window1\exthost\anysphere.cursor-mcp\MCP *.log`
- **Content**: MCP server connections, tool lists, call records
- **Extracted Info**: Server name, command, tool count, connection events

### 3. agent-transcripts (Agent Conversation JSON)
- **Location**: `%USERPROFILE%\.cursor\projects\<project-path>\agent-transcripts\*.json`
- **Content**: Full AI agent conversation records
- **Extracted Info**: MCP tool calls by server (confirmed), user queries, AI responses, thinking process
- **Formats Supported**:
  - `CallMcpTool` format: `{"toolName": "CallMcpTool", "args": {"server": "...", "toolName": "..."}}`
  - `mcp_` prefix format: `{"toolName": "mcp_ServerName_tool-name", "args": {...}}`

### 4. mcp.json (Configuration)
- **Location**: `%APPDATA%\Cursor\User\globalStorage\saoudrizwan.claude-dev\settings\mcp.json`
- **Content**: MCP server configuration
- **Extracted Info**: Server settings, commands, environment variables

### 5. HAR Network Captures
- **Location**: Captured via browser dev tools or Fiddler
- **Content**: HTTP/SSE requests to remote MCP servers
- **Extracted Info**: Request/response pairs, JSON-RPC messages, tool calls with arguments and results

## Usage

### Web Dashboard

1. Navigate to http://localhost:8000/app
2. Upload artifact files (state.vscdb, *.log, *.json, *.har, etc.)
3. Click "Analyze Artifacts"
4. View results by tab:
   - **Dashboard**: Server, tool, and event summary
   - **Analysis**: Detailed server information
   - **Timeline**: Event timeline (server filter, expand/collapse)

### Timeline Features

- **Server Filter**: Filter events by selecting a server from the dropdown
- **Event Expansion**: Click "Show more" to display full content
- **Server Tags**:
  - Confirmed: `[user-filesystem]` (explicitly confirmed from CallMcpTool)
  - Estimated: `[filesystem (estimated)]` (inferred from user query)

### Server Inference

Automatically detects MCP server mentions in user queries:

| Pattern | Inference Result |
|---------|------------------|
| "User-filesystem MCP list_allowed_directories" | `filesystem (estimated)` |
| "github mcp check issues" | `github (estimated)` |
| "filesystem server read file" | `filesystem (estimated)` |
| "MCP-browser open page" | `browser (estimated)` |

Supported server patterns: filesystem, github, git, notion, browser, slack, database, search, memory, fetch, docker, kubernetes, aws, google-drive, obsidian, and more.

### API Usage

```bash
# Upload and analyze files
curl -X POST http://localhost:8000/api/analyze \
  -F "files=@state.vscdb" \
  -F "files=@MCP user-filesystem.log"

# Get entities
curl http://localhost:8000/api/entities

# Get timeline
curl http://localhost:8000/api/timeline

# Get comparison matrix
curl http://localhost:8000/api/comparison/matrix
```

## Comparison Matrix

### Artifact Availability

| Artifact | Local STDIO | Custom Remote | Official Remote |
|----------|-------------|---------------|-----------------|
| mcp.json config | Full | Full | Full |
| Cursor logs | Full | Full | Full |
| state.vscdb | Full | Full | Full |
| agent-transcripts | Full | Full | Full |
| Server request log | None | **Full** | None |
| Server response log | None | **Full** | None |
| File access log | None | **Full** | None |
| Network capture | None | Full | Partial (encrypted) |

### Forensic Capabilities

| Capability | Local STDIO | Custom Remote | Official Remote |
|------------|-------------|---------------|-----------------|
| Timeline reconstruction | Medium | **High** | Medium |
| Action attribution | Low | **High** | Medium |
| Data exfiltration tracking | Low | **High** | Low |
| Security event detection | Low | **High** | Low |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Dashboard                             │
│  Upload → Analysis → Entities → Timeline (Filter/Expand)     │
└────────────────────────┬────────────────────────────────────┘
                         │ REST API
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  FastAPI Backend                             │
├─────────────────────────────────────────────────────────────┤
│  Transformers:                                               │
│  ├── VSCDBTransformer         (state.vscdb → conversations) │
│  ├── AgentTranscriptTransformer (*.json → MCP calls)        │
│  ├── CursorLogTransformer     (MCP *.log → server info)     │
│  ├── ConfigTransformer        (mcp.json → entities)         │
│  ├── NetworkTransformer       (*.har → JSON-RPC events)     │
│  └── ServerLogTransformer     (*.jsonl → events)            │
│                         ↓                                    │
│  Server Inference:                                           │
│  └── infer_server_from_text() → "filesystem (estimated)"    │
│                         ↓                                    │
│  CorrelationEngine:                                          │
│  ├── Request ID matching                                     │
│  ├── Session ID matching                                     │
│  ├── Time proximity matching                                 │
│  └── Event deduplication (timestamp + content hash)          │
└─────────────────────────────────────────────────────────────┘
```

## Artifact Locations (Windows)

```
# state.vscdb (conversation history)
%APPDATA%\Cursor\User\workspaceStorage\<workspace-id>\state.vscdb

# MCP server logs
%APPDATA%\Cursor\logs\<date>\window1\exthost\anysphere.cursor-mcp\MCP *.log

# Agent Transcripts
%USERPROFILE%\.cursor\projects\<project-path>\agent-transcripts\*.json

# MCP configuration
%APPDATA%\Cursor\User\globalStorage\saoudrizwan.claude-dev\settings\mcp.json
```

## References

- **MCP Specification**: https://modelcontextprotocol.io/specification/
- **Cursor IDE**: https://cursor.sh/

## License

MIT License
