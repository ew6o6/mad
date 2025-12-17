#!/usr/bin/env python
"""Run the MAD (MCP Artifact Digger) server"""
import sys
import os

# Add the project root to the path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "mad.api:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
