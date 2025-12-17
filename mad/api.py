"""
MAD (MCP Artifact Digger) - FastAPI Server
Cursor IDE MCP artifact forensic analysis API

Cursor IDE + Local vs Remote MCP Comparison
"""

import os
import json
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Internal imports
from .models import (
    MCPEntities,
    Timeline,
    ComparisonResult,
    ServerType
)
from .transformers import (
    ConfigTransformer,
    CursorLogTransformer,
    ServerLogTransformer,
    NetworkTransformer,
    get_transformer_for_artifact,
    get_all_transformers
)
from .correlation import CorrelationEngine
from .analysis import ComparativeAnalyzer

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mcp-forensics")

# FastAPI app
app = FastAPI(
    title="MCP Forensics Analyzer",
    description="Forensic analysis framework for MCP artifacts in Cursor IDE",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
correlation_engine = CorrelationEngine()
comparative_analyzer = ComparativeAnalyzer()


# ==================== Pydantic Models ====================

class AnalysisRequest(BaseModel):
    """Analysis request model"""
    artifact_paths: List[str] = []
    include_comparison: bool = True


class AnalysisResponse(BaseModel):
    """Analysis response model"""
    success: bool
    entities: Dict[str, Any]
    timeline: Dict[str, Any]
    comparison: Optional[Dict[str, Any]] = None
    vscdb_analysis: Optional[Dict[str, Any]] = None
    stats: Dict[str, Any]
    errors: List[str] = []


# ==================== API Endpoints ====================

@app.get("/")
async def root():
    """API root"""
    return {
        "name": "MCP Forensics Analyzer",
        "version": "0.1.0",
        "platform": "Cursor IDE",
        "framework": "MCP Forensics Analyzer",
        "endpoints": {
            "analyze": "/api/analyze",
            "upload": "/api/upload",
            "entities": "/api/entities",
            "timeline": "/api/timeline",
            "comparison": "/api/comparison",
            "docs": "/api/docs"
        }
    }


@app.get("/api/info")
async def get_info():
    """System information"""
    return {
        "transformers": [
            {
                "name": t.name,
                "source": t.source.value
            }
            for t in get_all_transformers()
        ],
        "artifact_sources": [
            "cursor_log",
            "server_log",
            "network_capture",
            "config_file"
        ],
        "server_types": [st.value for st in ServerType],
        "default_paths": {
            "cursor_config": ConfigTransformer().get_default_config_path(),
            "cursor_logs": CursorLogTransformer().get_default_log_path()
        }
    }


@app.post("/api/upload")
async def upload_artifacts(files: List[UploadFile] = File(...)):
    """
    Upload artifact files

    Supported formats:
    - mcp.json (configuration file)
    - *.log (Cursor logs)
    - *.jsonl (server logs)
    - *.pcap, *.har (network captures)
    """
    upload_dir = Path(tempfile.mkdtemp(prefix="mad_"))
    uploaded_files = []

    try:
        for file in files:
            file_path = upload_dir / file.filename
            with open(file_path, "wb") as f:
                content = await file.read()
                f.write(content)
            uploaded_files.append(str(file_path))
            logger.info(f"Uploaded: {file.filename}")

        return {
            "success": True,
            "upload_dir": str(upload_dir),
            "files": uploaded_files,
            "count": len(uploaded_files)
        }

    except Exception as e:
        logger.exception("Upload failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_artifacts(
    files: List[UploadFile] = File(None),
    artifact_paths: str = Query(None, description="Comma-separated artifact paths"),
    include_comparison: bool = Query(True, description="Include comparison analysis")
):
    """
    Analyze MCP artifacts

    Perform analysis via file upload or local paths
    """
    errors = []
    all_entities = []
    all_timelines = []
    vscdb_analysis = None
    stats = {
        "files_processed": 0,
        "transformers_used": set(),
        "total_servers": 0,
        "total_events": 0
    }

    # Create temporary directory
    temp_dir = None
    paths_to_analyze = []

    try:
        # Process uploaded files
        if files:
            temp_dir = Path(tempfile.mkdtemp(prefix="mcp_analysis_"))
            for file in files:
                if file.filename:
                    file_path = temp_dir / file.filename
                    with open(file_path, "wb") as f:
                        content = await file.read()
                        f.write(content)
                    paths_to_analyze.append(str(file_path))

        # Add local paths
        if artifact_paths:
            paths_to_analyze.extend(artifact_paths.split(","))

        # Use default paths (if no paths provided)
        if not paths_to_analyze:
            config_path = ConfigTransformer().get_default_config_path()
            log_path = CursorLogTransformer().get_default_log_path()

            if config_path and config_path.exists():
                paths_to_analyze.append(str(config_path))
            if log_path and log_path.exists():
                paths_to_analyze.append(str(log_path))

        if not paths_to_analyze:
            raise HTTPException(
                status_code=400,
                detail="No artifacts to analyze. Upload files or provide paths."
            )

        # Process each artifact
        for artifact_path in paths_to_analyze:
            path = Path(artifact_path.strip())

            if not path.exists():
                errors.append(f"Path not found: {artifact_path}")
                continue

            try:
                transformer = get_transformer_for_artifact(str(path))
                stats["transformers_used"].add(transformer.name)

                # Check if transformer has process method with vscdb_analysis
                if hasattr(transformer, 'process') and transformer.name == "vscdb_transformer":
                    result = transformer.process(path)
                    if result.get("success") and result.get("vscdb_analysis"):
                        vscdb_analysis = result["vscdb_analysis"]

                # Extract entities
                entities = transformer.extract_entities(path)
                all_entities.append(entities)

                # Extract events
                timeline = transformer.extract_events(path)
                all_timelines.append(timeline)

                stats["files_processed"] += 1
                logger.info(f"Processed: {path} with {transformer.name}")

            except ValueError as e:
                errors.append(f"No transformer for: {artifact_path}")
            except Exception as e:
                errors.append(f"Error processing {artifact_path}: {str(e)}")
                logger.exception(f"Error processing {artifact_path}")

        # Correlation analysis and merge
        if all_entities:
            merged_entities = correlation_engine.correlate_entities(*all_entities)
        else:
            merged_entities = MCPEntities()

        if all_timelines:
            merged_timeline = correlation_engine.correlate_timelines(*all_timelines)
            # Remove duplicate events (same timestamp + content)
            removed_count = merged_timeline.deduplicate()
            if removed_count > 0:
                logger.info(f"Deduplicated {removed_count} duplicate events from timeline")
        else:
            merged_timeline = Timeline()

        # Update statistics
        stats["total_servers"] = len(merged_entities.servers)
        stats["total_events"] = len(merged_timeline.events)
        stats["transformers_used"] = list(stats["transformers_used"])
        stats["correlation_stats"] = correlation_engine.get_correlation_stats()

        # Comparative analysis
        comparison = None
        if include_comparison:
            comparison_result = comparative_analyzer.analyze(
                merged_entities, merged_timeline
            )
            comparison = comparison_result.to_dict()

        return AnalysisResponse(
            success=True,
            entities=merged_entities.to_dict(),
            timeline=merged_timeline.to_dict(),
            comparison=comparison,
            vscdb_analysis=vscdb_analysis,
            stats=stats,
            errors=errors
        )

    finally:
        # Clean up temporary directory
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir)


@app.get("/api/entities")
async def get_entities(
    config_path: str = Query(None, description="Path to mcp.json")
):
    """Query MCP entities (servers, tools, resources)"""
    transformer = ConfigTransformer()

    if config_path:
        path = Path(config_path)
    else:
        path = transformer.get_default_config_path()

    if not path or not path.exists():
        raise HTTPException(
            status_code=404,
            detail="Config file not found"
        )

    entities = transformer.extract_entities(path)
    return entities.to_dict()


@app.get("/api/timeline")
async def get_timeline(
    log_path: str = Query(None, description="Path to log directory"),
    server_name: str = Query(None, description="Filter by server name"),
    limit: int = Query(100, description="Maximum events to return")
):
    """Query event timeline"""
    transformer = CursorLogTransformer()

    if log_path:
        path = Path(log_path)
    else:
        path = transformer.get_default_log_path()

    if not path or not path.exists():
        raise HTTPException(
            status_code=404,
            detail="Log directory not found"
        )

    timeline = transformer.extract_events(path)

    # Filter by server
    if server_name:
        events = timeline.filter_by_server(server_name)
        timeline.events = events[:limit]
    else:
        timeline.events = timeline.events[:limit]

    return timeline.to_dict()


@app.get("/api/comparison")
async def get_comparison():
    """
    Local vs Remote MCP comparison analysis

    Returns comparison matrix from handoff document
    """
    # Create default comparison matrix with empty data
    result = ComparisonResult()

    for server_type in ServerType:
        profile = comparative_analyzer._create_default_profile(server_type)
        result.add_profile(profile)

    result.generate_findings()

    return {
        "artifact_matrix": result.artifact_matrix,
        "capability_matrix": result.capability_matrix,
        "findings": result.findings,
        "recommendations": result.recommendations,
        "artifact_descriptions": comparative_analyzer.get_artifact_descriptions(),
        "capability_descriptions": comparative_analyzer.get_capability_descriptions()
    }


@app.get("/api/comparison/matrix")
async def get_comparison_matrix():
    """Artifact availability matrix (handoff document format)"""
    return {
        "artifact_availability": {
            "mcp_config": {
                "Local STDIO": "Full",
                "Custom Remote": "Full",
                "Official Remote": "Full"
            },
            "cursor_logs": {
                "Local STDIO": "Full",
                "Custom Remote": "Full",
                "Official Remote": "Full"
            },
            "server_request_log": {
                "Local STDIO": "None",
                "Custom Remote": "Full",
                "Official Remote": "None"
            },
            "server_response_log": {
                "Local STDIO": "None",
                "Custom Remote": "Full",
                "Official Remote": "None"
            },
            "file_access_log": {
                "Local STDIO": "None",
                "Custom Remote": "Full",
                "Official Remote": "None"
            },
            "network_capture": {
                "Local STDIO": "None",
                "Custom Remote": "Full",
                "Official Remote": "Partial (encrypted)"
            },
            "session_id": {
                "Local STDIO": "None",
                "Custom Remote": "Full",
                "Official Remote": "Partial"
            },
            "json_rpc_trace": {
                "Local STDIO": "Partial",
                "Custom Remote": "Full",
                "Official Remote": "Partial"
            }
        },
        "forensic_capabilities": {
            "timeline_reconstruction": {
                "Local STDIO": "Medium",
                "Custom Remote": "High",
                "Official Remote": "Medium"
            },
            "action_attribution": {
                "Local STDIO": "Low",
                "Custom Remote": "High",
                "Official Remote": "Medium"
            },
            "data_exfiltration_tracking": {
                "Local STDIO": "Low",
                "Custom Remote": "High",
                "Official Remote": "Low"
            },
            "security_event_detection": {
                "Local STDIO": "Low",
                "Custom Remote": "High",
                "Official Remote": "Low"
            }
        }
    }


@app.post("/api/report")
async def generate_report(
    files: List[UploadFile] = File(None),
    format: str = Query("json", description="Output format: json, html")
):
    """Generate analysis report"""
    # Perform analysis
    analysis = await analyze_artifacts(files=files)

    if not analysis.success:
        raise HTTPException(status_code=500, detail="Analysis failed")

    # Generate report
    report = {
        "title": "MCP Forensics Analysis Report",
        "generated_at": datetime.now().isoformat(),
        "platform": "Cursor IDE",
        "framework": "MCP Forensics Analyzer",
        "summary": {
            "servers_analyzed": analysis.stats.get("total_servers", 0),
            "events_processed": analysis.stats.get("total_events", 0),
            "files_processed": analysis.stats.get("files_processed", 0)
        },
        "entities": analysis.entities,
        "timeline_summary": {
            "total_events": len(analysis.timeline.get("events", [])),
            "start_time": analysis.timeline.get("start_time"),
            "end_time": analysis.timeline.get("end_time")
        },
        "comparison": analysis.comparison,
        "errors": analysis.errors
    }

    if format == "html":
        # HTML report (to be implemented)
        return JSONResponse(
            content={"error": "HTML format not yet implemented"},
            status_code=501
        )

    return report


@app.get("/api/search")
async def search_logs(
    keywords: str = Query(..., description="Comma-separated keywords"),
    log_path: str = Query(None, description="Path to log directory"),
    limit: int = Query(50, description="Maximum results")
):
    """Search logs"""
    transformer = CursorLogTransformer()

    if log_path:
        path = Path(log_path)
    else:
        path = transformer.get_default_log_path()

    if not path or not path.exists():
        raise HTTPException(
            status_code=404,
            detail="Log directory not found"
        )

    keyword_list = [k.strip() for k in keywords.split(",")]
    results = transformer.search_logs(path, keywords=keyword_list)

    return {
        "keywords": keyword_list,
        "results": results[:limit],
        "total_matches": len(results)
    }


# ==================== Static Files ====================

# Web static files (if exists)
web_path = Path(__file__).parent.parent / "web"
if web_path.exists():
    app.mount("/static", StaticFiles(directory=str(web_path)), name="static")

    @app.get("/app")
    async def serve_app():
        """Serve web application"""
        index_path = web_path / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
        raise HTTPException(status_code=404, detail="Web app not found")


# ==================== Health Check ====================

@app.get("/health")
async def health_check():
    """Health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }


# ==================== Main ====================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
