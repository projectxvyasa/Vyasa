"""
FastAPI Server & Real-time Web Dashboard for VYASA.
"""

import os
import time
import json
import uuid
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from vyasa.core.config import load_config
from vyasa.core.models import ReportPreferences
from vyasa.orchestrator import VyasaOrchestrator

app = FastAPI(
    title="VYASA Security Dashboard",
    description="Autonomous AI Penetration Testing & Risk Analysis Platform",
    version="0.1.0"
)

# Active scan tracker
active_scans: Dict[str, Dict[str, Any]] = {}


def clear_reports_dir():
    """Deletes all existing markdown and JSON reports from the ./reports directory."""
    reports_dir = Path("./reports")
    if reports_dir.exists():
        for p in reports_dir.glob("*"):
            if p.is_file() and p.suffix in [".md", ".json"]:
                try:
                    p.unlink()
                except Exception as e:
                    pass


class ScanRequest(BaseModel):
    target: str
    endpoint: Optional[str] = None
    deep_scan: bool = True
    fast: bool = True
    selected_checks: Optional[List[str]] = None
    selected_categories: Optional[List[str]] = None
    preferences: Optional[Dict[str, bool]] = None
    clear_old_reports: bool = True


def run_background_scan(
    scan_id: str,
    target: str,
    deep_scan: bool = True,
    preferences_dict: Optional[Dict[str, bool]] = None,
    selected_checks: Optional[List[str]] = None,
    selected_categories: Optional[List[str]] = None,
    target_endpoint: Optional[str] = None,
    fast: bool = True
):
    """Executes the orchestrator engagement and streams progress into active_scans."""
    config = load_config()
    orchestrator = VyasaOrchestrator(config, fast=fast)

    scan_record = active_scans[scan_id]
    scan_record["status"] = "RUNNING"
    scan_record["current_phase"] = "START"

    prefs = None
    if preferences_dict:
        try:
            prefs = ReportPreferences(**preferences_dict)
        except Exception:
            prefs = None

    def progress_callback(phase: str, message: str, data: Dict[str, Any]):
        timestamp = time.strftime("%H:%M:%S")
        scan_record["current_phase"] = phase

        # Granular live feeds (endpoints discovered one-by-one, checks run one-by-one).
        if phase == "CRAWL":
            scan_record["crawl_feed"].append({"path": data.get("path"), "url": data.get("url"), "t": timestamp})
            return
        if phase == "CHECK":
            scan_record["check_feed"].append({
                "id": data.get("check_id"), "title": data.get("title"),
                "category": data.get("category"), "verdict": data.get("verdict"), "t": timestamp,
            })
            if data.get("verdict") == "VULNERABLE":
                scan_record["terminal_logs"].append(
                    f"[{timestamp}] [FINDING] {data.get('check_id')}: {data.get('title')} -> VULNERABLE")
            return

        # Phase-level events feed the timeline.
        scan_record["phase_history"].append({"phase": phase, "message": message, "t": timestamp})
        scan_record["logs"].append({
            "timestamp": timestamp,
            "phase": phase,
            "message": message,
            "data": data
        })

        # Add formatted terminal log line
        scan_record["terminal_logs"].append(f"[{timestamp}] [{phase}] {message}")

        if "assets" in data:
            scan_record["assets"] = data["assets"]
        if "findings" in data:
            scan_record["findings"] = data["findings"]
        if "new_findings" in data:
            scan_record["findings"].extend(data["new_findings"])
        if "attack_paths" in data:
            scan_record["attack_paths"] = data["attack_paths"]
        if "decision" in data:
            dec = data["decision"]
            scan_record["decisions"].append({
                "iteration": data.get("iteration", len(scan_record["decisions"]) + 1),
                "decision": dec
            })
            scan_record["terminal_logs"].append(
                f"[{timestamp}] [AI_REASONING] Next Step: {dec.get('action_type')} on '{dec.get('target_resource')}' | Hypothesis: {dec.get('hypothesis')}"
            )
        if phase == "COMPLETED":
            scan_record["status"] = "COMPLETED"
            scan_record["report_id"] = data.get("report_id")
            scan_record["executive_summary"] = data.get("executive_summary")

    try:
        orchestrator.run_engagement(
            target,
            progress_callback=progress_callback,
            deep_scan=deep_scan,
            report_preferences=prefs,
            selected_checks=selected_checks,
            selected_categories=selected_categories,
            target_endpoint=target_endpoint
        )
    except Exception as e:
        scan_record["status"] = "FAILED"
        scan_record["error"] = str(e)
        scan_record["logs"].append({
            "timestamp": time.strftime("%H:%M:%S"),
            "phase": "ERROR",
            "message": f"Engagement failed: {e}",
            "data": {}
        })
        scan_record["terminal_logs"].append(f"[{time.strftime('%H:%M:%S')}] [ERROR] Engagement failed: {e}")


@app.get("/api/catalog")
def get_vulnerability_catalog():
    """Returns the full 100+ vulnerability catalog definitions."""
    from vyasa.testing.vulnerability_catalog import VULNERABILITY_CATALOG
    return [c.model_dump() for c in VULNERABILITY_CATALOG]


@app.post("/api/scan")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """Initiates an autonomous penetration testing engagement."""
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    if req.clear_old_reports:
        clear_reports_dir()

    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    active_scans[scan_id] = {
        "scan_id": scan_id,
        "target": target,
        "endpoint": req.endpoint,
        "status": "QUEUED",
        "current_phase": "INIT",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "logs": [],
        "terminal_logs": [
            f"[{time.strftime('%H:%M:%S')}] [INIT] Engagement initialized for target: {target}" +
            (f" (Endpoint: {req.endpoint})" if req.endpoint else "")
        ],
        "assets": [],
        "findings": [],
        "decisions": [],
        "attack_paths": [],
        "crawl_feed": [],
        "check_feed": [],
        "phase_history": [],
        "report_id": None,
        "executive_summary": None,
        "error": None
    }

    background_tasks.add_task(
        run_background_scan,
        scan_id,
        target,
        req.deep_scan,
        req.preferences,
        req.selected_checks,
        req.selected_categories,
        req.endpoint,
        req.fast
    )
    return {"scan_id": scan_id, "status": "QUEUED", "target": target}


@app.get("/api/scan/{scan_id}")
def get_scan_status(scan_id: str):
    """Retrieves live state, findings, decisions, and attack paths for an ongoing scan."""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return active_scans[scan_id]


@app.delete("/api/reports")
def delete_all_reports():
    """Deletes all previous audit reports."""
    clear_reports_dir()
    return {"status": "success", "message": "All old reports cleared successfully"}


@app.get("/api/reports")
def list_reports():
    """Lists all generated security audit reports."""
    reports_dir = Path("./reports")
    if not reports_dir.exists():
        return []

    reports = []
    for p in reports_dir.glob("*.md"):
        reports.append({
            "filename": p.name,
            "report_id": p.stem,
            "modified": time.ctime(p.stat().st_mtime),
            "size_bytes": p.stat().st_size
        })
    return sorted(reports, key=lambda x: x["modified"], reverse=True)



@app.get("/api/reports/{filename}")
def get_report_content(filename: str):
    """Returns the markdown content of a specific report file."""
    report_file = Path("./reports") / filename
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    with open(report_file, "r", encoding="utf-8") as f:
        return PlainTextResponse(f.read())


@app.get("/api/reports/{filename}/json")
def get_report_json(filename: str):
    """Returns the structured JSON report object for full 3-tab report rendering."""
    stem = Path(filename).stem
    json_path = Path("./reports") / f"{stem}.json"
    if not json_path.exists():
        raise HTTPException(status_code=404, detail="JSON report file not found")
    with open(json_path, "r", encoding="utf-8") as f:
        return JSONResponse(json.load(f))


@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    """Renders the single-page interactive command center."""
    template_path = Path(__file__).parent / "templates" / "index.html"
    if template_path.exists():
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>VYASA Dashboard Template Missing</h1>"


@app.get("/report/{report_id}", response_class=HTMLResponse)
def get_report_view(report_id: str):
    """Renders the polished, interactive, print-to-PDF security report for a given report ID."""
    template_path = Path(__file__).parent / "templates" / "report.html"
    if template_path.exists():
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>VYASA Report Template Missing</h1>"


def start_server(host: str = "127.0.0.1", port: int = 8000):
    """Entry point to launch the web dashboard server."""
    import uvicorn
    print(f"\n[+] Starting VYASA Interactive Command Center at: http://{host}:{port}")
    uvicorn.run("vyasa.web.app:app", host=host, port=port, reload=False, log_level="warning")


if __name__ == "__main__":
    start_server()
