"""FastAPI application — IPA upload, scan, results, diff, suppressions, baselines."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from shingan.core.analyzer import analyze
from shingan.core.diff import compare
from shingan.core.report import to_html, to_sarif
from shingan.core.storage import ScanStore
from shingan.core.suppression import SuppressionStore

app = FastAPI(title="shingan", version="1.0.0")

_WEB = Path(__file__).parent
templates = Jinja2Templates(directory=str(_WEB / "templates"))
store = ScanStore()
sup_store = SuppressionStore()

if (_WEB / "static").exists():
    app.mount("/static", StaticFiles(directory=str(_WEB / "static")), name="static")


# ── UI routes ─────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    scans = store.list_scans()
    return templates.TemplateResponse(request, "index.html", {"scans": scans})


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: str, baseline_id: str | None = None):
    try:
        result = store.load(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")

    diff_new = diff_fixed = None
    if baseline_id:
        try:
            baseline = store.load(baseline_id)
            diff = compare(baseline, result)
            diff_new = diff.new_fingerprints
            diff_fixed = diff.fixed_fingerprints
        except FileNotFoundError:
            pass

    html = to_html(result, diff_new=diff_new, diff_fixed=diff_fixed)
    return HTMLResponse(content=html)


# ── Scan API ──────────────────────────────────────────────────────────────────


@app.post("/api/scans")
async def upload_and_scan(file: UploadFile = File(...)):
    name = file.filename or ""
    if not name.endswith((".ipa", ".app", ".apk")):
        raise HTTPException(
            status_code=400, detail="Only .ipa or .apk files are accepted"
        )

    with tempfile.TemporaryDirectory(prefix="shingan_upload_") as tmp:
        input_path = Path(tmp) / name
        content = await file.read()
        input_path.write_bytes(content)

        try:
            result = analyze(input_path, suppression_store=sup_store)
        except Exception as e:
            raise HTTPException(status_code=422, detail=str(e))

    store.save(result)
    return JSONResponse(content=result.to_dict(), status_code=201)


@app.get("/api/scans")
async def list_scans(app_id: str | None = None):
    return store.list_scans(app_id=app_id)


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    try:
        result = store.load(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result.to_dict()


@app.get("/api/scans/{scan_id}/sarif")
async def get_sarif(scan_id: str):
    try:
        result = store.load(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")
    return Response(content=to_sarif(result), media_type="application/json")


@app.get("/api/scans/{scan_id}/html")
async def get_html(scan_id: str, baseline_id: str | None = None):
    try:
        result = store.load(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")

    diff_new = diff_fixed = None
    if baseline_id:
        try:
            baseline = store.load(baseline_id)
            diff = compare(baseline, result)
            diff_new = diff.new_fingerprints
            diff_fixed = diff.fixed_fingerprints
        except FileNotFoundError:
            pass

    return Response(
        content=to_html(result, diff_new=diff_new, diff_fixed=diff_fixed),
        media_type="text/html",
    )


@app.get("/api/scans/{scan_id}/diff/{baseline_id}")
async def diff_scans(scan_id: str, baseline_id: str):
    try:
        current = store.load(scan_id)
        baseline = store.load(baseline_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

    diff = compare(baseline, current)
    return {
        "scan_id": scan_id,
        "baseline_id": baseline_id,
        "summary": diff.summary(),
        "new": [f.to_dict() for f in diff.new],
        "fixed": [f.to_dict() for f in diff.fixed],
        "persisted": [f.to_dict() for f in diff.persisted],
    }


@app.delete("/api/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str):
    try:
        store.delete(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")


# ── Suppression API ───────────────────────────────────────────────────────────


class SuppressionRequest(BaseModel):
    rule_id: str
    evidence_prefix: str = ""
    reason: str = ""


@app.get("/api/suppressions")
async def list_suppressions():
    return [s.to_dict() for s in sup_store.list_all()]


@app.post("/api/suppressions", status_code=201)
async def add_suppression(body: SuppressionRequest):
    sup = sup_store.add(
        rule_id=body.rule_id,
        evidence_prefix=body.evidence_prefix,
        reason=body.reason,
    )
    return sup.to_dict()


@app.delete("/api/suppressions")
async def remove_suppression(rule_id: str, evidence_prefix: str = ""):
    removed = sup_store.remove(rule_id=rule_id, evidence_prefix=evidence_prefix)
    return {"removed": removed}


# ── Baseline API ──────────────────────────────────────────────────────────────


@app.post("/api/baselines/{app_id}")
async def set_baseline(app_id: str, scan_id: str):
    """Pin a specific scan as the baseline for an app."""
    try:
        store.load(scan_id)  # verify it exists
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")
    store.set_baseline(app_id, scan_id)
    return {"app_id": app_id, "baseline_scan_id": scan_id}


@app.get("/api/baselines/{app_id}")
async def get_baseline(app_id: str):
    scan_id = store.get_baseline(app_id)
    if not scan_id:
        raise HTTPException(status_code=404, detail="No baseline set for this app")
    return {"app_id": app_id, "baseline_scan_id": scan_id}
