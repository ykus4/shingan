"""FastAPI application — IPA upload, scan, results, diff, suppressions, baselines."""

from __future__ import annotations

import logging
import os
import secrets
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from shingan.core.analyzer import analyze
from shingan.core.archive import safe_filename
from shingan.core.constants import MAX_UPLOAD_BYTES, UPLOAD_CHUNK_BYTES
from shingan.core.diff import compare
from shingan.core.models import ScanResult
from shingan.core.notify import notify_all, select_new_high_findings
from shingan.core.report import to_html, to_pdf, to_sarif
from shingan.core.storage import ScanStore
from shingan.core.suppression import SuppressionStore
from shingan.core.version import get_version

logger = logging.getLogger(__name__)

app = FastAPI(
    title="shingan",
    version=get_version(),
    description="iOS/Android static security analyzer — maps findings to OWASP MASVS v2",
    contact={"url": "https://github.com/ykus4/shingan"},
)

_WEB = Path(__file__).parent
templates = Jinja2Templates(directory=str(_WEB / "templates"))

#: Accepted upload extensions. ".app" is a directory on disk and cannot be
#: uploaded as a single file, so it is not accepted here.
_ALLOWED_UPLOAD_SUFFIXES = (".ipa", ".apk")

#: Environment variable holding the API key. When unset the API is open, which
#: is why `shingan serve` binds loopback by default.
API_KEY_ENV = "SHINGAN_API_KEY"


# ── Dependencies ──────────────────────────────────────────────────────────────
# Stores are provided via dependencies rather than module-level globals so tests
# can override them and importing this module has no filesystem side effects.


@lru_cache(maxsize=1)
def get_store() -> ScanStore:
    return ScanStore()


@lru_cache(maxsize=1)
def get_suppression_store() -> SuppressionStore:
    return SuppressionStore()


StoreDep = Annotated[ScanStore, Depends(get_store)]
SuppressionDep = Annotated[SuppressionStore, Depends(get_suppression_store)]


async def require_api_key(request: Request) -> None:
    """Enforce ``X-API-Key`` when SHINGAN_API_KEY is configured.

    No-op when the variable is unset, preserving the previous open behaviour for
    existing local deployments.
    """
    expected = os.getenv(API_KEY_ENV)
    if not expected:
        return
    provided = request.headers.get("X-API-Key", "")
    # Constant-time comparison so a wrong key cannot be recovered by timing.
    if not secrets.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )


AuthDep = Depends(require_api_key)

if (_WEB / "static").exists():
    app.mount("/static", StaticFiles(directory=str(_WEB / "static")), name="static")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _load_or_404(store: ScanStore, scan_id: str) -> ScanResult:
    try:
        return store.load(scan_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc


def _diff_fingerprints(
    store: ScanStore, result: ScanResult, baseline_id: str | None
) -> tuple[set[str] | None, set[str] | None]:
    """Resolve (new, fixed) fingerprints for an optional baseline.

    This block was previously duplicated in four route handlers.
    """
    if not baseline_id:
        return None, None
    try:
        baseline = store.load(baseline_id)
    except FileNotFoundError:
        logger.debug("Baseline %s not found — rendering without diff", baseline_id)
        return None, None
    diff = compare(baseline, result)
    return diff.new_fingerprints, diff.fixed_fingerprints


async def _save_upload(file: UploadFile, dest_dir: Path) -> Path:
    """Stream an upload to disk, enforcing the size limit.

    The filename is reduced to a single path component: it is client-controlled,
    and a value like ``../../evil.ipa`` must not escape ``dest_dir``.  The body
    is streamed in chunks rather than read fully into memory.
    """
    name = safe_filename(file.filename or "", fallback="upload.ipa")
    suffix = Path(name).suffix.lower()
    if suffix not in _ALLOWED_UPLOAD_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail=f"Only {' or '.join(_ALLOWED_UPLOAD_SUFFIXES)} files are accepted",
        )

    dest = dest_dir / name
    written = 0
    with dest.open("wb") as out:
        while chunk := await file.read(UPLOAD_CHUNK_BYTES):
            written += len(chunk)
            if written > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=f"Upload exceeds the {MAX_UPLOAD_BYTES} byte limit",
                )
            out.write(chunk)
    return dest


# ── UI routes ─────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, store: StoreDep) -> Response:
    scans = store.list_scans()
    return templates.TemplateResponse(request, "index.html", {"scans": scans})


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(
    scan_id: str, store: StoreDep, baseline_id: str | None = None
) -> HTMLResponse:
    result = _load_or_404(store, scan_id)
    diff_new, diff_fixed = _diff_fingerprints(store, result, baseline_id)
    return HTMLResponse(
        content=to_html(result, diff_new=diff_new, diff_fixed=diff_fixed)
    )


# ── Scan API ──────────────────────────────────────────────────────────────────


@app.post(
    "/api/scans",
    tags=["scans"],
    summary="Upload and scan an IPA or APK",
    dependencies=[AuthDep],
)
async def upload_and_scan(
    store: StoreDep,
    suppressions: SuppressionDep,
    background: BackgroundTasks,
    file: UploadFile = File(...),
) -> JSONResponse:
    with tempfile.TemporaryDirectory(prefix="shingan_upload_") as tmp:
        input_path = await _save_upload(file, Path(tmp))
        try:
            result = analyze(input_path, suppression_store=suppressions)
        except (FileNotFoundError, ValueError, ImportError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Compare against the previous scan of the same app so notifications fire
    # only for newly-introduced findings instead of on every upload.
    previous = store.latest_for_app(result.app_id)
    store.save(result)

    new_findings = select_new_high_findings(result, previous)
    if new_findings:
        # Dispatched after the response so a slow webhook cannot stall the request.
        background.add_task(notify_all, result, new_findings)

    return JSONResponse(content=result.to_dict(), status_code=201)


@app.get("/api/scans", tags=["scans"], summary="List stored scans")
async def list_scans(store: StoreDep, app_id: str | None = None) -> list[dict]:
    return store.list_scans(app_id=app_id)


@app.get("/api/scans/{scan_id}", tags=["scans"], summary="Get a scan by ID")
async def get_scan(scan_id: str, store: StoreDep) -> dict:
    return _load_or_404(store, scan_id).to_dict()


@app.get(
    "/api/scans/{scan_id}/sarif", tags=["scans"], summary="Export scan as SARIF 2.1.0"
)
async def get_sarif(scan_id: str, store: StoreDep) -> Response:
    result = _load_or_404(store, scan_id)
    return Response(content=to_sarif(result), media_type="application/json")


@app.get(
    "/api/scans/{scan_id}/html", tags=["scans"], summary="Export scan as HTML report"
)
async def get_html(
    scan_id: str, store: StoreDep, baseline_id: str | None = None
) -> Response:
    result = _load_or_404(store, scan_id)
    diff_new, diff_fixed = _diff_fingerprints(store, result, baseline_id)
    return Response(
        content=to_html(result, diff_new=diff_new, diff_fixed=diff_fixed),
        media_type="text/html",
    )


@app.get(
    "/api/scans/{scan_id}/pdf", tags=["scans"], summary="Export scan as PDF report"
)
async def get_pdf(
    scan_id: str,
    store: StoreDep,
    baseline_id: str | None = None,
    lang: str = "en",
) -> Response:
    result = _load_or_404(store, scan_id)
    diff_new, diff_fixed = _diff_fingerprints(store, result, baseline_id)
    try:
        pdf_bytes = to_pdf(result, diff_new=diff_new, diff_fixed=diff_fixed, lang=lang)
    except RuntimeError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc

    filename = f"shingan_{scan_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get(
    "/api/scans/{scan_id}/diff/{baseline_id}", tags=["scans"], summary="Diff two scans"
)
async def diff_scans(scan_id: str, baseline_id: str, store: StoreDep) -> dict:
    current = _load_or_404(store, scan_id)
    baseline = _load_or_404(store, baseline_id)
    diff = compare(baseline, current)
    return {
        "scan_id": scan_id,
        "baseline_id": baseline_id,
        "summary": diff.summary(),
        "new": [f.to_dict() for f in diff.new],
        "fixed": [f.to_dict() for f in diff.fixed],
        "persisted": [f.to_dict() for f in diff.persisted],
    }


@app.delete(
    "/api/scans/{scan_id}",
    tags=["scans"],
    status_code=204,
    dependencies=[AuthDep],
)
async def delete_scan(scan_id: str, store: StoreDep) -> Response:
    # delete() reports whether a row actually went away; the old code relied on
    # a FileNotFoundError that delete() never raised, so unknown IDs returned 204.
    if not store.delete(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return Response(status_code=204)


# ── Suppression API ───────────────────────────────────────────────────────────


class SuppressionRequest(BaseModel):
    rule_id: str
    evidence_prefix: str = ""
    reason: str = ""


@app.get("/api/suppressions", tags=["suppressions"])
async def list_suppressions(suppressions: SuppressionDep) -> list[dict]:
    return [s.to_dict() for s in suppressions.list_all()]


@app.post(
    "/api/suppressions",
    tags=["suppressions"],
    status_code=201,
    dependencies=[AuthDep],
)
async def add_suppression(
    body: SuppressionRequest, suppressions: SuppressionDep
) -> dict:
    sup = suppressions.add(
        rule_id=body.rule_id,
        evidence_prefix=body.evidence_prefix,
        reason=body.reason,
    )
    return sup.to_dict()


@app.delete("/api/suppressions", tags=["suppressions"], dependencies=[AuthDep])
async def remove_suppression(
    suppressions: SuppressionDep, rule_id: str, evidence_prefix: str = ""
) -> dict:
    removed = suppressions.remove(rule_id=rule_id, evidence_prefix=evidence_prefix)
    return {"removed": removed}


# ── Baseline API ──────────────────────────────────────────────────────────────


@app.post("/api/baselines/{app_id}", tags=["baselines"], dependencies=[AuthDep])
async def set_baseline(app_id: str, scan_id: str, store: StoreDep) -> dict:
    """Pin a specific scan as the baseline for an app."""
    if not store.exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    store.set_baseline(app_id, scan_id)
    return {"app_id": app_id, "baseline_scan_id": scan_id}


@app.get("/api/baselines/{app_id}", tags=["baselines"])
async def get_baseline(app_id: str, store: StoreDep) -> dict:
    scan_id = store.get_baseline(app_id)
    if not scan_id:
        raise HTTPException(status_code=404, detail="No baseline set for this app")
    return {"app_id": app_id, "baseline_scan_id": scan_id}


@app.get("/api/health", tags=["meta"], summary="Liveness probe")
async def health() -> dict:
    return {"status": "ok", "version": get_version()}
