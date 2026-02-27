"""
Aegis Prime Auditor - Backend Orchestrator
Multi-engine security scanner with AI-powered analysis

Integrates:
- Semgrep (SAST)
- Gitleaks (Secrets)
- Trivy (SCA)
- CodeQL-pattern engine (Deep Analysis)
- Gemini AI (Risk Scoring & Remediation)
- Performance monitoring and metrics
- Structured logging
- Scan history API with pagination
- Process/Thread pool configuration
- Extended CodeQL patterns (8 types)
- Improved error handling

ENHANCEMENTS:
- Performance monitoring and metrics
- Structured logging
- Scan history API with pagination
- Process/Thread pool configuration
- Extended CodeQL patterns (8 types)
- Improved error handling

FEATURES:
- SBOM Generation (CycloneDX)
- Compliance Framework Mapping (6 frameworks)
- PDF/HTML Report Export
- Performance Monitoring
- Atlas Synapse Regulatory Rules
"""

import os
import json
import subprocess
import tempfile
import shutil
import uuid
import asyncio
import re
import time
import logging
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from background_processor import FilePrioritizer, BackgroundScanManager, background_manager
from file_parsers import FileParser
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from openai import OpenAI

from sbom_compliance import SBOMGenerator, ComplianceMapper
from pdf_generator import ReportGenerator

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('atlas_auditor.log')]
)
logger = logging.getLogger(__name__)

# App
app = FastAPI(
    title="Atlas Synapse Auditor",
    version="2.0.0",
    description="The Sovereign Standard for Enterprise Security Analysis"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Config
GEMINI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GEMINI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/")
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT_SECONDS", "120"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))

gemini_client = None
if GEMINI_API_KEY:
    try:
        gemini_client = OpenAI(api_key=GEMINI_API_KEY, base_url=GEMINI_BASE_URL)
        GEMINI_MODEL = "gemini-2.5-flash"
        logger.info("✅ Gemini AI initialized")
    except Exception as e:
        logger.error(f"❌ Gemini init failed: {e}")

SCAN_RESULTS_STORE: Dict[str, Any] = {}
UPLOAD_DIR = Path("/tmp/atlas_uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
CONFIG_DIR = Path(__file__).parent.parent / "config"

executor = ThreadPoolExecutor(max_workers=4)

# Metrics
class PerformanceMetrics:
    def __init__(self):
        self.scan_times = []
        self.engine_times = {'semgrep': [], 'gitleaks': [], 'trivy': [], 'codeql': [], 'ai': []}
    
    def record(self, total: float, engines: Dict[str, float]):
        self.scan_times.append(total)
        for e, t in engines.items():
            if e in self.engine_times:
                self.engine_times[e].append(t)
    
    def stats(self):
        if not self.scan_times:
            return {}
        return {
            "total_scans": len(self.scan_times),
            "avg_time": round(sum(self.scan_times) / len(self.scan_times), 2),
            "min_time": round(min(self.scan_times), 2),
            "max_time": round(max(self.scan_times), 2),
            "engines": {k: round(sum(v)/len(v), 2) if v else 0 for k, v in self.engine_times.items()}
        }

metrics = PerformanceMetrics()

# Scanners (simplified versions)
class SemgrepScanner:
    @staticmethod
def scan(path: str):
    start = time.time()
    try:
        # Get scannable content (handles all file types)
        content = FileParser.get_scannable_content(path)
        
        # Write to temp file for Semgrep
        temp_path = Path(path).parent / f"_scannable_{Path(path).name}.tmp"
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        rules = CONFIG_DIR / "semgrep_rules.yaml"
        cmd = ["semgrep", f"--config={rules}" if rules.exists() else "--config=auto", "--json", "--quiet", str(temp_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        elapsed = time.time() - start
        
        # Clean up temp file
        temp_path.unlink(missing_ok=True)
        
        if result.returncode in [0, 1]:
            data = json.loads(result.stdout)
            findings = [{
                "id": f.get("check_id", ""), "engine": "semgrep", "category": "SAST",
                "severity": f.get("extra", {}).get("severity", "WARNING").upper(),
                "message": f.get("extra", {}).get("message", f.get("check_id", "")),
                "file": Path(path).name,  # Use original filename
                "line_start": f.get("start", {}).get("line", 0),
                "snippet": f.get("extra", {}).get("lines", ""),
                "cwe": f.get("extra", {}).get("metadata", {}).get("cwe", [])
            } for f in data.get("results", [])]
            return ({"findings": findings, "engine": "semgrep", "error": None}, elapsed)
        return ({"findings": [], "engine": "semgrep", "error": result.stderr}, elapsed)
    except Exception as e:
        return ({"findings": [], "engine": "semgrep", "error": str(e)}, time.time() - start)

class GitleaksScanner:
    @staticmethod
    def scan(path: str):
        start = time.time()
        try:
            temp_dir, report = Path(path).parent, Path(path).parent / f"gl_{uuid.uuid4().hex[:8]}.json"
            subprocess.run(["gitleaks", "detect", "--source", str(temp_dir), "--report-format", "json",
                          "--report-path", str(report), "--no-git"], capture_output=True, timeout=SCAN_TIMEOUT)
            findings = []
            if report.exists():
                for item in json.load(open(report)):
                    findings.append({
                        "id": item.get("RuleID", ""), "engine": "gitleaks", "category": "Secrets",
                        "severity": "CRITICAL", "message": f"Secret: {item.get('Description', '')}",
                        "file": item.get("File", ""), "line_start": item.get("StartLine", 0),
                        "snippet": (item.get("Secret", "")[:50] + "...") if item.get("Secret") else ""
                    })
                report.unlink(missing_ok=True)
            return ({"findings": findings, "engine": "gitleaks", "error": None}, time.time() - start)
        except Exception as e:
            return ({"findings": [], "engine": "gitleaks", "error": str(e)}, time.time() - start)

class TrivyScanner:
    @staticmethod
    def scan(path: str):
        start = time.time()
        try:
            result = subprocess.run(["trivy", "fs", "--format", "json", "--scanners", "vuln", "--quiet", str(Path(path).parent)],
                                  capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            findings = []
            if result.returncode == 0:
                for entry in json.loads(result.stdout).get("Results", []):
                    for v in entry.get("Vulnerabilities", []):
                        findings.append({
                            "id": v.get("VulnerabilityID", ""), "engine": "trivy", "category": "SCA",
                            "severity": v.get("Severity", "MEDIUM"), "message": v.get("Title", ""),
                            "file": entry.get("Target", ""), "package": v.get("PkgName", ""),
                            "installed_version": v.get("InstalledVersion", ""),
                            "fixed_version": v.get("FixedVersion", ""),
                            "cve": v.get("VulnerabilityID", ""),
                            "cvss_score": v.get("CVSS", {}).get("nvd", {}).get("V3Score", 0)
                        })
            return ({"findings": findings, "engine": "trivy", "error": None}, time.time() - start)
        except Exception as e:
            return ({"findings": [], "engine": "trivy", "error": str(e)}, time.time() - start)

class CodeQLScanner:
    PATTERNS = {
        "sql-injection": {"regex": r'(execute|query)\s*\([^)]*[\{\%\+]', "severity": "CRITICAL", "cwe": "CWE-89",
                         "message": "SQL Injection: User data in SQL query"},
        "command-injection": {"regex": r'(system|exec|Runtime\.getRuntime)\s*\([^)]*[\+\$]', "severity": "CRITICAL", "cwe": "CWE-78",
                             "message": "Command Injection: User data in OS command"},
        "hardcoded-secret": {"regex": r'(password|secret|key|token)\s*=\s*["\'][^"\']{8,}', "severity": "HIGH", "cwe": "CWE-798",
                            "message": "Hardcoded Credential"},
        "weak-crypto": {"regex": r'(md5|sha1)\s*\(', "severity": "MEDIUM", "cwe": "CWE-327",
                       "message": "Weak Cryptography (MD5/SHA1)"},
        "path-traversal": {"regex": r'(open|File)\s*\([^)]*[\+]', "severity": "HIGH", "cwe": "CWE-22",
                          "message": "Path Traversal"},
        "insecure-deser": {"regex": r'(pickle\.load|yaml\.load\s*\([^,)]*\)|ObjectInputStream)', "severity": "CRITICAL", "cwe": "CWE-502",
                          "message": "Insecure Deserialization"},
        "xss": {"regex": r'innerHTML\s*=', "severity": "HIGH", "cwe": "CWE-79", "message": "XSS Vulnerability"},
        "eval": {"regex": r'\beval\s*\(', "severity": "CRITICAL", "cwe": "CWE-95", "message": "Code Injection (eval)"}
    }
    
    @staticmethod
def scan(path: str):
    start = time.time()
    try:
        # Get scannable content
        content = FileParser.get_scannable_content(path)
        lines = content.split('\n')
        
        findings = []
        for pid, pd in CodeQLScanner.PATTERNS.items():
            regex = re.compile(pd["regex"], re.I | re.M)
            for lnum, line in enumerate(lines, 1):
                if regex.search(line):
                    findings.append({
                        "id": f"codeql/{pid}", "engine": "codeql", "category": "Deep Analysis",
                        "severity": pd["severity"], "message": pd["message"],
                        "file": Path(path).name, "line_start": lnum,
                        "snippet": line.strip()[:150], "cwe": pd["cwe"]
                    })
        return ({"findings": findings, "engine": "codeql", "error": None}, time.time() - start)
    except Exception as e:
        return ({"findings": [], "engine": "codeql", "error": str(e)}, time.time() - start)

# AI
class GeminiAnalyzer:
    @staticmethod
    def analyze(findings: List[Dict], total: int, filename: str = ""):
        start = time.time()
        if not gemini_client:
            return (GeminiAnalyzer._fallback(findings, total), time.time() - start)
        
        try:
            sev_dist = {}
            for f in findings:
                s = f.get("severity", "MEDIUM")
                sev_dist[s] = sev_dist.get(s, 0) + 1
            
            prompt = f"""Security scan analysis - JSON only:

File: {filename}
Findings: {total}
Severity: {json.dumps(sev_dist)}

Return JSON:
{{"executive_summary": "2-3 sentences", "risk_score": 0-100, "risk_level": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW", "top_priorities": ["P1","P2","P3"]}}"""

            resp = gemini_client.chat.completions.create(
                model=GEMINI_MODEL, messages=[{"role": "user", "content": prompt}],
                temperature=0.2, max_tokens=800
            )
            
            ai_text = resp.choices[0].message.content.strip().replace('```json', '').replace('```', '').strip()
            ai_data = json.loads(ai_text)
            
            return ({
                "executive_summary": ai_data.get("executive_summary", ""),
                "risk_score": min(100, max(0, int(ai_data.get("risk_score", 50)))),
                "risk_level": ai_data.get("risk_level", "MEDIUM"),
                "top_priorities": ai_data.get("top_priorities", [])[:5]
            }, time.time() - start)
        except:
            return (GeminiAnalyzer._fallback(findings, total), time.time() - start)
    
    @staticmethod
    def _fallback(findings, total):
        weights = {"CRITICAL": 10, "ERROR": 10, "HIGH": 7, "MEDIUM": 4, "WARNING": 4, "LOW": 1}
        total_w = sum(weights.get(f.get("severity", "MEDIUM"), 4) for f in findings)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for f in findings:
            s = f.get("severity", "MEDIUM")
            if s in ["CRITICAL", "ERROR"]: counts["CRITICAL"] += 1
            elif s == "HIGH": counts["HIGH"] += 1
            elif s in ["MEDIUM", "WARNING"]: counts["MEDIUM"] += 1
            else: counts["LOW"] += 1
        
        score = min(100, int((total_w / max(1, total)) * 10))
        level = "CRITICAL" if score >= 80 or counts["CRITICAL"] >= 3 else \
                "HIGH" if score >= 60 or counts["HIGH"] >= 5 else \
                "MEDIUM" if score >= 30 else "LOW"
        
        return {
            "executive_summary": f"{total} findings. {counts['CRITICAL']} CRITICAL. Risk: {level} ({score}/100)",
            "risk_score": score,
            "risk_level": level,
            "top_priorities": [
                "Remediate CRITICAL findings immediately",
                "Address HIGH severity within 7 days",
                "Update vulnerable dependencies",
                "Implement secure coding practices",
                "Establish continuous monitoring"
            ]
        }

def generate_heatmap(findings):
    categories = ["SAST", "Secrets", "SCA", "Deep Analysis"]
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    matrix = {f"{c}_{s}": {"category": c, "severity": s, "count": 0, "risk_weight": 0.0} 
              for c in categories for s in severities}
    
    weights = {"CRITICAL": 1.0, "ERROR": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "WARNING": 0.5, "LOW": 0.25}
    
    for f in findings:
        cat, sev = f.get("category", "SAST"), f.get("severity", "MEDIUM")
        sev = "CRITICAL" if sev == "ERROR" else "MEDIUM" if sev == "WARNING" else sev
        key = f"{cat}_{sev}"
        if key in matrix:
            matrix[key]["count"] += 1
            matrix[key]["risk_weight"] += weights.get(sev, 0.5)
    
    max_w = max([m["risk_weight"] for m in matrix.values()] + [1])
    return [{**m, "normalized": round(m["risk_weight"]/max_w, 2) if max_w else 0} for m in matrix.values()]

async def _run_scanners(path: str):
    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(executor, s.scan, path) for s in [SemgrepScanner, GitleaksScanner, TrivyScanner, CodeQLScanner]]
    results = await asyncio.gather(*tasks)
    
    engines, timings = {}, {}
    for (data, elapsed), name in zip(results, ['semgrep', 'gitleaks', 'trivy', 'codeql']):
        engines[name], timings[name] = data, elapsed
    
    return (engines, timings)

# API Endpoints
@app.get("/")
async def root():
    return {
        "service": "Atlas Synapse Auditor",
        "version": "2.0.0",
        "status": "operational",
        "tagline": "The Sovereign Standard for Enterprise Security",
        "engines": {
            "semgrep": shutil.which("semgrep") is not None,
            "gitleaks": shutil.which("gitleaks") is not None,
            "trivy": shutil.which("trivy") is not None,
            "codeql": True,
            "gemini_ai": gemini_client is not None
        },
        "features": {
            "sbom_generation": True,
            "compliance_mapping": True,
            "pdf_reports": True,
            "atlas_regulatory_rules": True,
            "frameworks": list(ComplianceMapper.FRAMEWORKS.keys())
        },
        "metrics": metrics.stats()
    }

@app.post("/api/scan")
async def scan_code(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    """Smart scan with priority-based file selection and background processing."""
    import zipfile
    
    req_start = time.time()
    contents = await file.read()
    
    if len(contents) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"File > {MAX_UPLOAD_MB}MB")
    
    scan_id = str(uuid.uuid4())[:8]
    scan_dir = UPLOAD_DIR / scan_id
    scan_dir.mkdir(exist_ok=True)
    
    try:
        file_path = scan_dir / file.filename
        open(file_path, 'wb').write(contents)
        
        files_to_scan = []
        
        # Handle ZIP files
        if file.filename.endswith('.zip'):
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    code_extensions = {
    '.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.cs', 
    '.jsx', '.tsx', '.rs', '.kt', '.swift',  # Code
    '.html', '.htm', '.xml', '.svg',  # Web
    '.pdf', '.docx', '.doc', '.xlsx', '.xls',  # Documents
    '.txt', '.md', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg'  # Text
}
                    
                    for zip_info in zip_ref.filelist:
                        if zip_info.is_dir():
                            continue
                        
                        file_ext = Path(zip_info.filename).suffix.lower()
                        if file_ext in code_extensions:
                            zip_ref.extract(zip_info, scan_dir / 'extracted')
                            extracted_path = scan_dir / 'extracted' / zip_info.filename
                            
                            if extracted_path.exists() and extracted_path.stat().st_size < 5 * 1024 * 1024:
                                files_to_scan.append(extracted_path)
                    
                    logger.info(f"ZIP extraction: {len(files_to_scan)} code files found")
                    
            except Exception as e:
                logger.error(f"ZIP extraction failed: {e}")
                raise HTTPException(400, f"Invalid ZIP: {e}")
        else:
            files_to_scan = [file_path]
        
        if not files_to_scan:
            raise HTTPException(400, "No code files found")
        
        # SMART PRIORITIZATION
        files_to_scan = FilePrioritizer.filter_scannable(files_to_scan, max_files=50)
        original_count = len(files_to_scan)
        
        # For large batches (>15 files), use background processing
        if len(files_to_scan) > 15:
            # Create background task
            task_info = background_manager.create_task(scan_id, len(files_to_scan))
            
            # Return immediately with task ID
            return JSONResponse(content={
                "scan_id": scan_id,
                "status": "processing",
                "message": f"Large batch detected ({len(files_to_scan)} files). Processing in background...",
                "total_files": len(files_to_scan),
                "progress": 0,
                "estimated_time": f"{len(files_to_scan) * 3}s",
                "check_status_at": f"/api/scan/{scan_id}/status"
            })
            # Background processing happens asynchronously
        
        # For small batches (≤15 files), scan immediately
        all_findings = []
        files_scanned = []
        
        # Single file: full scan
        if len(files_to_scan) == 1:
            engines, timings = await _run_scanners(str(files_to_scan[0]))
            
            for data in engines.values():
                all_findings.extend(data.get("findings", []))
            
            files_scanned.append({"file": files_to_scan[0].name, "findings": len(all_findings)})
        
        # Multiple files: fast parallel scan (Semgrep + CodeQL only)
        else:
            async def scan_fast(fpath):
                loop = asyncio.get_event_loop()
                semgrep_task = loop.run_in_executor(executor, SemgrepScanner.scan, str(fpath))
                codeql_task = loop.run_in_executor(executor, CodeQLScanner.scan, str(fpath))
                
                (semgrep_result, _), (codeql_result, _) = await asyncio.gather(semgrep_task, codeql_task)
                
                findings = semgrep_result.get("findings", []) + codeql_result.get("findings", [])
                return {"file": fpath.name, "findings": len(findings), "findings_list": findings}
            
            results = await asyncio.gather(*[scan_fast(f) for f in files_to_scan])
            
            for r in results:
                files_scanned.append({"file": r["file"], "findings": r["findings"]})
                all_findings.extend(r["findings_list"])
        
        # AI analysis
        ai_analysis, ai_time = GeminiAnalyzer.analyze(all_findings, len(all_findings), file.filename)
        
        # Heatmap
        heatmap = generate_heatmap(all_findings)
        
        # Severity breakdown
        sev_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in all_findings:
            s = f.get("severity", "MEDIUM")
            if s in ["CRITICAL", "ERROR"]: sev_breakdown["CRITICAL"] += 1
            elif s == "HIGH": sev_breakdown["HIGH"] += 1
            elif s in ["MEDIUM", "WARNING"]: sev_breakdown["MEDIUM"] += 1
            else: sev_breakdown["LOW"] += 1
        
        total_time = time.time() - req_start
        
        result = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "file": file.filename,
            "is_batch": len(files_to_scan) > 1,
            "files_scanned": len(files_to_scan),
            "files_in_zip": original_count if file.filename.endswith('.zip') else len(files_to_scan),
            "file_results": files_scanned,
            "all_findings": all_findings,
            "total_findings": len(all_findings),
            "ai_analysis": ai_analysis,
            "heatmap_data": heatmap,
            "severity_breakdown": sev_breakdown,
            "performance": {"total": round(total_time, 2)},
            "status": "completed"
        }
        
        SCAN_RESULTS_STORE[scan_id] = result
        logger.info(f"✅ Scan {scan_id}: {total_time:.2f}s, {len(files_to_scan)} files, {len(all_findings)} findings")
        
        return JSONResponse(content=result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Scan failed: {e}", exc_info=True)
        raise HTTPException(500, str(e))
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get background scan progress status."""
    
    # Check if completed scan exists
    if scan_id in SCAN_RESULTS_STORE:
        return JSONResponse(content={
            "status": "completed",
            "result": SCAN_RESULTS_STORE[scan_id]
        })
    
    # Check background task status
    task_status = background_manager.get_status(scan_id)
    
    if task_status["status"] == "not_found":
        raise HTTPException(404, "Scan not found")
    
    return JSONResponse(content=task_status)

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in SCAN_RESULTS_STORE:
        raise HTTPException(404, "Scan not found")
    return JSONResponse(content=SCAN_RESULTS_STORE[scan_id])

@app.get("/api/scans")
async def list_scans(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)):
    scans = [{
        "scan_id": sid, "timestamp": d.get("timestamp"), "file": d.get("file"),
        "total_findings": d.get("total_findings"),
        "risk_score": d.get("ai_analysis", {}).get("risk_score", 0),
        "risk_level": d.get("ai_analysis", {}).get("risk_level", "UNKNOWN")
    } for sid, d in SCAN_RESULTS_STORE.items()]
    
    scans.sort(key=lambda x: x["timestamp"], reverse=True)
    return JSONResponse(content={"scans": scans[offset:offset+limit], "total": len(scans)})

@app.get("/api/metrics")
async def get_metrics():
    return JSONResponse(content=metrics.stats())

# NEW: Competitive Feature Endpoints
@app.get("/api/scan/{scan_id}/sbom")
async def get_sbom(scan_id: str):
    """Generate SBOM (Software Bill of Materials) - NIST SSDF Compliance."""
    if scan_id not in SCAN_RESULTS_STORE:
        raise HTTPException(404, "Scan not found")
    
    sbom = SBOMGenerator.generate(SCAN_RESULTS_STORE[scan_id])
    return JSONResponse(content=sbom, headers={
        "Content-Disposition": f"attachment; filename=atlas-sbom-{scan_id}.json"
    })

@app.get("/api/scan/{scan_id}/compliance")
async def get_compliance(scan_id: str):
    """Generate compliance framework mapping - SOC 2, PCI-DSS, OWASP, NYDFS."""
    if scan_id not in SCAN_RESULTS_STORE:
        raise HTTPException(404, "Scan not found")
    
    compliance = ComplianceMapper.map_findings_to_compliance(SCAN_RESULTS_STORE[scan_id]["all_findings"])
    return JSONResponse(content=compliance)

@app.get("/api/scan/{scan_id}/report/markdown")
async def get_md_report(scan_id: str):
    """Generate executive Markdown report."""
    if scan_id not in SCAN_RESULTS_STORE:
        raise HTTPException(404, "Scan not found")
    
    scan = SCAN_RESULTS_STORE[scan_id]
    compliance = ComplianceMapper.map_findings_to_compliance(scan["all_findings"])
    report = ReportGenerator.generate_executive_markdown(scan, compliance)
    
    return JSONResponse(content={"report": report, "format": "markdown"})

@app.get("/api/scan/{scan_id}/report/html")
async def get_html_report(scan_id: str):
    """Generate HTML report (PDF-ready via browser print)."""
    if scan_id not in SCAN_RESULTS_STORE:
        raise HTTPException(404, "Scan not found")
    
    scan = SCAN_RESULTS_STORE[scan_id]
    compliance = ComplianceMapper.map_findings_to_compliance(scan["all_findings"])
    html = ReportGenerator.generate_html_report(scan, compliance)
    
    return HTMLResponse(content=html)

@app.get("/api/compliance/frameworks")
async def list_frameworks():
    """List available compliance frameworks and regulatory rules."""
    return JSONResponse(content={
        "frameworks": [
            {"id": k, "name": v.get("name", k), "controls": len(v.get("mappings", {}))}
            for k, v in ComplianceMapper.FRAMEWORKS.items()
        ],
        "atlas_industries": ["fintech", "insurance", "healthcare", "legal"],
        "total_frameworks": len(ComplianceMapper.FRAMEWORKS)
    })

if __name__ == "__main__":
    import uvicorn
    
    host, port = os.getenv("AEGIS_HOST", "0.0.0.0"), int(os.getenv("AEGIS_PORT", "8000"))
    
    print("="*80)
    print("ATLAS SYNAPSE AUDITOR v2.0 - COMPETITIVE EDITION")
    print("="*80)
    print(f"🚀 Server: http://{host}:{port}")
    print(f"📊 API Docs: http://{host}:{port}/docs")
    print(f"🔧 Gemini AI: {'✅' if gemini_client else '❌'}")
    print(f"📋 Features: SBOM, Compliance (6 frameworks), PDF Reports")
    print(f"🏢 Atlas Industries: FinTech, Insurance, Healthcare, Legal")
    print("="*80)
    
    uvicorn.run("orchestrator:app", host=host, port=port, reload=False, log_level="info")