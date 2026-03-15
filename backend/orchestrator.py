"""
Atlas Synapse Auditor v3.1 - Production Backend with Malware Detection
Multi-file, multi-format security scanner + Antivirus-style malware detection
"""

import os
import json
import subprocess
import shutil
import uuid
import asyncio
import re
import time
import hashlib
import threading
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from openai import OpenAI

# Supabase client for persistent scan storage
try:
    from supabase import create_client, Client as SupabaseClient
    _sb_url = os.environ.get("SUPABASE_URL", "")
    _sb_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    supabase_db: SupabaseClient | None = create_client(_sb_url, _sb_key) if _sb_url and _sb_key else None
    if supabase_db:
        print("✅ Supabase connected — scan results will be persisted")
    else:
        print("⚠️  SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY not set — results stored in memory only")
except Exception as _sb_err:
    supabase_db = None
    print(f"⚠️  Supabase init failed: {_sb_err}")
from background_processor import FilePrioritizer, BackgroundScanManager, background_manager
from specialized_scanners import SpecializedScanner
from file_parsers import FileParser
from sbom_compliance import SBOMGenerator, ComplianceMapper
from pdf_generator import ReportGenerator

# Malware detection imports
try:
    from malware_detection.signature_scanner import MalwareScanner as MalwareScannerEngine, YARAScanner
    from malware_detection.heuristic_analyzer import HeuristicAnalyzer, EntropyAnalyzer
    MALWARE_DETECTION_AVAILABLE = True
except ImportError:
    MALWARE_DETECTION_AVAILABLE = False
    logger_temp = logging.getLogger(__name__)
    logger_temp.warning("⚠️ Malware detection modules not found")

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
    version="3.1.0",
    description="Trust Engine for AI Systems + Malware Detection"
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
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")  # Optional
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

# Initialize malware scanner
malware_scanner = None
if MALWARE_DETECTION_AVAILABLE:
    try:
        malware_scanner = MalwareScannerEngine(VIRUSTOTAL_API_KEY)
        logger.info(f"🦠 Malware detection: ✅ Enabled {'(with VirusTotal)' if VIRUSTOTAL_API_KEY else '(YARA only)'}")
    except Exception as e:
        logger.error(f"❌ Malware scanner init failed: {e}")

SCAN_RESULTS_STORE: Dict[str, Any] = {}
UPLOAD_DIR = Path("/tmp/atlas_uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
CONFIG_DIR = Path(__file__).parent.parent / "config"

executor = ThreadPoolExecutor(max_workers=4)

# Metrics
class PerformanceMetrics:
    def __init__(self):
        self.scan_times = []
        self.engine_times = {'semgrep': [], 'gitleaks': [], 'trivy': [], 'codeql': [], 'ai': [], 'malware': []}
    
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

# ── Immutable Audit Log ──────────────────────────────────────────────────────
class ImmutableAuditLog:
    """
    Append-only, cryptographically hash-chained audit log.
    Each entry stores the SHA-256 hash of the previous entry so the chain
    can be independently verified and any tampering detected.
    """

    GENESIS_HASH = hashlib.sha256(b"ATLAS_SYNAPSE_GENESIS_BLOCK_v3.1").hexdigest()

    def __init__(self, log_path: str = "audit_log.jsonl"):
        self._log_path = Path(log_path)
        self._lock = threading.Lock()
        self._last_hash, self._seq = self._load_tail()
        logger.info(f"📋 Audit log initialised — {self._seq} existing entries at {self._log_path}")

    # ── private helpers ──────────────────────────────────────────────────────

    def _load_tail(self):
        """Read the tail of an existing log to initialise state."""
        if not self._log_path.exists():
            return self.GENESIS_HASH, 0
        last_hash, seq = self.GENESIS_HASH, 0
        try:
            with open(self._log_path, "r", encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        entry = json.loads(raw)
                        last_hash = entry.get("entry_hash", last_hash)
                        seq = entry.get("seq", seq)
                    except json.JSONDecodeError:
                        pass
        except OSError as exc:
            logger.warning(f"Could not read audit log: {exc}")
        return last_hash, seq

    @staticmethod
    def _hash_entry(entry: dict) -> str:
        """Produce a deterministic SHA-256 hash of an entry (without entry_hash field)."""
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # ── public API ───────────────────────────────────────────────────────────

    def append(self, event_type: str, data: dict) -> dict:
        """Append an immutable entry and return it (including its hash)."""
        with self._lock:
            self._seq += 1
            entry: dict = {
                "seq": self._seq,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "data": data,
                "prev_hash": self._last_hash,
            }
            entry["entry_hash"] = self._hash_entry(entry)
            try:
                with open(self._log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")
            except OSError as exc:
                logger.error(f"Audit log write failed: {exc}")
                return entry
            self._last_hash = entry["entry_hash"]
            return entry

    def get_entries(self, limit: int = 100, offset: int = 0):
        """Return (entries, total) — entries are newest-first with pagination."""
        entries: List[dict] = []
        if not self._log_path.exists():
            return entries, 0
        try:
            with open(self._log_path, "r", encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if raw:
                        try:
                            entries.append(json.loads(raw))
                        except json.JSONDecodeError:
                            pass
        except OSError as exc:
            logger.error(f"Audit log read failed: {exc}")
            return entries, 0
        total = len(entries)
        # Newest first
        entries = list(reversed(entries))
        return entries[offset: offset + limit], total

    def verify_chain(self) -> dict:
        """
        Walk the entire log and verify the hash chain.
        Returns a dict with keys: valid (bool), entries_checked (int), broken_at_seq (int|None).
        """
        if not self._log_path.exists():
            return {"valid": True, "entries_checked": 0, "broken_at_seq": None}
        prev_hash = self.GENESIS_HASH
        checked = 0
        try:
            with open(self._log_path, "r", encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    stored_hash = entry.pop("entry_hash", None)
                    if entry.get("prev_hash") != prev_hash:
                        return {"valid": False, "entries_checked": checked, "broken_at_seq": entry.get("seq")}
                    recomputed = self._hash_entry(entry)
                    if recomputed != stored_hash:
                        return {"valid": False, "entries_checked": checked, "broken_at_seq": entry.get("seq")}
                    prev_hash = stored_hash
                    entry["entry_hash"] = stored_hash  # restore
                    checked += 1
        except OSError as exc:
            logger.error(f"Audit log verification failed: {exc}")
            return {"valid": False, "entries_checked": checked, "broken_at_seq": None}
        return {"valid": True, "entries_checked": checked, "broken_at_seq": None}


# Global audit log instance
audit_log = ImmutableAuditLog(log_path=os.getenv("AUDIT_LOG_PATH", "audit_log.jsonl"))

# Scanners
class SemgrepScanner:
    @staticmethod
    def scan(path: str):
        start = time.time()
        try:
            content = FileParser.get_scannable_content(path)
            temp_path = Path(path).parent / f"_scan_{Path(path).name}.tmp"
            
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            rules = CONFIG_DIR / "semgrep_rules.yaml"
            cmd = ["semgrep", f"--config={rules}" if rules.exists() else "--config=auto", "--json", "--quiet", str(temp_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            elapsed = time.time() - start
            
            temp_path.unlink(missing_ok=True)
            
            if result.returncode in [0, 1]:
                data = json.loads(result.stdout)
                findings = [{
                    "id": f.get("check_id", ""), "engine": "semgrep", "category": "SAST",
                    "severity": f.get("extra", {}).get("severity", "WARNING").upper(),
                    "message": f.get("extra", {}).get("message", f.get("check_id", "")),
                    "file": Path(path).name,
                    "line_start": f.get("start", {}).get("line", 0),
                    "snippet": f.get("extra", {}).get("lines", ""),
                    "cwe": f.get("extra", {}).get("metadata", {}).get("cwe", [])
                } for f in data.get("results", [])]
                
                logger.info(f"Semgrep: {elapsed:.2f}s, {len(findings)} findings")
                return ({"findings": findings, "engine": "semgrep", "error": None}, elapsed)
            return ({"findings": [], "engine": "semgrep", "error": result.stderr}, elapsed)
        except Exception as e:
            return ({"findings": [], "engine": "semgrep", "error": str(e)}, time.time() - start)

class GitleaksScanner:
    @staticmethod
    def scan(path: str):
        start = time.time()
        try:
            temp_dir = Path(path).parent
            report = temp_dir / f"gl_{uuid.uuid4().hex[:8]}.json"
            
            subprocess.run(["gitleaks", "detect", "--source", str(temp_dir), "--report-format", "json",
                          "--report-path", str(report), "--no-git"], capture_output=True, timeout=SCAN_TIMEOUT)
            
            findings = []
            if report.exists():
                for item in json.load(open(report)):
                    findings.append({
                        "id": item.get("RuleID", ""), "engine": "gitleaks", "category": "Secrets",
                        "severity": "CRITICAL", "message": f"Secret: {item.get('Description', '')}",
                        "file": Path(item.get("File", "")).name,
                        "line_start": item.get("StartLine", 0),
                        "snippet": (item.get("Secret", "")[:50] + "...") if item.get("Secret") else ""
                    })
                report.unlink(missing_ok=True)
            
            elapsed = time.time() - start
            logger.info(f"Gitleaks: {elapsed:.2f}s, {len(findings)} findings")
            return ({"findings": findings, "engine": "gitleaks", "error": None}, elapsed)
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
            
            elapsed = time.time() - start
            logger.info(f"Trivy: {elapsed:.2f}s, {len(findings)} findings")
            return ({"findings": findings, "engine": "trivy", "error": None}, elapsed)
        except Exception as e:
            return ({"findings": [], "engine": "trivy", "error": str(e)}, time.time() - start)

class CodeQLScanner:
    PATTERNS = {
        "sql-injection": {"regex": r'(execute|query|executeQuery)\s*\([^)]*[\{\%\+]', "severity": "CRITICAL", "cwe": "CWE-89",
                         "message": "SQL Injection: User data in SQL query"},
        "command-injection": {"regex": r'(system|exec|Runtime\.getRuntime)\s*\([^)]*[\+\$]', "severity": "CRITICAL", "cwe": "CWE-78",
                             "message": "Command Injection: User data in OS command"},
        "hardcoded-secret": {"regex": r'(password|secret|key|token|API_KEY)\s*=\s*["\'][^"\']{8,}', "severity": "HIGH", "cwe": "CWE-798",
                            "message": "Hardcoded Credential"},
        "weak-crypto": {"regex": r'(md5|sha1|MD5|SHA1)\s*\(', "severity": "MEDIUM", "cwe": "CWE-327",
                       "message": "Weak Cryptography"},
        "path-traversal": {"regex": r'(open|File)\s*\([^)]*[\+]', "severity": "HIGH", "cwe": "CWE-22",
                          "message": "Path Traversal"},
        "insecure-deser": {"regex": r'(pickle\.load|yaml\.load\s*\([^,)]*\)|ObjectInputStream)', "severity": "CRITICAL", "cwe": "CWE-502",
                          "message": "Insecure Deserialization"},
        "xss": {"regex": r'innerHTML\s*=', "severity": "HIGH", "cwe": "CWE-79", "message": "XSS"},
        "eval": {"regex": r'\beval\s*\(', "severity": "CRITICAL", "cwe": "CWE-95", "message": "Code Injection"}
    }
    
    @staticmethod
    def scan(path: str):
        start = time.time()
        try:
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
            
            elapsed = time.time() - start
            logger.info(f"CodeQL: {elapsed:.2f}s, {len(findings)} findings")
            return ({"findings": findings, "engine": "codeql", "error": None}, elapsed)
        except Exception as e:
            return ({"findings": [], "engine": "codeql", "error": str(e)}, time.time() - start)

class EnhancedScanner:
    """Combines CodeQL patterns with specialized format scanners."""
    
    @staticmethod
    def scan(path: str):
        start = time.time()
        try:
            content = FileParser.get_scannable_content(path)
            
            # Run CodeQL patterns
            codeql_findings = []
            lines = content.split('\n')
            
            for pid, pd in CodeQLScanner.PATTERNS.items():
                regex = re.compile(pd["regex"], re.I | re.M)
                for lnum, line in enumerate(lines, 1):
                    if regex.search(line):
                        codeql_findings.append({
                            "id": f"codeql/{pid}", "engine": "codeql", "category": "Deep Analysis",
                            "severity": pd["severity"], "message": pd["message"],
                            "file": Path(path).name, "line_start": lnum,
                            "snippet": line.strip()[:150], "cwe": pd["cwe"]
                        })
            
            # Run specialized scanners
            specialized_findings = SpecializedScanner.scan_file_by_type(path, content)
            
            # Combine results
            all_findings = codeql_findings + specialized_findings
            
            elapsed = time.time() - start
            logger.info(f"Enhanced scan: {elapsed:.2f}s, {len(all_findings)} findings")
            return ({"findings": all_findings, "engine": "enhanced", "error": None}, elapsed)
            
        except Exception as e:
            return ({"findings": [], "engine": "enhanced", "error": str(e)}, time.time() - start)

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
            
            prompt = f"""Security scan - JSON only:

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
                "Update vulnerable dependencies"
            ]
        }

def generate_heatmap(findings):
    categories = ["SAST", "Secrets", "SCA", "Deep Analysis", "Malware Detection"]
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    matrix = {f"{c}_{s}": {"category": c, "severity": s, "count": 0, "risk_weight": 0.0} 
              for c in categories for s in severities}
    
    weights = {"CRITICAL": 1.0, "ERROR": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "WARNING": 0.5, "LOW": 0.25}
    
    for f in findings:
        cat = f.get("category", "SAST")
        sev = "CRITICAL" if f.get("severity") == "ERROR" else "MEDIUM" if f.get("severity") == "WARNING" else f.get("severity", "MEDIUM")
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

# API
@app.get("/")
async def root():
    return {
        "service": "Atlas Synapse Auditor",
        "version": "3.1.0",
        "status": "operational",
        "tagline": "Trust Engine for AI Systems + Malware Detection",
        "engines": {
            "semgrep": shutil.which("semgrep") is not None,
            "gitleaks": shutil.which("gitleaks") is not None,
            "trivy": shutil.which("trivy") is not None,
            "codeql": True,
            "gemini_ai": gemini_client is not None,
            "malware_detection": malware_scanner is not None,
            "yara": MALWARE_DETECTION_AVAILABLE,
            "virustotal": bool(VIRUSTOTAL_API_KEY),
            "heuristic_analysis": MALWARE_DETECTION_AVAILABLE
        },
        "features": {
            "multi_file_upload": True,
            "multi_format_support": True,
            "malware_detection": True,
            "sbom_generation": True,
            "compliance_mapping": True,
            "pdf_reports": True,
            "frameworks": list(ComplianceMapper.FRAMEWORKS.keys())
        },
        "metrics": metrics.stats()
    }

@app.post("/api/scan")
async def scan_code(files: List[UploadFile] = File(...)):
    """Multi-file scan with code vulnerability + malware detection."""
    import zipfile
    
    req_start = time.time()
    scan_id = str(uuid.uuid4())[:8]
    scan_dir = UPLOAD_DIR / scan_id
    scan_dir.mkdir(exist_ok=True)
    
    try:
        files_to_scan = []
        uploaded_filenames = []
        
        # Process uploaded files
        for uploaded_file in files:
            contents = await uploaded_file.read()
            
            if len(contents) > MAX_UPLOAD_MB * 1024 * 1024:
                logger.warning(f"Skipping {uploaded_file.filename} - too large")
                continue
            
            file_path = scan_dir / uploaded_file.filename
            open(file_path, 'wb').write(contents)
            uploaded_filenames.append(uploaded_file.filename)
            
            # Handle ZIP
            if uploaded_file.filename.endswith('.zip'):
                try:
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        code_exts = {'.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.cs',
                                    '.jsx', '.tsx', '.html', '.htm', '.xml', '.pdf', '.docx', '.xlsx',
                                    '.txt', '.md', '.json', '.yaml', '.yml', '.exe', '.dll', '.sh'}
                        
                        for zip_info in zip_ref.filelist:
                            if zip_info.is_dir():
                                continue
                            
                            if Path(zip_info.filename).suffix.lower() in code_exts:
                                zip_ref.extract(zip_info, scan_dir / 'extracted')
                                extracted = scan_dir / 'extracted' / zip_info.filename
                                
                                if extracted.exists() and extracted.stat().st_size < 5 * 1024 * 1024:
                                    files_to_scan.append(extracted)
                        
                        logger.info(f"ZIP {uploaded_file.filename}: {len(files_to_scan)} files")
                except Exception as e:
                    logger.error(f"ZIP extraction failed: {e}")
            else:
                files_to_scan.append(file_path)
        
        if not files_to_scan:
            raise HTTPException(400, "No scannable files found")
        
        # Smart prioritization
        files_to_scan = FilePrioritizer.filter_scannable(files_to_scan, max_files=15)
        
        logger.info(f"Scanning {len(files_to_scan)} files from {len(uploaded_filenames)} uploads")
        
        # Scan all files
        all_findings = []
        files_scanned = []
        malware_stats = {"total_detections": 0, "yara_hits": 0, "heuristic_flags": 0}
        
        if len(files_to_scan) == 1:
            # Single file: full scan
            engines, timings = await _run_scanners(str(files_to_scan[0]))
            for data in engines.values():
                all_findings.extend(data.get("findings", []))
            
            # Add malware detection
            if malware_scanner:
                try:
                    malware_result = malware_scanner.scan_file(str(files_to_scan[0]))
                    all_findings.extend(malware_result.get("findings", []))
                    malware_stats["total_detections"] = malware_result.get("total_detections", 0)
                    malware_stats["yara_hits"] = malware_result.get("scanners_used", {}).get("yara", 0)
                    logger.info(f"🦠 Malware scan: {malware_result['total_detections']} detections")
                except Exception as e:
                    logger.error(f"Malware scan error: {e}")
            
            # Add heuristic analysis
            if MALWARE_DETECTION_AVAILABLE:
                try:
                    heuristic_result = HeuristicAnalyzer.scan(str(files_to_scan[0]))
                    all_findings.extend(heuristic_result.get("findings", []))
                    malware_stats["heuristic_flags"] = heuristic_result.get("total_indicators", 0)
                    logger.info(f"🔍 Heuristic: {heuristic_result['total_indicators']} indicators")
                except Exception as e:
                    logger.error(f"Heuristic analysis error: {e}")
            
            files_scanned.append({"file": files_to_scan[0].name, "findings": len(all_findings)})
        else:
            # Multiple files: fast scan
            async def scan_fast(fpath):
                loop = asyncio.get_event_loop()
                s_task = loop.run_in_executor(executor, SemgrepScanner.scan, str(fpath))
                e_task = loop.run_in_executor(executor, EnhancedScanner.scan, str(fpath))
                
                (s_result, _), (e_result, _) = await asyncio.gather(s_task, e_task)
                
                findings = s_result.get("findings", []) + e_result.get("findings", [])
                
                # Add malware detection for each file
                if malware_scanner:
                    try:
                        malware_result = malware_scanner.scan_file(str(fpath))
                        findings.extend(malware_result.get("findings", []))
                        logger.info(f"🦠 {fpath.name}: {malware_result['total_detections']} malware detections")
                    except Exception as e:
                        logger.error(f"Malware scan error for {fpath.name}: {e}")
                
                return {"file": fpath.name, "findings": len(findings), "findings_list": findings}
            
            results = await asyncio.gather(*[scan_fast(f) for f in files_to_scan])
            
            for r in results:
                files_scanned.append({"file": r["file"], "findings": r["findings"]})
                all_findings.extend(r["findings_list"])
        
        # AI analysis
        file_desc = ", ".join(uploaded_filenames) if len(uploaded_filenames) <= 3 else f"{uploaded_filenames[0]} + {len(uploaded_filenames)-1} more"
        ai_analysis, ai_time = GeminiAnalyzer.analyze(all_findings, len(all_findings), file_desc)
        
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
        metrics.record(total_time, {"ai": ai_time})
        
        result = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "file": file_desc,
            "uploaded_files": uploaded_filenames,
            "is_batch": len(files_to_scan) > 1,
            "files_scanned": len(files_to_scan),
            "file_results": files_scanned,
            "all_findings": all_findings,
            "total_findings": len(all_findings),
            "ai_analysis": ai_analysis,
            "heatmap_data": heatmap,
            "severity_breakdown": sev_breakdown,
            "malware_detection": malware_stats if malware_scanner else None,
            "performance": {"total": round(total_time, 2)},
            "status": "completed",
            "engines": {"semgrep": {"findings": []}, "gitleaks": {"findings": []}, 
                       "trivy": {"findings": []}, "codeql": {"findings": []},
                       "malware": {"findings": []}}
        }
        
        SCAN_RESULTS_STORE[scan_id] = result
        
        # Persist to Supabase (user_id null until user claims after signup)
        if supabase_db:
            try:
                supabase_db.table("scan_results").insert({
                    "scan_id": scan_id,
                    "user_id": None,
                    "file_desc": file_desc,
                    "total_findings": len(all_findings),
                    "risk_score": result["ai_analysis"].get("risk_score"),
                    "risk_level": result["ai_analysis"].get("risk_level"),
                    "result_data": result,
                }).execute()
                logger.info(f"✅ Scan {scan_id} saved to Supabase")
            except Exception as _e:
                logger.warning(f"⚠️  Supabase save failed (non-critical): {_e}")

        # ── Write immutable audit log entry ──────────────────────────────────
        findings_hash = hashlib.sha256(
            json.dumps(all_findings, sort_keys=True, default=str).encode()
        ).hexdigest()
        audit_log.append("scan_completed", {
            "scan_id": scan_id,
            "file_desc": file_desc,
            "files_uploaded": len(uploaded_filenames),
            "files_scanned": len(files_to_scan),
            "total_findings": len(all_findings),
            "severity_breakdown": sev_breakdown,
            "risk_score": ai_analysis.get("risk_score"),
            "risk_level": ai_analysis.get("risk_level"),
            "malware_detected": malware_stats.get("total_detections", 0) > 0,
            "findings_hash": findings_hash,
            "duration_seconds": round(total_time, 2),
        })

        logger.info(f"✅ Scan {scan_id}: {len(uploaded_filenames)} uploads, {len(files_to_scan)} scanned, {len(all_findings)} findings")
        
        return JSONResponse(content=result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Scan failed: {e}", exc_info=True)
        raise HTTPException(500, str(e))
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in SCAN_RESULTS_STORE:
        raise HTTPException(404, "Scan not found")
    return JSONResponse(content=SCAN_RESULTS_STORE[scan_id])

@app.get("/api/scan/{scan_id}/status")
async def get_status(scan_id: str):
    if scan_id in SCAN_RESULTS_STORE:
        return JSONResponse(content={"status": "completed", "result": SCAN_RESULTS_STORE[scan_id]})
    
    task_status = background_manager.get_status(scan_id)
    if task_status["status"] == "not_found":
        raise HTTPException(404, "Scan not found")
    
    return JSONResponse(content=task_status)

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

@app.get("/api/scan/{scan_id}/sbom")
async def get_sbom(scan_id: str):
    if scan_id not in SCAN_RESULTS_STORE:
        raise HTTPException(404, "Scan not found")
    sbom = SBOMGenerator.generate(SCAN_RESULTS_STORE[scan_id])
    return JSONResponse(content=sbom, headers={"Content-Disposition": f"attachment; filename=atlas-sbom-{scan_id}.json"})

@app.get("/api/scan/{scan_id}/compliance")
async def get_compliance(scan_id: str):
    if scan_id not in SCAN_RESULTS_STORE:
        raise HTTPException(404, "Scan not found")
    compliance = ComplianceMapper.map_findings_to_compliance(SCAN_RESULTS_STORE[scan_id]["all_findings"])
    return JSONResponse(content=compliance)

@app.get("/api/scan/{scan_id}/report/markdown")
async def get_md_report(scan_id: str):
    if scan_id not in SCAN_RESULTS_STORE:
        raise HTTPException(404, "Scan not found")
    scan = SCAN_RESULTS_STORE[scan_id]
    compliance = ComplianceMapper.map_findings_to_compliance(scan["all_findings"])
    report = ReportGenerator.generate_executive_markdown(scan, compliance)
    return JSONResponse(content={"report": report, "format": "markdown"})

@app.get("/api/scan/{scan_id}/report/html")
async def get_html_report(scan_id: str):
    if scan_id not in SCAN_RESULTS_STORE:
        raise HTTPException(404, "Scan not found")
    scan = SCAN_RESULTS_STORE[scan_id]
    compliance = ComplianceMapper.map_findings_to_compliance(scan["all_findings"])
    html = ReportGenerator.generate_html_report(scan, compliance)
    return HTMLResponse(content=html)

@app.get("/api/compliance/frameworks")
async def list_frameworks():
    return JSONResponse(content={
        "frameworks": [{"id": k, "name": v.get("name", k)} for k, v in ComplianceMapper.FRAMEWORKS.items()],
        "total": len(ComplianceMapper.FRAMEWORKS)
    })

# ── Immutable Audit Log endpoints ────────────────────────────────────────────

@app.get("/api/audit-log")
async def get_audit_log(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Return paginated immutable audit log entries (newest first)."""
    entries, total = audit_log.get_entries(limit=limit, offset=offset)
    return JSONResponse(content={
        "entries": entries,
        "total": total,
        "limit": limit,
        "offset": offset,
    })

@app.get("/api/audit-log/verify")
async def verify_audit_log():
    """Verify the cryptographic integrity of the entire audit log chain."""
    result = audit_log.verify_chain()
    status_code = 200 if result["valid"] else 409
    return JSONResponse(content=result, status_code=status_code)

# ── CI/CD Plugin endpoints ────────────────────────────────────────────────────

_GITHUB_ACTIONS_TEMPLATE = """\
# Atlas Synapse Aegis Prime Auditor — GitHub Actions CI plugin
# Add this file to .github/workflows/aegis-security-scan.yml in your repository.
name: Aegis Security Scan

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: read
  pull-requests: write

jobs:
  aegis-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Aegis Prime Auditor
        id: scan
        env:
          AEGIS_BACKEND: ${{ secrets.AEGIS_BACKEND_URL }}
        run: |
          RESULT=$(curl -s -X POST "$AEGIS_BACKEND/api/scan" \\
            $(find . -name "*.py" -o -name "*.js" -o -name "*.ts" | head -20 | xargs -I{} sh -c 'echo "-F files=@{}"') \\
            -w "\\nHTTP_%{http_code}")
          HTTP_CODE=$(echo "$RESULT" | tail -1 | sed 's/HTTP_//')
          BODY=$(echo "$RESULT" | head -n -1)
          echo "scan_result=$BODY" >> $GITHUB_OUTPUT
          RISK=$(echo "$BODY" | jq -r '.ai_analysis.risk_level // "UNKNOWN"')
          SCORE=$(echo "$BODY" | jq -r '.ai_analysis.risk_score // 0')
          echo "risk_level=$RISK" >> $GITHUB_OUTPUT
          echo "risk_score=$SCORE" >> $GITHUB_OUTPUT

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const risk  = '${{ steps.scan.outputs.risk_level }}';
            const score = '${{ steps.scan.outputs.risk_score }}';
            const emoji = risk === 'CRITICAL' ? '🔴' : risk === 'HIGH' ? '🟠' : risk === 'MEDIUM' ? '🟡' : '🟢';
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## ${emoji} Aegis Security Scan\\n**Risk:** ${risk} (${score}/100)\\n\\n*Powered by Atlas Synapse Aegis Prime Auditor*`
            });
"""

_GITLAB_CI_TEMPLATE = """\
# Atlas Synapse Aegis Prime Auditor — GitLab CI plugin
# Merge this block into your .gitlab-ci.yml

aegis-security-scan:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install httpie --quiet
  script:
    - >
      http --ignore-stdin POST "$AEGIS_BACKEND_URL/api/scan"
      $(find . -name "*.py" -o -name "*.js" -o -name "*.ts" | head -20 |
        xargs -I{} sh -c 'printf "files@{}\\n"') > scan_result.json
    - RISK=$(jq -r '.ai_analysis.risk_level // "UNKNOWN"' scan_result.json)
    - SCORE=$(jq -r '.ai_analysis.risk_score // 0' scan_result.json)
    - echo "Risk level $RISK ($SCORE/100)"
    - if [ "$RISK" = "CRITICAL" ]; then exit 1; fi
  artifacts:
    paths:
      - scan_result.json
    expire_in: 7 days
  variables:
    AEGIS_BACKEND_URL: ""   # Set this in GitLab CI/CD Variables
"""

_JENKINS_TEMPLATE = """\
// Atlas Synapse Aegis Prime Auditor — Jenkins Pipeline plugin
// Add this stage to your Jenkinsfile

stage('Aegis Security Scan') {
    steps {
        script {
            def backendUrl = env.AEGIS_BACKEND_URL ?: 'http://localhost:10000'
            def files = sh(
                script: "find . -name '*.py' -o -name '*.js' -o -name '*.ts' | head -20",
                returnStdout: true
            ).trim().split('\\n')

            def formArgs = files.collect { "-F 'files=@${it}'" }.join(' ')

            def response = sh(
                script: "curl -s -X POST '${backendUrl}/api/scan' ${formArgs}",
                returnStdout: true
            )
            def result = readJSON text: response

            def riskLevel = result.ai_analysis?.risk_level ?: 'UNKNOWN'
            def riskScore = result.ai_analysis?.risk_score ?: 0

            echo "Aegis Scan — Risk: ${riskLevel} (${riskScore}/100)"
            currentBuild.description = "Aegis: ${riskLevel} ${riskScore}/100"

            if (riskLevel == 'CRITICAL') {
                error("CRITICAL security risk detected by Aegis. Build blocked.")
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'aegis-scan-*.json', allowEmptyArchive: true
        }
    }
}
"""


@app.get("/api/ci-cd/github-actions", response_class=PlainTextResponse)
async def cicd_github_actions():
    """Return a ready-to-use GitHub Actions workflow YAML for Aegis scans."""
    return PlainTextResponse(content=_GITHUB_ACTIONS_TEMPLATE, media_type="text/yaml")


@app.get("/api/ci-cd/gitlab-ci", response_class=PlainTextResponse)
async def cicd_gitlab_ci():
    """Return a ready-to-use GitLab CI job block for Aegis scans."""
    return PlainTextResponse(content=_GITLAB_CI_TEMPLATE, media_type="text/yaml")


@app.get("/api/ci-cd/jenkins", response_class=PlainTextResponse)
async def cicd_jenkins():
    """Return a ready-to-use Jenkins Pipeline stage for Aegis scans."""
    return PlainTextResponse(content=_JENKINS_TEMPLATE, media_type="text/plain")


@app.get("/api/ci-cd")
async def cicd_index():
    """List available CI/CD plugin templates."""
    return JSONResponse(content={
        "plugins": [
            {"name": "GitHub Actions", "endpoint": "/api/ci-cd/github-actions", "format": "yaml"},
            {"name": "GitLab CI",      "endpoint": "/api/ci-cd/gitlab-ci",      "format": "yaml"},
            {"name": "Jenkins",        "endpoint": "/api/ci-cd/jenkins",         "format": "groovy"},
        ]
    })


if __name__ == "__main__":
    import uvicorn
    
    host = os.getenv("AEGIS_HOST", "0.0.0.0")
    port = int(os.getenv("AEGIS_PORT", "10000"))
    
    print("="*80)
    print("ATLAS SYNAPSE AUDITOR v3.1 - MALWARE DETECTION EDITION")
    print("="*80)
    print(f"🚀 http://{host}:{port}")
    print(f"📊 Docs: http://{host}:{port}/docs")
    print(f"🔧 Gemini: {'✅' if gemini_client else '❌'}")
    print(f"🦠 Malware Detection: {'✅' if malware_scanner else '❌'}")
    print(f"🔍 YARA Rules: {'✅' if MALWARE_DETECTION_AVAILABLE else '❌'}")
    print(f"☁️  VirusTotal: {'✅' if VIRUSTOTAL_API_KEY else '❌ (optional)'}")
    print(f"📁 Multi-File + Multi-Format: ✅")
    print(f"🎯 Trust Engine for AI Systems")
    print("="*80)
    
    uvicorn.run("orchestrator:app", host=host, port=port, reload=False, log_level="info")
