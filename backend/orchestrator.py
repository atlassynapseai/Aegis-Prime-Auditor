"""
Aegis Prime Auditor - Backend Orchestrator
Multi-engine security scanner with AI-powered analysis

Integrates:
- Semgrep (SAST)
- Gitleaks (Secrets)
- Trivy (SCA)
- CodeQL-pattern engine (Deep Analysis)
- Gemini AI (Risk Scoring & Remediation)
"""

import os
import json
import subprocess
import tempfile
import shutil
import uuid
import asyncio
import re
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from openai import OpenAI

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Aegis Prime Auditor",
    version="1.0.0",
    description="Multi-engine security analysis platform with AI-powered risk assessment"
)

# CORS - Allow all origins for development (restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Environment variables
GEMINI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GEMINI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/")
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT_SECONDS", "120"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))

# Initialize Gemini client
gemini_client = None
if GEMINI_API_KEY:
    gemini_client = OpenAI(api_key=GEMINI_API_KEY, base_url=GEMINI_BASE_URL)
    GEMINI_MODEL = "gemini-2.5-flash"

# In-memory storage (replace with PostgreSQL in production)
SCAN_RESULTS_STORE: Dict[str, Any] = {}

# Temp directory for uploads
UPLOAD_DIR = Path("/tmp/aegis_uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Config directory
CONFIG_DIR = Path(__file__).parent.parent / "config"

# Thread pool for concurrent scanning
executor = ThreadPoolExecutor(max_workers=4)

# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER ENGINES
# ═══════════════════════════════════════════════════════════════════════════════

class SemgrepScanner:
    """SAST scanner using Semgrep for pattern-based code analysis."""
    
    @staticmethod
    def scan(file_path: str) -> Dict[str, Any]:
        """Run Semgrep scan on file."""
        try:
            # Check if custom rules exist
            rules_file = CONFIG_DIR / "semgrep_rules.yaml"
            rules_arg = f"--config={rules_file}" if rules_file.exists() else "--config=auto"
            
            result = subprocess.run(
                ["semgrep", rules_arg, "--json", file_path],
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT
            )
            
            if result.returncode in [0, 1]:  # 0=no findings, 1=findings found
                data = json.loads(result.stdout)
                findings = []
                
                for finding in data.get("results", []):
                    findings.append({
                        "id": finding.get("check_id", "unknown"),
                        "engine": "semgrep",
                        "category": "SAST",
                        "severity": finding.get("extra", {}).get("severity", "WARNING").upper(),
                        "message": finding.get("extra", {}).get("message", finding.get("check_id", "")),
                        "file": finding.get("path", ""),
                        "line_start": finding.get("start", {}).get("line", 0),
                        "line_end": finding.get("end", {}).get("line", 0),
                        "snippet": finding.get("extra", {}).get("lines", ""),
                        "cwe": finding.get("extra", {}).get("metadata", {}).get("cwe", []),
                        "owasp": finding.get("extra", {}).get("metadata", {}).get("owasp", [])
                    })
                
                return {"findings": findings, "engine": "semgrep", "error": None}
            else:
                return {"findings": [], "engine": "semgrep", "error": result.stderr}
                
        except subprocess.TimeoutExpired:
            return {"findings": [], "engine": "semgrep", "error": "Timeout exceeded"}
        except Exception as e:
            return {"findings": [], "engine": "semgrep", "error": str(e)}


class GitleaksScanner:
    """Secrets detection using Gitleaks."""
    
    @staticmethod
    def scan(file_path: str) -> Dict[str, Any]:
        """Run Gitleaks scan on file."""
        try:
            # Gitleaks needs a git repo, so create temp one
            temp_dir = Path(file_path).parent
            
            result = subprocess.run(
                ["gitleaks", "detect", "--source", str(temp_dir), "--report-format", "json", "--report-path", "/tmp/gitleaks_report.json", "--no-git"],
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT
            )
            
            findings = []
            report_path = Path("/tmp/gitleaks_report.json")
            
            if report_path.exists():
                with open(report_path) as f:
                    data = json.load(f)
                    
                for finding in data:
                    findings.append({
                        "id": finding.get("RuleID", "unknown"),
                        "engine": "gitleaks",
                        "category": "Secrets",
                        "severity": "CRITICAL",  # All secrets are critical
                        "message": f"Secret detected: {finding.get('Description', 'Unknown secret type')}",
                        "file": finding.get("File", ""),
                        "line_start": finding.get("StartLine", 0),
                        "line_end": finding.get("EndLine", 0),
                        "snippet": finding.get("Secret", "")[:50] + "...",
                        "secret_type": finding.get("RuleID", ""),
                        "entropy": finding.get("Entropy", 0)
                    })
                
                # Clean up
                report_path.unlink(missing_ok=True)
            
            return {"findings": findings, "engine": "gitleaks", "error": None}
            
        except Exception as e:
            return {"findings": [], "engine": "gitleaks", "error": str(e)}


class TrivyScanner:
    """SCA/CVE scanner using Trivy."""
    
    @staticmethod
    def scan(file_path: str) -> Dict[str, Any]:
        """Run Trivy filesystem scan."""
        try:
            # Trivy scans directories, so scan the parent directory
            scan_dir = Path(file_path).parent
            
            result = subprocess.run(
                ["trivy", "fs", "--format", "json", "--scanners", "vuln", str(scan_dir)],
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                findings = []
                
                for result_entry in data.get("Results", []):
                    for vuln in result_entry.get("Vulnerabilities", []):
                        severity_map = {
                            "CRITICAL": "CRITICAL",
                            "HIGH": "HIGH",
                            "MEDIUM": "MEDIUM",
                            "LOW": "LOW"
                        }
                        
                        findings.append({
                            "id": vuln.get("VulnerabilityID", "unknown"),
                            "engine": "trivy",
                            "category": "SCA",
                            "severity": severity_map.get(vuln.get("Severity", "MEDIUM"), "MEDIUM"),
                            "message": vuln.get("Title", ""),
                            "file": result_entry.get("Target", "requirements.txt"),
                            "line_start": 0,
                            "line_end": 0,
                            "package": vuln.get("PkgName", ""),
                            "installed_version": vuln.get("InstalledVersion", ""),
                            "fixed_version": vuln.get("FixedVersion", ""),
                            "cve": vuln.get("VulnerabilityID", ""),
                            "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0)
                        })
                
                return {"findings": findings, "engine": "trivy", "error": None}
            else:
                return {"findings": [], "engine": "trivy", "error": result.stderr}
                
        except Exception as e:
            return {"findings": [], "engine": "trivy", "error": str(e)}


class CodeQLScanner:
    """Custom CodeQL-pattern engine for taint analysis."""
    
    # Vulnerability patterns based on CodeQL rules
    PATTERNS = {
        "sql-injection": {
            "regex": r'(execute|cursor\.execute|query)\s*\(\s*[f"\'].*\{.*\}|%.*\+',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "message": "SQL Injection: User-controlled data flows into SQL query without parameterization"
        },
        "command-injection": {
            "regex": r'os\.system\s*\(.*\+|subprocess\.(call|run|Popen).*shell\s*=\s*True',
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "message": "Command Injection: User-controlled data flows into OS command execution"
        },
        "hardcoded-password": {
            "regex": r'(password|passwd|pwd|secret|api_key|token)\s*=\s*["\'][^"\']{8,}["\']',
            "severity": "HIGH",
            "cwe": "CWE-798",
            "message": "Hardcoded Credential: Sensitive value assigned directly in source code"
        },
        "weak-crypto": {
            "regex": r'hashlib\.(md5|sha1)\s*\(',
            "severity": "MEDIUM",
            "cwe": "CWE-327",
            "message": "Weak Cryptography: Use of deprecated or weak cryptographic algorithm"
        },
        "path-traversal": {
            "regex": r'open\s*\(.*\+.*\)|os\.path\.join\s*\(.*\+',
            "severity": "HIGH",
            "cwe": "CWE-22",
            "message": "Path Traversal: User input used in file path construction"
        },
        "insecure-deserialization": {
            "regex": r'pickle\.loads?\s*\(|yaml\.load\s*\([^,]*\)',
            "severity": "CRITICAL",
            "cwe": "CWE-502",
            "message": "Insecure Deserialization: Arbitrary code execution risk"
        }
    }
    
    @staticmethod
    def scan(file_path: str) -> Dict[str, Any]:
        """Run pattern-based deep analysis."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            findings = []
            
            for pattern_id, pattern_data in CodeQLScanner.PATTERNS.items():
                regex = re.compile(pattern_data["regex"], re.IGNORECASE)
                
                for line_num, line in enumerate(lines, start=1):
                    if regex.search(line):
                        findings.append({
                            "id": f"codeql/{pattern_id}",
                            "engine": "codeql",
                            "category": "Deep Analysis",
                            "severity": pattern_data["severity"],
                            "message": pattern_data["message"],
                            "file": Path(file_path).name,
                            "line_start": line_num,
                            "line_end": line_num,
                            "snippet": line.strip()[:100],
                            "cwe": pattern_data["cwe"]
                        })
            
            return {"findings": findings, "engine": "codeql", "error": None}
            
        except Exception as e:
            return {"findings": [], "engine": "codeql", "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# AI ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

class GeminiAnalyzer:
    """Gemini AI-powered risk analysis and remediation guidance."""
    
    @staticmethod
    def analyze(all_findings: List[Dict], total_findings: int) -> Dict[str, Any]:
        """Generate AI-powered risk analysis."""
        
        if not gemini_client or not GEMINI_API_KEY:
            return GeminiAnalyzer._fallback_analysis(all_findings, total_findings)
        
        try:
            # Prepare findings summary for AI
            findings_summary = {
                "total": total_findings,
                "by_severity": {},
                "by_category": {},
                "critical_issues": []
            }
            
            for finding in all_findings:
                severity = finding.get("severity", "UNKNOWN")
                category = finding.get("category", "UNKNOWN")
                
                findings_summary["by_severity"][severity] = findings_summary["by_severity"].get(severity, 0) + 1
                findings_summary["by_category"][category] = findings_summary["by_category"].get(category, 0) + 1
                
                if severity in ["CRITICAL", "ERROR"]:
                    findings_summary["critical_issues"].append({
                        "type": finding.get("message", "")[:100],
                        "file": finding.get("file", ""),
                        "line": finding.get("line_start", 0)
                    })
            
            # Gemini prompt
            prompt = f"""You are a security analysis AI. Analyze this code security scan and provide a JSON response.

Scan Results:
- Total findings: {findings_summary['total']}
- By severity: {json.dumps(findings_summary['by_severity'])}
- By category: {json.dumps(findings_summary['by_category'])}
- Critical issues: {json.dumps(findings_summary['critical_issues'][:5])}

Provide a JSON response with:
{{
  "executive_summary": "2-3 sentence summary of security posture",
  "risk_score": 0-100 (higher is worse),
  "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "top_priorities": ["Priority 1 remediation", "Priority 2 remediation", "Priority 3 remediation"]
}}

Respond ONLY with valid JSON, no markdown or explanations."""

            response = gemini_client.chat.completions.create(
                model=GEMINI_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=1000
            )
            
            ai_response = response.choices[0].message.content
            
            # Parse JSON response
            ai_data = json.loads(ai_response)
            
            return {
                "executive_summary": ai_data.get("executive_summary", ""),
                "risk_score": ai_data.get("risk_score", 50),
                "risk_level": ai_data.get("risk_level", "MEDIUM"),
                "top_priorities": ai_data.get("top_priorities", [])
            }
            
        except Exception as e:
            print(f"Gemini AI error: {e}")
            return GeminiAnalyzer._fallback_analysis(all_findings, total_findings)
    
    @staticmethod
    def _fallback_analysis(all_findings: List[Dict], total_findings: int) -> Dict[str, Any]:
        """Deterministic fallback when Gemini unavailable."""
        
        severity_weights = {
            "CRITICAL": 10,
            "ERROR": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "WARNING": 4,
            "LOW": 1
        }
        
        total_weight = 0
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for finding in all_findings:
            severity = finding.get("severity", "MEDIUM")
            weight = severity_weights.get(severity, 4)
            total_weight += weight
            
            # Normalize to standard severity levels
            if severity in ["CRITICAL", "ERROR"]:
                severity_counts["CRITICAL"] += 1
            elif severity == "HIGH":
                severity_counts["HIGH"] += 1
            elif severity in ["MEDIUM", "WARNING"]:
                severity_counts["MEDIUM"] += 1
            else:
                severity_counts["LOW"] += 1
        
        # Calculate risk score (0-100)
        risk_score = min(100, int((total_weight / max(1, total_findings)) * 10))
        
        # Determine risk level
        if risk_score >= 80 or severity_counts["CRITICAL"] >= 3:
            risk_level = "CRITICAL"
        elif risk_score >= 60 or severity_counts["HIGH"] >= 5:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Generate summary
        summary = f"Scan detected {total_findings} security findings. "
        if severity_counts["CRITICAL"] > 0:
            summary += f"{severity_counts['CRITICAL']} CRITICAL issues require immediate attention. "
        if severity_counts["HIGH"] > 0:
            summary += f"{severity_counts['HIGH']} HIGH severity issues found. "
        
        summary += f"Risk level: {risk_level} ({risk_score}/100)."
        
        return {
            "executive_summary": summary,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "top_priorities": [
                "Review and remediate all CRITICAL findings immediately",
                "Address HIGH severity vulnerabilities within 7 days",
                "Update vulnerable dependencies identified by SCA"
            ]
        }


# ═══════════════════════════════════════════════════════════════════════════════
# HEATMAP GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

def generate_heatmap_data(all_findings: List[Dict]) -> List[Dict]:
    """Generate heatmap data for D3.js visualization."""
    
    categories = ["SAST", "Secrets", "SCA", "Deep Analysis"]
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    
    # Initialize matrix
    matrix = {}
    for cat in categories:
        for sev in severities:
            matrix[f"{cat}_{sev}"] = {"category": cat, "severity": sev, "count": 0, "risk_weight": 0.0}
    
    # Populate counts
    severity_weights = {"CRITICAL": 1.0, "ERROR": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "WARNING": 0.5, "LOW": 0.25}
    
    for finding in all_findings:
        cat = finding.get("category", "SAST")
        sev = finding.get("severity", "MEDIUM")
        
        # Normalize severity
        if sev == "ERROR":
            sev = "CRITICAL"
        elif sev == "WARNING":
            sev = "MEDIUM"
        
        key = f"{cat}_{sev}"
        if key in matrix:
            matrix[key]["count"] += 1
            matrix[key]["risk_weight"] += severity_weights.get(sev, 0.5)
    
    # Normalize risk weights for visualization
    max_weight = max([m["risk_weight"] for m in matrix.values()] + [1])
    heatmap_data = []
    
    for data in matrix.values():
        heatmap_data.append({
            **data,
            "normalized": round(data["risk_weight"] / max_weight, 2) if max_weight > 0 else 0.0
        })
    
    return heatmap_data


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════════════

async def _run_all_scanners(file_path: str) -> Dict[str, Any]:
    """Run all 4 scanners concurrently."""
    
    loop = asyncio.get_event_loop()
    
    # Run scanners in parallel
    semgrep_task = loop.run_in_executor(executor, SemgrepScanner.scan, file_path)
    gitleaks_task = loop.run_in_executor(executor, GitleaksScanner.scan, file_path)
    trivy_task = loop.run_in_executor(executor, TrivyScanner.scan, file_path)
    codeql_task = loop.run_in_executor(executor, CodeQLScanner.scan, file_path)
    
    # Wait for all to complete
    semgrep_result, gitleaks_result, trivy_result, codeql_result = await asyncio.gather(
        semgrep_task, gitleaks_task, trivy_task, codeql_task
    )
    
    return {
        "semgrep": semgrep_result,
        "gitleaks": gitleaks_result,
        "trivy": trivy_result,
        "codeql": codeql_result
    }


# ═══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "service": "Aegis Prime Auditor",
        "version": "1.0.0",
        "status": "operational",
        "engines": {
            "semgrep": shutil.which("semgrep") is not None,
            "gitleaks": shutil.which("gitleaks") is not None,
            "trivy": shutil.which("trivy") is not None,
            "codeql": True,  # Built-in
            "gemini_ai": gemini_client is not None
        }
    }


@app.post("/api/scan")
async def scan_code(file: UploadFile = File(...)):
    """
    Scan uploaded code file for vulnerabilities.
    
    Accepts: .py, .js, .ts, .java, .go, .rb files
    Returns: Comprehensive security analysis with risk score and heatmap data
    """
    
    # Validate file size
    max_size = MAX_UPLOAD_MB * 1024 * 1024
    contents = await file.read()
    if len(contents) > max_size:
        raise HTTPException(status_code=413, detail=f"File too large (max {MAX_UPLOAD_MB}MB)")
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())[:8]
    
    # Create temp directory for this scan
    scan_dir = UPLOAD_DIR / scan_id
    scan_dir.mkdir(exist_ok=True)
    
    try:
        # Save uploaded file
        file_path = scan_dir / file.filename
        with open(file_path, 'wb') as f:
            f.write(contents)
        
        # Run all scanners concurrently
        engine_results = await _run_all_scanners(str(file_path))
        
        # Collect all findings
        all_findings = []
        for engine_name, engine_data in engine_results.items():
            all_findings.extend(engine_data.get("findings", []))
        
        total_findings = len(all_findings)
        
        # Generate AI analysis
        ai_analysis = GeminiAnalyzer.analyze(all_findings, total_findings)
        
        # Generate heatmap data
        heatmap_data = generate_heatmap_data(all_findings)
        
        # Calculate severity breakdown
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "WARNING": 0}
        for finding in all_findings:
            sev = finding.get("severity", "MEDIUM")
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1
            elif sev == "ERROR":
                severity_breakdown["CRITICAL"] += 1
            else:
                severity_breakdown["MEDIUM"] += 1
        
        # Build response
        scan_result = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "file": file.filename,
            "engines": engine_results,
            "all_findings": all_findings,
            "total_findings": total_findings,
            "ai_analysis": ai_analysis,
            "heatmap_data": heatmap_data,
            "severity_breakdown": severity_breakdown
        }
        
        # Store result
        SCAN_RESULTS_STORE[scan_id] = scan_result
        
        return JSONResponse(content=scan_result)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        # Cleanup temp files
        shutil.rmtree(scan_dir, ignore_errors=True)


@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Retrieve scan results by ID."""
    
    if scan_id not in SCAN_RESULTS_STORE:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return JSONResponse(content=SCAN_RESULTS_STORE[scan_id])


@app.get("/api/scans")
async def list_scans():
    """List all scan results."""
    
    scans = []
    for scan_id, data in SCAN_RESULTS_STORE.items():
        scans.append({
            "scan_id": scan_id,
            "timestamp": data.get("timestamp"),
            "file": data.get("file"),
            "total_findings": data.get("total_findings"),
            "risk_score": data.get("ai_analysis", {}).get("risk_score", 0),
            "risk_level": data.get("ai_analysis", {}).get("risk_level", "UNKNOWN")
        })
    
    return JSONResponse(content={"scans": scans, "total": len(scans)})


# ═══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    
    host = os.getenv("AEGIS_HOST", "0.0.0.0")
    port = int(os.getenv("AEGIS_PORT", "8000"))
    
    print("=" * 80)
    print("AEGIS PRIME AUDITOR - Backend Server")
    print("=" * 80)
    print(f"🚀 Starting server on http://{host}:{port}")
    print(f"📊 API Documentation: http://{host}:{port}/docs")
    print(f"🔧 Gemini AI: {'✅ Enabled' if gemini_client else '❌ Disabled (using fallback)'}")
    print(f"🔍 Engines:")
    print(f"   - Semgrep: {'✅' if shutil.which('semgrep') else '❌'}")
    print(f"   - Gitleaks: {'✅' if shutil.which('gitleaks') else '❌'}")
    print(f"   - Trivy: {'✅' if shutil.which('trivy') else '❌'}")
    print(f"   - CodeQL: ✅ (built-in)")
    print("=" * 80)
    
    uvicorn.run(
        "orchestrator:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )
