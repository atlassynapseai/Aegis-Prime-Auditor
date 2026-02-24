# 🛡️ Aegis Prime Auditor

**Multi-Engine AI-Powered Security Analysis Platform**

Built by [Atlas Synapse LLC](https://atlassynapseai.com) - The Sovereign Standard for Enterprise AI Systems

---

## 🎯 What It Does

Aegis Prime Auditor performs comprehensive security analysis of code using **4 independent scanning engines** running concurrently, then synthesizes results through **Gemini AI** into actionable intelligence.

**One upload. Four engines. One score.**

### Scanning Engines

| Engine | Type | What It Detects |
|--------|------|-----------------|
| **Semgrep** | SAST | SQL injection, command injection, hardcoded secrets, weak crypto |
| **Gitleaks** | Secrets | API keys, AWS credentials, tokens, passwords |
| **Trivy** | SCA | CVEs in dependencies, vulnerable packages |
| **CodeQL** | Deep Analysis | Taint tracking, data flow vulnerabilities |

### AI Analysis (Gemini 2.5 Flash)

- **Risk Scoring:** 0-100 scale with CRITICAL/HIGH/MEDIUM/LOW classification
- **Executive Summary:** Plain-English security posture assessment
- **Prioritized Remediation:** Top 3 actions ranked by impact
- **Heatmap Data:** Category × Severity matrix for visualization

---

## 🚀 Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/atlassynapseai/Aegis-Prime-Auditor.git
cd Aegis-Prime-Auditor
```

### 2. Backend Setup (5 minutes)

```bash
# Install Python dependencies
cd backend
pip install -r requirements.txt

# Install scanning engines
pip install semgrep
# [Download Gitleaks and Trivy - see DEPLOYMENT.md]

# Configure environment
cp config/.env.example .env
nano .env  # Add your Gemini API key

# Run server
python orchestrator.py
```

### 3. Frontend Setup (3 minutes)

```bash
# Install Node dependencies
cd frontend
npm install

# Run development server
npm run dev
```

**Access at:** http://localhost:5173

### 4. Test the System

Upload `tests/test_vulnerable.py` and click "INITIATE SCAN"

**Expected:** 29+ security findings detected in 15-45 seconds

---

## 📊 Sample Results

**Scanning a vulnerable Python file:**

```json
{
  "scan_id": "a3f2c1b9",
  "total_findings": 29,
  "ai_analysis": {
    "risk_score": 67,
    "risk_level": "HIGH",
    "executive_summary": "Scan detected 29 security findings. 5 CRITICAL issues require immediate attention. 4 HIGH severity issues found. Risk level: HIGH (67/100).",
    "top_priorities": [
      "Review and remediate all CRITICAL findings immediately",
      "Address HIGH severity vulnerabilities within 7 days",
      "Update vulnerable dependencies identified by SCA"
    ]
  },
  "severity_breakdown": {
    "CRITICAL": 5,
    "HIGH": 5,
    "MEDIUM": 15,
    "LOW": 4
  }
}
```

---

## 🏗️ Architecture

### Backend (FastAPI)

**Concurrent Execution Model:**
```python
async def _run_all_scanners(file_path):
    # Run all 4 engines in parallel using ThreadPoolExecutor
    semgrep_task = loop.run_in_executor(executor, SemgrepScanner.scan, file_path)
    gitleaks_task = loop.run_in_executor(executor, GitleaksScanner.scan, file_path)
    trivy_task = loop.run_in_executor(executor, TrivyScanner.scan, file_path)
    codeql_task = loop.run_in_executor(executor, CodeQLScanner.scan, file_path)
    
    return await asyncio.gather(semgrep_task, gitleaks_task, trivy_task, codeql_task)
```

**AI Fallback:**
If Gemini API is unavailable, the system uses a deterministic risk scoring algorithm based on severity-weighted calculations.

### Frontend (React + Vite)

- **Zero external UI libraries** - all components built inline
- **Tailwind CSS** for styling
- **Responsive design** - works on mobile and desktop
- **Real-time updates** - shows scan progress

---

## 🔧 API Endpoints

### `POST /api/scan`

Upload a code file for analysis.

**Request:**
```bash
curl -X POST http://localhost:8000/api/scan \
  -F "file=@vulnerable_script.py"
```

**Response:** Complete scan results with findings, risk score, and heatmap data

### `GET /api/scan/{scan_id}`

Retrieve previous scan results by ID.

### `GET /api/scans`

List all scan results.

### `GET /docs`

Interactive API documentation (Swagger UI)

---

## 📈 Performance Benchmarks

**Target Performance (from institutional brief):**

| Metric | Target | Current |
|--------|--------|---------|
| Scan time (1K lines) | <15s | ~8-12s ✅ |
| Scan time (10K lines) | <30s | ~25-40s ⚠️ |
| AI response time | <2s | ~1.5-3s ⚠️ |
| Concurrent scans | 4+ | Limited by thread pool |

**Optimization opportunities** (your assignment):
1. Gemini prompt engineering for faster responses
2. Process pool vs thread pool for scanner parallelism
3. Scanner-specific timeout tuning

---

## 🎓 White-Labeling for Atlas Synapse

**To rebrand as "Atlas Synapse Auditor":**

1. **Frontend:** Replace "AEGIS PRIME" in `frontend/src/App.tsx`
2. **Backend:** Update `app = FastAPI(title=...)` in `backend/orchestrator.py`
3. **Colors:** Change blue (`#3b82f6`) to Atlas brand color in `App.tsx`
4. **Logo:** Replace shield SVG with Atlas logo
5. **Config:** Rename rule IDs from `aegis-*` to `atlas-*` in `config/semgrep_rules.yaml`

---

## 📜 License

**Open Source Components:**
- Semgrep: LGPL-2.1
- Gitleaks: MIT
- Trivy: Apache-2.0
- React/Vite/Tailwind: MIT

**Custom Code:** Proprietary - Atlas Synapse LLC

---

## 🤝 Contributing

This is Atlas Synapse's internal security infrastructure. For the founding team:

**Steve George (CSO):** Backend optimization, AI tuning, latency monitoring  
**Sathvik Pittala (CPO):** Architecture review, data pipeline, scalability  
**Max Kiefer (CRO):** Compliance audit, license review, regulatory mapping

---

## 📞 Contact

**Atlas Synapse LLC**  
Email: contact@atlassynapseai.com  
GitHub: https://github.com/atlassynapseai

---

**Built to set the trust layer of the AI era.**
