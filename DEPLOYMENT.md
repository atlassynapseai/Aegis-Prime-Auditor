# Aegis Prime Auditor - Complete Deployment Guide

## 🎯 System Overview

**Aegis Prime Auditor** is a multi-engine security scanning platform that combines:
- **4 Scanning Engines:** Semgrep (SAST), Gitleaks (Secrets), Trivy (SCA), CodeQL (Deep Analysis)
- **AI-Powered Analysis:** Gemini 2.5 Flash for risk scoring and remediation guidance
- **Interactive Dashboard:** React frontend with D3.js-inspired heatmap visualization

**Deployment Architecture:**
- **Frontend:** GitHub Pages (static site)
- **Backend:** GitHub Codespaces (persistent API server)

---

## 📋 Prerequisites

### Required Software
- **Node.js** 18+ (for frontend)
- **Python** 3.11+ (for backend)
- **Git** (for version control)
- **GitHub account** (for Codespaces and Pages)

### Required API Keys
- **Gemini API Key** (free tier: 15 requests/min, 1,500/day)
  - Get at: https://aistudio.google.com/apikey

---

## 🚀 Part 1: Backend Setup (GitHub Codespaces)

### Step 1: Create Codespace

1. Go to your repository on GitHub
2. Click **Code** → **Codespaces** → **Create codespace on main**
3. Wait 2-3 minutes for environment setup

### Step 2: Install Python Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### Step 3: Install Scanning Engines

**Semgrep (SAST):**
```bash
pip install semgrep
semgrep --version  # Verify: 1.152.0+
```

**Gitleaks (Secrets Detection):**
```bash
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz
tar -xzf gitleaks_8.18.4_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
rm gitleaks_8.18.4_linux_x64.tar.gz
gitleaks version  # Verify: 8.18.4
```

**Trivy (CVE Scanner):**
```bash
wget https://github.com/aquasecurity/trivy/releases/download/v0.50.1/trivy_0.50.1_Linux-64bit.tar.gz
tar -xzf trivy_0.50.1_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/
rm trivy_0.50.1_Linux-64bit.tar.gz
trivy image --download-db-only  # Download vulnerability database
trivy --version  # Verify: 0.50.1
```

### Step 4: Configure Environment

```bash
# Copy environment template
cp config/.env.example .env

# Edit .env file
nano .env
```

**Add your Gemini API key:**
```bash
OPENAI_API_KEY=AIzaSyC_your_actual_gemini_key_here
OPENAI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/

AEGIS_HOST=0.0.0.0
AEGIS_PORT=8000
AEGIS_DEBUG=false

SEMGREP_PATH=semgrep
GITLEAKS_PATH=gitleaks
TRIVY_PATH=trivy

MAX_UPLOAD_SIZE_MB=50
SCAN_TIMEOUT_SECONDS=120
```

Save: `Ctrl+X` → `Y` → `Enter`

### Step 5: Run Backend Server

```bash
# Export environment variables
export OPENAI_API_KEY="your-gemini-key-here"
export OPENAI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"

# Start server
python backend/orchestrator.py
```

**Expected output:**
```
================================================================================
AEGIS PRIME AUDITOR - Backend Server
================================================================================
🚀 Starting server on http://0.0.0.0:8000
📊 API Documentation: http://0.0.0.0:8000/docs
🔧 Gemini AI: ✅ Enabled
🔍 Engines:
   - Semgrep: ✅
   - Gitleaks: ✅
   - Trivy: ✅
   - CodeQL: ✅ (built-in)
================================================================================
```

### Step 6: Make Backend Port Public

1. In VS Code, click **PORTS** tab (bottom panel)
2. Find **port 8000**
3. Right-click → **Port Visibility** → **Public**
4. **Copy the forwarded address** (e.g., `https://xxx-8000.app.github.dev`)

**This is your permanent backend API URL** - save it!

---

## 🎨 Part 2: Frontend Setup (GitHub Pages)

### Step 1: Install Frontend Dependencies

**Open a NEW terminal** (keep backend running in terminal 1):

```bash
cd frontend
npm install
```

### Step 2: Configure Backend URL

**Create `.env` file in frontend folder:**

```bash
echo "VITE_BACKEND_URL=https://your-codespace-url-8000.app.github.dev" > .env
```

**Replace with your actual Codespace URL from Part 1, Step 6.**

### Step 3: Test Locally

```bash
npm run dev
```

**Access at port 5173** - test file upload and scanning.

### Step 4: Build for Production

```bash
npm run build
```

**This creates `dist/` folder with production files.**

### Step 5: Deploy to GitHub Pages

**Option A: Manual (One-Time)**

```bash
# Force add dist folder
git add -f dist

# Commit
git commit -m "Add production build"

# Push
git push origin main
```

**Then in GitHub repo settings:**
1. Settings → Pages
2. Source: Deploy from a branch
3. Branch: `main`
4. Folder: `/dist`
5. Save

**Option B: Automated (GitHub Actions)**

Create `.github/workflows/deploy.yml` - see Automation section below.

---

## 🧪 Testing

### Test Backend API

```bash
# Health check
curl http://localhost:8000/

# Scan test file
curl -X POST http://localhost:8000/api/scan \
  -F "file=@tests/test_vulnerable.py"
```

### Test Frontend

1. Open browser to Codespace port 5173
2. Upload `tests/test_vulnerable.py`
3. Click "INITIATE SCAN"
4. Verify results show 20+ findings across all engines

---

## 🔄 Automation (GitHub Actions)

**Create `.github/workflows/deploy.yml`:**

```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches: [ main ]

permissions:
  contents: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: 18
          
      - name: Install and Build
        working-directory: ./frontend
        run: |
          npm install
          npm run build
        
      - name: Deploy to GitHub Pages
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./frontend/dist
```

**Then in Pages settings:**
- Source: `gh-pages` branch (auto-created)
- Folder: `/` (root)

---

## 📊 Expected Results

**When scanning `test_vulnerable.py`:**
- **Semgrep:** 7 findings (SQL injection, weak crypto, command injection)
- **Gitleaks:** 1 finding (AWS credentials)
- **Trivy:** 15+ findings (Jinja2, urllib3, requests CVEs)
- **CodeQL:** 6 findings (taint analysis)

**Total:** 29+ security findings  
**Risk Score:** 50-70/100 (MEDIUM to HIGH)

---

## 🔧 Troubleshooting

### Backend won't start
- **Error:** `OpenAIError: api_key must be set`
  - **Fix:** Export environment variables before running
  ```bash
  export OPENAI_API_KEY="your-key"
  export OPENAI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
  ```

### Scanner not found
- **Error:** `FileNotFoundError: semgrep/gitleaks/trivy`
  - **Fix:** Verify installation with `which semgrep`
  - **Fix:** Check PATH or update .env with full paths

### Frontend can't reach backend
- **Error:** `Failed to fetch` or CORS errors
  - **Fix:** Make Codespace port 8000 public
  - **Fix:** Update `VITE_BACKEND_URL` in frontend/.env
  - **Fix:** Restart frontend dev server after changing .env

### Build fails
- **Error:** `vite: not found`
  - **Fix:** Run `npm install` in frontend directory first

---

## 🎯 Your Assignment (10 Days)

### Task 1: Gemini Prompt Optimization
**File:** `backend/orchestrator.py` → `GeminiAnalyzer.analyze()`

**Goals:**
- Sub-2-second AI response time
- 99%+ valid JSON output
- Test with 50+ diverse codebases

**Metrics to track:**
```bash
# Create testing script
python -c "
import time
import statistics

times = []
for i in range(50):
    start = time.time()
    # Run scan
    elapsed = time.time() - start
    times.append(elapsed)

print(f'Avg: {statistics.mean(times):.2f}s')
print(f'P95: {statistics.quantiles(times, n=20)[18]:.2f}s')
"
```

### Task 2: Scanner Parallelism
**File:** `backend/orchestrator.py` → `_run_all_scanners()`

**Test thread vs process pools:**
```python
from concurrent.futures import ProcessPoolExecutor
executor = ProcessPoolExecutor(max_workers=4)  # Instead of ThreadPoolExecutor
```

**Target:** <30 seconds for 10,000-line files

### Task 3: Latency Monitoring
**Add to orchestrator.py:**
```python
import logging
import time

logger = logging.getLogger(__name__)

# In scan endpoint:
upload_time = time.time()
# ... file handling ...
logger.info(f"Upload: {time.time() - upload_time:.2f}s")

scan_time = time.time()
# ... scanning ...
logger.info(f"Scan: {time.time() - scan_time:.2f}s")
```

---

## 📦 File Structure

```
aegis-prime-auditor/
├── backend/
│   ├── orchestrator.py          # Main FastAPI server (650 lines)
│   ├── requirements.txt         # Python dependencies
│   └── __init__.py
├── frontend/
│   ├── src/
│   │   ├── App.tsx             # Main React component
│   │   ├── App.css             # Component styles
│   │   ├── main.tsx            # Entry point
│   │   └── index.css           # Tailwind base
│   ├── index.html              # HTML template
│   ├── package.json            # Node dependencies
│   ├── vite.config.ts          # Vite configuration
│   ├── tailwind.config.js      # Tailwind config
│   ├── postcss.config.js       # PostCSS config
│   ├── tsconfig.json           # TypeScript config
│   └── tsconfig.node.json      # TS Node config
├── config/
│   ├── .env.example            # Environment template
│   └── semgrep_rules.yaml      # Custom Semgrep rules
├── tests/
│   └── test_vulnerable.py      # Test file with vulnerabilities
├── .gitignore
└── README.md
```

---

## 🌐 Production Deployment

### Frontend (GitHub Pages)
- **URL:** https://[your-org].github.io/Aegis-Prime-Auditor/
- **Update frequency:** Every push to main (if using Actions)
- **Cost:** Free

### Backend (Codespace)
- **URL:** https://[codespace-id]-8000.app.github.dev
- **Persistence:** Keep Codespace running or restart on demand
- **Cost:** Free tier (120 core-hours/month)
- **Upgrade path:** Migrate to AWS/Railway/Render when revenue starts

---

## 🔐 Security Notes

- **Never commit .env** with real API keys
- **.gitignore** includes .env, dist/, node_modules/
- **Regenerate API keys** after sharing in chat/screenshots
- **Make Codespace ports private** in production

---

## 📞 Support

**For Atlas Synapse Team:**
- Backend issues → Steve George (Chief Systems Officer)
- Compliance questions → Max Kiefer (Chief Risk Officer)
- Product strategy → Julius Sanders (Chairman)

---

**Built for Atlas Synapse LLC - February 2026**
