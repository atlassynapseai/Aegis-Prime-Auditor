# ⚡ Aegis Prime Auditor - Quick Start

**Get running in 10 minutes**

---

## 🚀 For GitHub Codespaces (Recommended)

### 1. Create Codespace
- Go to your GitHub repo
- Click **Code** → **Codespaces** → **Create codespace on main**

### 2. Run Setup Script
```bash
chmod +x setup.sh
./setup.sh
```

### 3. Add Gemini API Key
```bash
nano .env
# Add: OPENAI_API_KEY=AIzaSyC_your_key_here
# Add: OPENAI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/
```

Get key at: https://aistudio.google.com/apikey

### 4. Start Backend
```bash
export OPENAI_API_KEY="your-key-here"
export OPENAI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
python backend/orchestrator.py
```

### 5. Start Frontend (New Terminal)
```bash
cd frontend
npm run dev
```

### 6. Make Ports Public
- **PORTS** tab → Right-click 8000 and 5173 → **Port Visibility** → **Public**

### 7. Test
- Open port 5173 in browser
- Upload `tests/test_vulnerable.py`
- Click "INITIATE SCAN"
- See 29+ findings detected

---

## 💻 For Local Development

### Backend
```bash
cd backend
pip install -r requirements.txt
pip install semgrep
# Install Gitleaks + Trivy (see DEPLOYMENT.md)
cp ../config/.env.example ../.env
# Add Gemini API key to .env
python orchestrator.py
```

### Frontend
```bash
cd frontend
npm install
echo "VITE_BACKEND_URL=http://localhost:8000" > .env
npm run dev
```

---

## 🌐 For Production (GitHub Pages + Codespace)

### Deploy Frontend
```bash
cd frontend
npm run build
git add -f dist
git commit -m "Production build"
git push origin main
```

**GitHub Settings:**
- Pages → Branch: `main` → Folder: `/frontend/dist` → Save

### Keep Backend Running
- Make Codespace port 8000 public
- Copy the public URL: `https://xxx-8000.app.github.dev`
- Add to frontend `.env`: `VITE_BACKEND_URL=https://xxx-8000.app.github.dev`
- Rebuild frontend

---

## ✅ Verification Checklist

- [ ] Backend responds at `/` and `/docs`
- [ ] All 4 engines show ✅ in startup banner
- [ ] Frontend loads without 404 errors
- [ ] File upload accepts `.py` files
- [ ] Scan completes in <45 seconds
- [ ] Results show findings from all 4 engines
- [ ] Heatmap visualizes Category × Severity matrix
- [ ] AI analysis shows risk score and priorities

---

## 🆘 Common Issues

**"Gemini API error"**
→ Check .env has correct API key and base URL

**"Scanner not found"**  
→ Run `which semgrep && which gitleaks && which trivy`

**"Frontend blank page"**
→ Check browser console (F12) for errors

**"CORS error"**
→ Make backend port public in Codespaces

---

**For detailed guides, see:**
- `DEPLOYMENT.md` - Complete deployment instructions
- `docs/ATLAS_SYNAPSE_BRANDING.md` - White-labeling guide
- `README.md` - Full documentation
