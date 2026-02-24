# Atlas Synapse White-Labeling Guide

This document details how to rebrand Aegis Prime Auditor as "Atlas Synapse Auditor" for Atlas Synapse LLC.

---

## 🎨 Branding Changes Required

### 1. Frontend Branding (`frontend/src/App.tsx`)

**Line 152-157: Update Header**

**Current:**
```tsx
<h1 className="text-xl font-bold text-white">AEGIS PRIME</h1>
<p className="text-xs text-slate-400">Security Auditor v1.0</p>
```

**Change to:**
```tsx
<h1 className="text-xl font-bold text-white">ATLAS SYNAPSE</h1>
<p className="text-xs text-slate-400">Sovereign Security Auditor v1.0</p>
```

**Line 145-150: Update Logo Color**

**Current:** Blue (`bg-blue-500`)

**Change to Atlas brand color:**
```tsx
<div className="w-10 h-10 bg-[#0A84FF] rounded-lg flex items-center justify-center">
```

Replace `#0A84FF` with your actual brand color.

---

### 2. Backend Branding (`backend/orchestrator.py`)

**Line 30: Update FastAPI Title**

**Current:**
```python
app = FastAPI(
    title="Aegis Prime Auditor",
    version="1.0.0",
    description="Multi-engine security analysis platform with AI-powered risk assessment"
)
```

**Change to:**
```python
app = FastAPI(
    title="Atlas Synapse Auditor",
    version="1.0.0",
    description="Sovereign Standard for Enterprise Security Analysis - Multi-engine scanning with AI-powered compliance assessment"
)
```

**Line 285-293: Update Startup Banner**

**Current:**
```python
print("AEGIS PRIME AUDITOR - Backend Server")
```

**Change to:**
```python
print("ATLAS SYNAPSE AUDITOR - Sovereign Security Platform")
```

---

### 3. Configuration Files

**`config/semgrep_rules.yaml`**

Rename all rule IDs from `aegis-*` to `atlas-*`:

```yaml
# Before
- id: aegis-sql-injection-fstring

# After
- id: atlas-sql-injection-fstring
```

Do this for all 6 rules in the file.

---

### 4. HTML Meta Tags (`frontend/index.html`)

**Current:**
```html
<title>Aegis Prime Auditor - Multi-Engine Security Analysis</title>
<meta name="description" content="AI-powered security scanning..." />
```

**Change to:**
```html
<title>Atlas Synapse Auditor - Sovereign Security Standard</title>
<meta name="description" content="Enterprise-grade multi-engine security analysis for $10M+ businesses in FinTech, Insurance, and Legal sectors" />
```

---

### 5. README.md

**Line 1:**
```markdown
# 🛡️ Atlas Synapse Auditor

**The Sovereign Standard for Enterprise Security Analysis**
```

**Line 3:**
```markdown
Built by [Atlas Synapse LLC](https://atlassynapseai.com)
```

---

### 6. Package Naming

**`frontend/package.json`:**
```json
{
  "name": "atlas-synapse-auditor-frontend",
  "version": "1.0.0"
}
```

---

## 🎨 Brand Color Palette (Recommendation)

Replace blue (`#3b82f6`, `rgb(59, 130, 246)`) throughout with Atlas Synapse colors:

**Suggested palette:**
```css
--atlas-primary: #0A84FF;    /* Signal blue - professional, trustworthy */
--atlas-critical: #dc2626;   /* Keep red for critical alerts */
--atlas-high: #ea580c;       /* Keep orange for high severity */
--atlas-medium: #eab308;     /* Keep yellow for medium */
--atlas-low: #22c55e;        /* Keep green for low */
```

**Files to update:**
- `frontend/src/App.tsx` (all `bg-blue-*` and `text-blue-*`)
- `frontend/src/index.css` (if custom colors added)

---

## 🔧 Technical Rebrand Checklist

- [ ] Update app title in `App.tsx`
- [ ] Update FastAPI title in `orchestrator.py`
- [ ] Update startup banner in `orchestrator.py`
- [ ] Rename Semgrep rules `aegis-*` → `atlas-*`
- [ ] Update HTML title and meta tags
- [ ] Update README.md branding
- [ ] Update package.json names
- [ ] Replace blue color with Atlas brand color
- [ ] Update logo SVG (if custom logo exists)
- [ ] Update favicon (optional)

---

## 🚀 Regulatory Extensions for Atlas Synapse

Based on the Atlas Synapse mission (FinTech/Insurance/Legal compliance), add these scanner rules:

### Financial Compliance Patterns

**Add to `config/semgrep_rules.yaml`:**

```yaml
  - id: atlas-fair-lending-proxy-feature
    pattern-regex: "(zipcode|zip_code|postal_code).*credit_score"
    message: |
      Potential Fair Lending Act violation: Geographic data used in credit decisioning.
      Verify this is not a proxy for protected class information.
    severity: ERROR
    metadata:
      compliance: [Fair-Lending-Act, ECOA]
      industry: fintech
      
  - id: atlas-unexplained-decision
    pattern-regex: "predict\\(.*\\).*without.*explanation"
    message: |
      NYDFS 23 NYCRR 500: Financial decisions require explainability.
      Implement SHAP values or decision lineage.
    severity: WARNING
    metadata:
      compliance: [NYDFS-500, Model-Risk-Management]
      industry: fintech
```

### Insurance Compliance

```yaml
  - id: atlas-claims-bias-detection
    pattern-regex: "(race|ethnicity|gender).*claims_amount"
    message: |
      Potential discriminatory claims processing.
      Protected attributes should not influence claim decisions.
    severity: ERROR
    metadata:
      compliance: [Insurance-Fair-Practice]
      industry: insurance
```

---

## 📊 Atlas Synapse Positioning

**Update README executive summary:**

```markdown
## Why Atlas Synapse Auditor?

Atlas Synapse serves $10M+ businesses in regulated industries where "AI toys" 
create liability. Our auditor is built for:

- **FinTech:** Fair Lending Act compliance, NYDFS explainability requirements
- **Insurance:** Discriminatory claims detection, actuarial model validation
- **LegalTech:** Contract consistency analysis, regulatory document drift detection

We don't just find bugs—we find **fiduciary liabilities** that make migration 
to Atlas infrastructure a necessity, not a choice.
```

---

## 🎯 Atlas Synapse Value Proposition

**Add to README:**

```markdown
## The Atlas Difference

| Capability | Aegis Prime | Atlas Synapse Extension |
|------------|-------------|-------------------------|
| Code security | ✅ SAST, Secrets, SCA | ✅ Same foundation |
| Compliance | Basic CWE mapping | ✅ Fair Lending, NYDFS, SOC 2 rules |
| Risk scoring | Generic 0-100 | ✅ Regulatory-weighted scoring |
| Explainability | Finding details | ✅ SHAP values, decision lineage |
| Target market | General software | ✅ $10M+ FinTech/Insurance/Legal |

**Atlas Synapse doesn't compete on AI sophistication—we compete on evidentiary-grade 
failure detection that makes regulatory migration a fiduciary necessity.**
```

---

**This guide enables complete rebranding from "Aegis Prime" to "Atlas Synapse Auditor" 
while maintaining the technical foundation and extending it for regulated industries.**
