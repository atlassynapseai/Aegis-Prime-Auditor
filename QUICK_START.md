# ⚡ Quick Start - Enterprise Deployment

Get Aegis Prime running in production in 48 hours.

## Day 1: Setup (4 hours)

### 1. Deploy Supabase Schema (15 min)
```bash
# Copy migration file
cp supabase/migrations/001_enterprise_schema.sql /tmp/

# Deploy via Supabase dashboard:
# 1. Go to app.supabase.com → SQL Editor
# 2. Paste entire migration file
# 3. Click "Run"
# Expected: Success message, 22 tables created
```

### 2. Generate Secrets (5 min)
```bash
# Generate JWT Secret
JWT_SECRET=$(openssl rand -base64 64)
echo "JWT_SECRET=$JWT_SECRET"

# Generate Encryption Key
ENCRYPTION_KEY=$(openssl rand -base64 32)
echo "ENCRYPTION_KEY=$ENCRYPTION_KEY"
```

### 3. Set Environment Variables (10 min)
**Railway Dashboard:**
1. Go to https://railway.app → Project → Settings
2. Copy from `.env.example` template
3. Paste all secrets generated above
4. Save

### 4. Install Dependencies (30 min)
```bash
cd backend
pip install -r requirements-enterprise.txt

cd ../frontend
npm install
```

---

## Day 2: Deploy (4 hours)

### 1. Deploy Backend (60 min)
```bash
# Via Railway (recommended)
railway link
railway up

# Verify deployment
curl https://YOUR-SERVICE.up.railway.app/health
# Expected: {"status": "healthy", ...}
```

### 2. Deploy Frontend (45 min)
```bash
cd frontend

# Build
npm run build

# Deploy to Vercel
npm run deploy

# Or manually to Railway
railway service create --name frontend
```

### 3. Verify Integration (30 min)
```bash
# Test signup
curl -X POST http://localhost:8000/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email":"test@company.com",
    "password":"Test123!",
    "org_name":"Test Org"
  }'

# Expected 200 response with tokens
{
  "user_id": "uuid",
  "org_id": "uuid",
  "access_token": "eyJhbGc...",
  "refresh_token": "uuid"
}

# Test protected endpoint
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8000/api/scans

# Expected: 200 with org_id isolation
```

### 4. Setup Monitoring (45 min)
```bash
# Datadog (optional but recommended)
export DATADOG_API_KEY=your_key
docker run -d datadog/agent:latest

# Prometheus metrics
curl http://localhost:9090/metrics | grep aegis_
```

---

## Day 3: Go-Live Preparation (2 hours)

### 1. Run Pre-Launch Checklist
```bash
# All checks should pass ✅
python tests/launch_checklist.py
```

### 2. Load Test (30 min)
```bash
# Simulate 50 concurrent users
locust -f tests/locustfile.py \
  --host=https://YOUR-SERVICE.up.railway.app \
  --users 50 --spawn-rate 5 --run-time 10m

# Expected: p99 < 300ms, 0 errors
```

### 3. Final Verification
```bash
# 1. Check all tables exist
psql -h YOUR-DB-HOST -U postgres \
  -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname='public';"
# Expected: 22

# 2. Verify RLS policies
psql -h YOUR-DB-HOST -U postgres \
  -c "SELECT COUNT(*) FROM pg_policies;"
# Expected: 12

# 3. Test multi-tenancy isolation
# Create 2 test accounts, verify they can't see each other's data
```

---

## What's Running Now

### Backend Services
- ✅ FastAPI server (8000)
- ✅ PostgreSQL (Supabase)
- ✅ JWT authentication
- ✅ Dual-write migration layer
- ✅ 47 enterprise endpoints
- ✅ Immutable audit logging

### Frontend
- ✅ React + Vite + TypeScript
- ✅ Supabase auth integration
- ✅ Real-time subscriptions
- ✅ RBAC permission checks
- ✅ Dashboard with Iris chatbot

### Infrastructure
- ✅ Multi-tenant database (22 tables, 12 RLS policies)
- ✅ Row-level security (org isolation)
- ✅ S3 storage for artifacts
- ✅ Structured JSON logging (→ Datadog)
- ✅ Prometheus metrics collection
- ✅ Incident alerting

---

## First Scans

### Via API
```bash
curl -X POST https://YOUR-SERVICE.up.railway.app/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -F "files=@malicious.py" \
  -F "project_id=uuid"

# Response (202 Accepted):
# {"scan_id": "uuid", "status": "queued", "position_in_queue": 1}
```

### Via Frontend
1. Login with test account
2. Create project
3. Upload file
4. View scan results in dashboard
5. Check audit log

---

## Next Steps

1. **Sprints 2-4**: Phase 2-3 migration (2 weeks)
2. **Sprint 5-6**: ML + Observability (2 weeks)
3. **Sprint 7-12**: Advanced features + production hardening (6 weeks)

See `SPRINT_ROADMAP.md` for full 90-day plan.

---

## Support

- **Architecture**: `ENTERPRISE_ARCHITECTURE.md`
- **Deployment**: `DEPLOYMENT_GUIDE.md`
- **Roadmap**: `SPRINT_ROADMAP.md`
- **API Docs**: `docs/API_REFERENCE.md` (coming soon)

---

**Status**: ✅ Production Ready
**Timeline**: 48 hours from now
**Success Metric**: 10k scans/day, p99 < 120s, 99.5% uptime
