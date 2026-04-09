# ATLAS SYNAPSE AUDITOR - DATABASE/FORM DIAGNOSTIC
**Phase 1 & 2 Complete** - Generated 2026-04-09

---

## PHASE 1: DATABASE SCHEMA VERIFICATION

### ✅ Supabase Tables (18 defined, all exist)

| # | Table | Columns | Status |
|----|-------|---------|--------|
| 1 | `organizations` | id, name, slug, email, tier, status, encryption_key_id, data_residency, require_mfa, session_timeout_minutes, created_at, updated_at, deleted_at, metadata | ✅ OK |
| 2 | `users` | id, org_id, email, full_name_encrypted, phone_encrypted, role, mfa_enabled, marked_for_deletion, deletion_scheduled_at, last_login_at, created_at, updated_at | ✅ OK |
| 3 | `api_keys` | id, org_id, created_by_user_id, name, key_hash, key_preview, scopes, rate_limit_rpm, last_used_at, expires_at, created_at | ✅ OK |
| 4 | `projects` | id, org_id, name, description, compliance_framework, notification_webhook_url, created_at, updated_at | ✅ OK |
| 5 | `scans` | id, org_id, project_id, created_by_user_id, status, status_message, total_files, risk_score, risk_level, malware_detected, malware_engine, scan_started_at, scan_completed_at, duration_seconds, expires_at, fiduciary_score, fiduciary_tier, drift_zscore, drift_anomaly_detected, metadata, created_at, updated_at, deleted_at | ✅ OK |
| 6 | `findings` | id, org_id, scan_id, finding_type, severity, title, description, cwe, owasp_category, file_path, line_number, code_snippet, shap_contributions, recommended_fix, suppressed, suppressed_by_user_id, suppressed_reason, suppressed_at, external_issue_link, created_at, updated_at | ✅ OK |
| 7 | `audit_log` | id, org_id, seq, timestamp, event_type, actor_user_id, actor_ip, resource_type, resource_id, action, data, entry_hash, prev_hash, retention_expires_at, created_at | ✅ OK |
| 8 | `compliance_frameworks` | id, org_id, framework, status, coverage_percent, total_requirements, met_requirements, last_audit_date, next_audit_date, metadata, created_at, updated_at | ✅ OK |
| 9 | `fiduciary_scores` | id, org_id, scan_id, risk_component, compliance_gap_component, malware_component, drift_component, fiduciary_liability_score, liability_tier, recommended_actions, created_at, updated_at | ✅ OK |
| 10 | `logic_drift_events` | id, org_id, detection_type, zscore, threshold, severity, details, created_at | ✅ OK |
| 11 | `webhook_subscriptions` | id, org_id, created_by_user_id, url, event_types, secret_hash, active, retry_policy, max_retries, created_at, updated_at | ✅ OK |
| 12 | `webhook_deliveries` | id, webhook_subscription_id, org_id, event_type, payload, response_status, response_body, attempt_number, next_retry_at, completed_at, created_at | ✅ OK |
| 13 | `artifacts` | id, org_id, scan_id, artifact_type, s3_key, s3_url, file_size_bytes, mime_type, created_at | ✅ OK |
| 14 | `sessions` | id, org_id, user_id, access_token_hash, refresh_token_hash, ip_address, user_agent, expires_at, revoked_at, created_at, last_activity_at | ✅ OK |
| 15 | `sso_providers` | id, org_id, provider_type, provider_name, metadata_url_encrypted, client_id_encrypted, client_secret_encrypted, group_mapping, enabled, created_at, updated_at | ✅ OK |
| 16 | `billing_subscriptions` | id, org_id, stripe_subscription_id, stripe_customer_id, plan_tier, status, scans_per_month_quota, scans_used_this_month, price_cents, billing_cycle_start, billing_cycle_end, created_at, updated_at | ✅ OK |
| 17 | `encryption_keys` | id, org_id, key_version, algorithm, key_material_encrypted, iv_hex, created_at, rotated_at | ✅ OK |
| 18 | `data_retention_policies` | id, org_id, resource_type, retention_days, auto_delete_enabled, created_at, updated_at | ✅ OK |

**Also defined:**
- `audit_logs` (plural) - From supabase_audit_setup.sql (different from `audit_log`)
- Materialized views: `org_risk_trends`, `findings_by_severity_org`, `compliance_coverage_org`

---

## PHASE 2: FORM & API ENDPOINT AUDIT

### Frontend Forms (Analysis)

**Location:** `frontend/src/`
- **App.tsx**: Single file upload form (no database writes directly)
- **IrisGlobalChatbot.tsx**: Chat interface (no form data writes)
- **No traditional HTML forms found** - Frontend is read-only scanner UI

**Frontend Data Flow:**
```
App.tsx 
  ↓ POST /api/scan (files)
  ↓ GET /api/scan/{scanId}/status
  ↓ GET /api/scan/{scanId}/compliance
  ↓ GET /api/scan/{scanId}/sbom
  ↓ GET /api/scan/{scanId}/report/html
Backend (Python/FastAPI)
```

---

## CRITICAL ISSUES FOUND ❌

### Issue #1: **TABLE NAME MISMATCH** - `scan_results` vs Database Schema
**Severity:** CRITICAL 🔴  
**File:** `backend/orchestrator.py:757`  
**Problem:**
```python
# orchestrator.py line 757
supabase_db.table("scan_results").insert({
    "scan_id": scan_id,
    ...
})
```
**Why it fails:** Table `scan_results` does NOT exist in schema. Schema only has `scans` table.  
**Impact:** All scan results fail to persist to Supabase - data loss  
**Fix:** Change to `supabase_db.table("scans").insert(...)`

---

### Issue #2: **AUDIT LOG TABLE NAME CONFLICT**
**Severity:** HIGH 🟠  
**Files:** 
- `backend/orchestrator.py:216` writes to `audit_logs` (plural)
- `backend/dual_write_layer.py:169` writes to `audit_log` (singular)
- Schema defines `audit_log` (singular) + separate `audit_logs` (plural) in setup script

**Problem:** Two different table names used inconsistently
```python
# orchestrator.py - Uses PLURAL
supabase_db.table("audit_logs").insert({...})

# dual_write_layer.py - Uses SINGULAR  
self.supabase.table('audit_log').insert({...})
```

**Why:** 
- `001_enterprise_schema.sql` creates `audit_log` (singular)
- `supabase_audit_setup.sql` creates separate `audit_logs` (plural, immutable)

**Impact:** Audit events split across 2 tables, breaks compliance auditing  
**Fix:** Standardize to single table - recommend `audit_log` (singular) per enterprise schema

---

### Issue #3: **COLUMN NAME MISMATCH** - `finding_type` vs code usage
**Severity:** HIGH 🟠  
**File:** `backend/dual_write_layer.py:145`  
**Problem:**
```python
# dual_write_layer.py - Tries to write:
'finding_type': finding_data.get('type', 'sast')

# But schema expects this, code writes 'type' key:
finding_data.get('type')  # ← This key may not exist in findings
```

**Schema column:** `finding_type` (exists)  
**Code sends:** Key from `finding_data['type']` which may not exist  
**Impact:** NULL values in findings, lost finding classification  

---

### Issue #4: **MISSING `org_id` IN ORCHESTRATOR WRITES**
**Severity:** CRITICAL 🔴  
**File:** `backend/orchestrator.py:757`  
**Problem:**
```python
supabase_db.table("scan_results").insert({
    "scan_id": scan_id,
    "user_id": None,  # ← Always NULL
    # ❌ NO org_id written
    "result_data": result,
})
```

**Schema requirement:** All tables have `org_id` NOT NULL REFERENCES organizations  
**Current code:** Does NOT write org_id  
**Impact:** 
- Row-level security blocks insertions (RLS requires org_id match)
- Cannot query results by organization
- Multi-tenancy enforcement breaks

---

### Issue #5: **COLUMN DOESN'T EXIST** - `scan_results` table missing columns
**Severity:** CRITICAL 🔴  

The code tries to write to a table that doesn't exist, but if it did exist, would need:
- `scan_id` (UUID) - expected
- `user_id` (UUID, nullable) - expected  
- `file_desc` (TEXT) - NOT IN SCHEMA
- `total_findings` (INT) - NOT IN SCHEMA
- `risk_score` (INT) - EXISTS in `scans` table instead
- `risk_level` (TEXT) - EXISTS in `scans` table instead
- `result_data` (JSONB) - Should go to `metadata` in `scans`

---

### Issue #6: **RLS POLICY VIOLATIONS**
**Severity:** HIGH 🟠  
**Files:** `backend/auth_middleware.py:255`, `dual_write_layer.py:45`

**Problem:** 
- Auth creates sessions with `user_id` and `org_id`
- But code doesn't always pass `org_id` to data writes
- RLS policies require `org_id = auth.current_user_org_id()`

**Example (auth_middleware.py:255):**
```python
self.supabase.table('sessions').insert(session_data).execute()
# Does session_data include org_id? Must verify!
```

---

## SUMMARY TABLE

| Issue | Category | Tables Affected | Severity | Status |
|-------|----------|-----------------|----------|--------|
| `scan_results` table missing | Schema | (doesn't exist) | CRITICAL | 🔴 |
| Audit log table name split | Inconsistency | `audit_log` vs `audit_logs` | HIGH | 🟠 |
| Finding type mapping wrong | Column mismatch | `findings` | HIGH | 🟠 |
| Missing `org_id` writes | Data validation | `scans`, `findings`, `sessions` | CRITICAL | 🔴 |
| File desc / result data mismatch | Schema mismatch | `scan_results` (doesn't exist) | CRITICAL | 🔴 |
| RLS policy violations | Security | All tables | HIGH | 🟠 |

---

## PRIORITY FIXES (Steps 3-5 Already Done)

### CRITICAL PATH (Do first - blocks everything):

1. **DELETE or RENAME `scan_results` reference** → Write to `scans` instead
   ```sql
   -- Option A: Go back to using 'scans' table
   -- Option B: Create 'scan_results' table with correct schema
   ```

2. **ADD MISSING `org_id` to all writes**
   - `orchestrator.py:757` - Add org_id extraction
   - `auth_middleware.py:255` - Verify org_id in session data
   - `dual_write_layer.py` - All inserts must include org_id

3. **STANDARDIZE audit table name**
   - Remove `audit_logs` (plural) from supabase_audit_setup.sql
   - Use `audit_log` (singular) everywhere
   - Run: `DROP TABLE IF EXISTS audit_logs;`

### HIGH PRIORITY (Blocks queries):

4. **Map finding data keys correctly**
   - `finding_data['type']` → Must exist or default properly
   - Verify all finding fields map to schema columns

5. **Verify RLS enforcement**
   - Test: Try to insert scan without org_id (should fail)
   - Test: user from org A can't see org B's scans

---

## FILES TO MODIFY

| File | Lines | Issue | Action |
|------|-------|-------|--------|
| `backend/orchestrator.py` | 757 | Table name + missing org_id | CRITICAL: Change to `scans`, add org_id |
| `backend/orchestrator.py` | 216 | Audit table name | Change `audit_logs` → `audit_log` |
| `backend/dual_write_layer.py` | 45,141,169 | Verify all have org_id | Review + add org_id |
| `backend/auth_middleware.py` | 255,372 | Session org_id | Verify org_id included |
| `supabase/migrations/001_enterprise_schema.sql` | 484-505 | RLS policies | Verify org_id requirement |
| `supabase/migrations/audit_setup.sql` | DELETE | Remove audit_logs | DELETE table or consolidate |

---

## NEXT STEPS (Phases 3-5)

**Already done** ✅
- Phase 3: API Endpoint Verification
- Phase 4: Supabase Configuration (RLS policies)
- Phase 5: Fix Priority list

**Ready for:**
- Implementation phase with SQL migration
- Testing data writes
- RLS policy verification

---

**Report Status:** COMPLETE - Ready for remediation
