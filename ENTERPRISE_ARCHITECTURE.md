# Atlas Synapse Aegis Prime Auditor — Enterprise Architecture Blueprint
**Version:** 1.0
**Status:** Implementation-Ready
**Last Updated:** 2026-04-09
**Classification:** Internal Confidential

---

## EXECUTIVE SUMMARY

This document provides a complete architecture blueprint for transforming Aegis Prime Auditor into an enterprise-grade AI security and governance platform. The design prioritizes regulatory compliance (SOC 2, NYDFS), zero-downtime migration from current in-memory state to full persistence, production-ready multi-tenancy, and differentiation through advanced ML detection and explainability.

**Key Objectives:**
- ✅ Full auth/tenant isolation with RBAC, SSO, and project-level data fencing
- ✅ Persistent scan history, fiduciary scoring, and audit evidence chain
- ✅ Production CI/CD with policy gates and environment promotion
- ✅ Advanced features: logic drift detection, SHAP-based explainability, Tier 3 ML malware
- ✅ Enterprise observability: datadog/axiom logs, prometheus metrics, otel traces, SLOs
- ✅ 30/60/90 day roadmap for staged rollout

**Quick Stats:**
- Schema: 18 tables + 8 materialized views
- Auth: Supabase Auth + JWT + 12 RLS policies
- APIs: 47 core endpoints + 12 webhook subscriptions
- Scanning: 4 OSS + 3 cloud intelligence sources + 1 ML pipeline
- Scale: 10k scans/day, 100ms p99 latency per scan, <$0.10 COGS

---

## PART 1: TARGET ARCHITECTURE

### 1.1 Service Boundaries & Deployment Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                                  │
├────────────────┬──────────────────────────┬─────────────────────────┤
│ Browser SPA    │ IDE Extension (VSCode)   │ CI/CD Runners           │
│ (Vercel Pages) │ (Node.js Plugin)         │ (GitHub/GitLab/Jenkins) │
└────────┬────────┴──────────────┬───────────┴──────────────┬──────────┘
         │                       │                          │
    ┌────▼──────────────────┐    │    ┌─────────────────────▼────┐
    │  API Gateway          │    │    │  Scanner Ingestion Queue  │
    │  (Railway Proxy)      │    │    │  (Bull/Redis)             │
    └────┬──────────────────┘    │    └─────────────────────┬────┘
         │ JWT Verification      │                          │
    ┌────▼──────────────────────────────────────────────────▼────┐
    │                 BACKEND SERVICE LAYER (Railway)           │
    ├──────────────────────────────────────────────────────────┤
    │ ┌────────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
    │ │ Auth       │ │ Scanning │ │ Findings │ │ Compliance   │ │
    │ │ Service    │ │ Pipeline │ │ Mapper   │ │ Engine       │ │
    │ ├────────────┤ ├──────────┤ ├──────────┤ ├──────────────┤ │
    │ │ Audit Log  │ │ ML Queue │ │ Report   │ │ Drift        │ │
    │ │ Service    │ │ Manager  │ │ Builder  │ │ Detector     │ │
    │ └────────────┘ └──────────┘ └──────────┘ └──────────────┘ │
    └────┬──────────────────────┬──────────────────────────┬────┘
         │                      │                          │
    ┌────▼──────┐  ┌───────────▼──────────┐  ┌────────────▼────────┐
    │ Supabase  │  │ External Cloud APIs  │  │ Observability       │
    │ PostgreSQL│  │ - VirusTotal         │  │ - Datadog Logs      │
    │ - 18 Core │  │ - AlienVault OTX     │  │ - Prometheus Metrics│
    │   tables  │  │ - Gemini AI          │  │ - OpenTelemetry     │
    └───────────┘  │ - Okta / Azure AD    │  │ - Alert Manager     │
                   └──────────────────────┘  └─────────────────────┘

    ┌──────────────────────────────────────────────┐
    │  STATIC LAYER (GitHub Pages)                 │
    │  - Frontend Build Artifacts                  │
    │  - CI/CD Integration Docs                    │
    └──────────────────────────────────────────────┘
```

### 1.2 Trust Boundaries

```
PUBLIC (No Auth)
├── GET /api/health
├── POST /api/scan (anonymous, creates temp session)
├── GET /api/scan/{scan_id} (if not requires_auth)
└── GET /api/findings/{finding_id} (if public_link=true)

AUTHENTICATED (JWT Required)
├── GET /api/scans (user's org only)
├── POST /api/org/{org_id}/scans
├── GET /api/org/{org_id}/compliance
└── POST /api/workspace/{ws_id}/audit-log

ADMIN (RBAC:admin)
├── POST /api/org/{org_id}/users
├── POST /api/audit-log/export
└── POST /api/billing/usage

ML_PIPELINE (Service-to-Service)
├── GET /api/internal/queue/next-scan
├── POST /api/internal/ml/detect
└── PUT /api/internal/scan/{id}/status
```

### 1.3 Data Flow — Core Scan-to-Report
```
User / CI/CD
    │
    ├─► POST /api/scan
    │   {files, metadata, org_id, project_id}
    │
    ├─► Backend Auth Service
    │   ├─ Verify JWT (or create anonymous session)
    │   ├─ Check RLS: can_scan(org_id, project_id)
    │   └─ Associate scan with ownership
    │
    ├─► Scan Service + Queue
    │   ├─ Create scan record (status=queued)
    │   ├─ Push to Bull Redis queue
    │   └─ Return scan_id + presigned_url for uploads
    │
    ├─► Scanner Workers (Max 4 concurrent)
    │   ├─ Dequeue from Redis
    │   ├─ Run 4 engines in parallel (Semgrep, Gitleaks, Trivy, CodeQL)
    │   ├─ Run YARA + Heuristic malware checks
    │   ├─ Call VirusTotal + OTX for cloud intel (async, non-blocking)
    │   ├─ Store findings batch to findings table
    │   └─ Mark scan status = scanning_complete
    │
    ├─► AI Analysis Service
    │   ├─ Call Gemini 2.5 Flash with findings + context
    │   ├─ Parse risk_score (0-100), risk_level (LOW/MED/HIGH/CRITICAL)
    │   ├─ Extract top_priorities[], remediation_guidance
    │   └─ Insert ai_analysis record
    │
    ├─► Compliance Mapper
    │   ├─ Map findings to frameworks (GDPR, HIPAA, SOX, etc.)
    │   ├─ Calculate framework_compliance_score
    │   └─ Identify compliance_gaps
    │
    ├─► Report Generator
    │   ├─ Generate executive_markdown + html_report
    │   ├─ Create PDF artifact (if premium)
    │   └─ Store artifact_url in artifacts table
    │
    ├─► Audit Log (Append-Only)
    │   ├─ scan_started(scan_id, org_id, user_id, file_count)
    │   ├─ engine_completed(scan_id, engine, finding_count)
    │   ├─ ai_analysis_completed(scan_id, risk_score)
    │   ├─ report_generated(scan_id, report_id)
    │   └─ All entries hash-chained: entry_hash = sha256(prev_hash + event_json)
    │
    ├─► Fiduciary Score Engine
    │   ├─ Calculate liability_score = f(risk_score, compliance_gaps, malware_detected)
    │   ├─ Track trend over time (logic_drift detection)
    │   └─ Store in fiduciary_scores table
    │
    └─► Webhooks + Events
        ├─ Emit ScanCompleted event
        ├─ Trigger subscribed CI/CD (GitHub Check Suite)
        ├─ Notify integrations (Slack, PagerDuty)
        └─ Post to compliance_checkpoint if required
```

### 1.4 Failure Modes & Resilience

| Failure | Impact | Mitigation |
|---------|--------|-----------|
| VirusTotal API down | Tier 2 malware skipped (non-critical) | Graceful timeout 5s, log, continue |
| Gemini API rate limit | Risk analysis delayed | Queue with exp backoff + fallback heuristic scoring |
| Supabase connection lost | Scan still runs, findings queued | Redis persist layer + async Supabase flush |
| Scanner worker crash | Scan marked stale after 5min | Redis lock + restart worker, retry from checkpoint |
| PDF gen timeout | Report not generated | Mark as pending, retry async, notify user |
| RLS policy error | Data leak risk | Kill request, alert ops, human audit |
| Audit log corruption | Compliance evidence lost | Daily checksum verify + immutable backup to S3 |

---

## PART 2: SUPABASE PostgreSQL SCHEMA

### 2.1 Core DDL

```sql
-- ============================================================================
-- USERS & ORGANIZATIONS
-- ============================================================================

CREATE TABLE auth.users (
  id UUID PRIMARY KEY DEFAULT auth.uid(),
  email TEXT UNIQUE NOT NULL,
  raw_user_meta_data JSONB DEFAULT '{}',
  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now()
);
COMMENT ON TABLE auth.users IS 'Supabase Auth integration (managed by Auth service)';

CREATE TABLE public.users (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  org_id UUID NOT NULL,
  email TEXT NOT NULL,
  display_name TEXT,
  avatar_url TEXT,
  role TEXT DEFAULT 'viewer' CHECK (role IN ('admin', 'editor', 'viewer')),
  permissions JSONB DEFAULT '{}',
  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now()
);
CREATE INDEX idx_users_org_id ON public.users(org_id);
COMMENT ON TABLE public.users IS 'User profiles with org membership and RBAC role';

CREATE TABLE public.organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  plan TEXT DEFAULT 'free' CHECK (plan IN ('free', 'starter', 'pro', 'enterprise')),
  stripe_customer_id TEXT,
  sso_enabled BOOLEAN DEFAULT FALSE,
  sso_provider TEXT CHECK (sso_provider IN ('okta', 'azure', 'google', NULL)),
  sso_config JSONB DEFAULT '{}',
  max_scans_per_month INT DEFAULT 100,
  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now()
);
CREATE INDEX idx_org_slug ON public.organizations(slug);
COMMENT ON TABLE public.organizations IS 'Organizations (tenants) with plan and SSO config';

-- ============================================================================
-- PROJECTS & WORKSPACES
-- ============================================================================

CREATE TABLE public.projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES public.organizations(id),
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  description TEXT,
  repo_url TEXT,
  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now(),
  UNIQUE(org_id, slug)
);
CREATE INDEX idx_projects_org_id ON public.projects(org_id);
COMMENT ON TABLE public.projects IS 'Projects represent code repos or applications within an org';

CREATE TABLE public.workspaces (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES public.projects(id),
  name TEXT NOT NULL,
  description TEXT,
  retention_days INT DEFAULT 90,
  created_at TIMESTAMP DEFAULT now(),
  UNIQUE(project_id, name)
);
COMMENT ON TABLE public.workspaces IS 'Logical groupings within projects for scan isolation';

-- ============================================================================
-- SCANS & FINDINGS
-- ============================================================================

CREATE TABLE public.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES public.organizations(id),
  project_id UUID NOT NULL REFERENCES public.projects(id),
  workspace_id UUID REFERENCES public.workspaces(id),
  user_id UUID REFERENCES auth.users(id),

  -- Scan metadata
  status TEXT DEFAULT 'queued' CHECK (status IN (
    'queued', 'scanning', 'scanning_complete', 'analyzing', 'report_generating',
    'completed', 'failed', 'cancelled'
  )),
  scan_type TEXT DEFAULT 'adhoc' CHECK (scan_type IN ('adhoc', 'scheduled', 'cicd')),

  -- File info
  file_count INT DEFAULT 0,
  total_file_size_mb INT,
  file_hashes TEXT[], -- SHA256 of each file for dedup

  -- Scan result aggregates
  total_findings INT DEFAULT 0,
  critical_count INT DEFAULT 0,
  high_count INT DEFAULT 0,
  medium_count INT DEFAULT 0,
  low_count INT DEFAULT 0,

  -- Risk analysis
  risk_score INT DEFAULT 0, -- 0-100
  risk_level TEXT CHECK (risk_level IN ('PASSED', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  malware_detected BOOLEAN DEFAULT FALSE,

  -- Lifecycle
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT now(),

  -- Auth & ownership
  shared_token TEXT UNIQUE, -- For public links (scan?token=xxx)
  requires_authentication BOOLEAN DEFAULT TRUE,

  -- Metadata
  metadata JSONB DEFAULT '{}', -- CI service, commit hash, branch, etc

  PRIMARY KEY (id),
  CONSTRAINT started_before_completed CHECK (started_at IS NULL OR completed_at IS NULL OR started_at <= completed_at)
);
CREATE INDEX idx_scans_org_id ON public.scans(org_id);
CREATE INDEX idx_scans_project_id ON public.scans(project_id);
CREATE INDEX idx_scans_user_id ON public.scans(user_id);
CREATE INDEX idx_scans_status ON public.scans(status);
CREATE INDEX idx_scans_created_at ON public.scans(created_at DESC);
COMMENT ON TABLE public.scans IS 'Core scan records with aggregated results';

CREATE TABLE public.findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  org_id UUID NOT NULL REFERENCES public.organizations(id),

  -- Finding identity
  finding_key TEXT NOT NULL, -- engine:rule:file:line for dedup
  engine TEXT NOT NULL CHECK (engine IN (
    'semgrep', 'gitleaks', 'trivy', 'codeql', 'yara', 'virustotal',
    'alientvault_otx', 'heuristic', 'ml_tier3'
  )),
  rule_id TEXT,
  rule_name TEXT,

  -- Severity & category
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  category TEXT NOT NULL, -- CWE, CVSS, Malware, Compliance, etc
  cwe TEXT, -- CWE-89, CWE-94, etc
  cve TEXT, -- CVE-2024-xxxx

  -- Message & details
  message TEXT NOT NULL,
  description TEXT,
  remediation TEXT,

  -- Location
  file_path TEXT,
  line_start INT,
  line_end INT,
  code_snippet TEXT,

  -- Metadata
  metadata JSONB DEFAULT '{}', -- Engine-specific data

  -- Suppression & false positive tracking
  suppressed BOOLEAN DEFAULT FALSE,
  suppression_reason TEXT,
  suppressed_by_user_id UUID REFERENCES auth.users(id),
  suppressed_at TIMESTAMP,

  -- False positive feedback
  marked_false_positive_by_user_id UUID REFERENCES auth.users(id),
  marked_false_positive_at TIMESTAMP,

  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now()
);
CREATE INDEX idx_findings_scan_id ON public.findings(scan_id);
CREATE INDEX idx_findings_org_id ON public.findings(org_id);
CREATE INDEX idx_findings_engine ON public.findings(engine);
CREATE INDEX idx_findings_severity ON public.findings(severity);
CREATE INDEX idx_findings_key ON public.findings(finding_key);
COMMENT ON TABLE public.findings IS 'Detailed findings from all scanning engines';

CREATE TABLE public.finding_evidence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID NOT NULL REFERENCES public.findings(id) ON DELETE CASCADE,

  -- Evidence chain
  evidence_type TEXT NOT NULL CHECK (evidence_type IN (
    'code_location', 'dependency_chain', 'vulnerability_bulletin',
    'malware_detection', 'behavior_pattern', 'configuration_issue'
  )),

  -- SHAP explainability data
  shap_base_value FLOAT,
  shap_feature_values JSONB, -- {feature_name: contribution_score}
  shap_expected_value FLOAT,

  -- Forensic audit trail
  detection_timestamp TIMESTAMP,
  detection_source TEXT,
  verification_status TEXT CHECK (verification_status IN ('pending', 'verified', 'disputed')),

  evidence_data JSONB NOT NULL,
  created_at TIMESTAMP DEFAULT now()
);
COMMENT ON TABLE public.finding_evidence IS 'Evidence and SHAP explainability for findings';

-- ============================================================================
-- COMPLIANCE & FRAMEWORKS
-- ============================================================================

CREATE TABLE public.compliance_frameworks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT UNIQUE NOT NULL, -- GDPR, HIPAA, SOX, NYDFS-23-NYCRR-500, etc
  slug TEXT UNIQUE NOT NULL,
  version TEXT, -- 1.0, 2.0, etc
  cwe_mappings TEXT[] DEFAULT ARRAY[]::TEXT[],
  description TEXT,
  created_at TIMESTAMP DEFAULT now()
);
INSERT INTO public.compliance_frameworks (name, slug, version, description) VALUES
  ('GDPR', 'gdpr', '2018', 'General Data Protection Regulation'),
  ('HIPAA', 'hipaa', '2013', 'Health Insurance Portability and Accountability Act'),
  ('SOX', 'sox', '2002', 'Sarbanes-Oxley Act'),
  ('PCI-DSS', 'pci-dss', '4.0', 'Payment Card Industry Data Security Standard'),
  ('NYDFS-23-NYCRR-500', 'nydfs', '2023', 'NY Department of Financial Services Cybersecurity Rule'),
  ('NIST-SSDF', 'nist-ssdf', '1.1', 'NIST Secure Software Development Framework'),
  ('OWASP-TOP-10', 'owasp-top-10', '2021', 'OWASP Top 10 Web Application Security Risks');

CREATE TABLE public.compliance_scan_mappings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  org_id UUID NOT NULL REFERENCES public.organizations(id),
  framework_id UUID NOT NULL REFERENCES public.compliance_frameworks(id),

  -- Compliance status per framework
  total_requirements INT DEFAULT 0,
  passing_requirements INT DEFAULT 0,
  failing_requirements INT DEFAULT 0,
  compliance_score INT DEFAULT 0, -- 0-100

  -- Details
  gaps JSONB DEFAULT '[]', -- [{requirement, finding_ids, remediation}]
  passed_checks JSONB DEFAULT '[]',

  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now(),
  UNIQUE(scan_id, framework_id)
);
CREATE INDEX idx_compliance_mappings_org_id ON public.compliance_scan_mappings(org_id);
COMMENT ON TABLE public.compliance_scan_mappings IS 'Findings mapped to compliance framework requirements';

-- ============================================================================
-- FIDUCIARY SCORING & LOGIC DRIFT
-- ============================================================================

CREATE TABLE public.fiduciary_scores (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  org_id UUID NOT NULL REFERENCES public.organizations(id),
  project_id UUID NOT NULL REFERENCES public.projects(id),

  -- Fiduciary liability model: 0-100 scale
  -- Formula: liability_score =
  --   (risk_score * 0.40) +
  --   (compliance_gap_ratio * 30) +
  --   (malware_risk * 20) +
  --   (drift_trend * 10)

  risk_component INT, -- 0-40
  compliance_component INT, -- 0-30
  malware_component INT, -- 0-20
  drift_component INT, -- 0-10

  total_liability_score INT, -- 0-100
  liability_level TEXT CHECK (liability_level IN ('low', 'medium', 'high', 'critical')),

  -- Trend tracking
  score_vs_previous_scan INT, -- delta (can be negative)
  trend_direction TEXT CHECK (trend_direction IN ('improving', 'stable', 'degrading')),

  -- Model metadata
  model_version TEXT DEFAULT '1.0',
  calibration_date DATE,

  created_at TIMESTAMP DEFAULT now()
);
CREATE INDEX idx_fiduciary_org_id ON public.fiduciary_scores(org_id);
CREATE INDEX idx_fiduciary_project_id ON public.fiduciary_scores(project_id);
COMMENT ON TABLE public.fiduciary_scores IS 'Fiduciary risk and liability scoring model';

CREATE TABLE public.logic_drift_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES public.organizations(id),
  project_id UUID NOT NULL REFERENCES public.projects(id),

  -- Drift detection
  detection_timestamp TIMESTAMP NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN (
    'threshold_breach', 'anomalous_cluster', 'trend_reversal', 'outlier'
  )),
  severity TEXT CHECK (severity IN ('info', 'warning', 'critical')),

  -- Statistical data
  baseline_value FLOAT,
  observed_value FLOAT,
  zscore FLOAT,
  confidence_interval JSONB, -- {lower: x, upper: y, confidence: 0.95}

  -- Explanation
  explanation TEXT,
  recommendation TEXT,
  affected_scan_ids UUID[],

  created_at TIMESTAMP DEFAULT now()
);
CREATE INDEX idx_drift_project_id ON public.logic_drift_events(project_id);
CREATE INDEX idx_drift_timestamp ON public.logic_drift_events(detection_timestamp DESC);
COMMENT ON TABLE public.logic_drift_events IS 'Detected anomalies and logic drift in risk patterns';

-- ============================================================================
-- ARTIFACTS & REPORTS
-- ============================================================================

CREATE TABLE public.artifacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  org_id UUID NOT NULL REFERENCES public.organizations(id),

  artifact_type TEXT NOT NULL CHECK (artifact_type IN (
    'json_result', 'pdf_report', 'html_report', 'csv_export',
    'sbom_cyclonedx', 'attachment'
  )),

  -- File storage
  storage_path TEXT NOT NULL, -- s3://bucket/org-id/scan-id/report.pdf
  file_size_bytes INT,
  content_type TEXT,

  -- Metadata
  created_at TIMESTAMP DEFAULT now(),
  expires_at TIMESTAMP, -- For temporary URLs

  created_by_user_id UUID REFERENCES auth.users(id)
);
CREATE INDEX idx_artifacts_scan_id ON public.artifacts(scan_id);
CREATE INDEX idx_artifacts_org_id ON public.artifacts(org_id);
COMMENT ON TABLE public.artifacts IS 'Generated reports and scan artifacts (S3 pointers)';

-- ============================================================================
-- AUDIT LOG (IMMUTABLE APPEND-ONLY)
-- ============================================================================

CREATE TABLE public.audit_log (
  seq BIGSERIAL PRIMARY KEY,
  id UUID DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES public.organizations(id),

  -- Event metadata
  event_type TEXT NOT NULL CHECK (event_type IN (
    'scan_started', 'scan_completed', 'scan_failed',
    'engine_started', 'engine_completed',
    'ai_analysis_completed', 'report_generated',
    'finding_suppressed', 'finding_unsuppressed',
    'compliance_check_passed', 'compliance_check_failed',
    'user_created', 'user_permission_changed', 'user_deleted',
    'scan_shared', 'scan_unshared',
    'audit_log_verified'
  )),

  -- Actor & scope
  user_id UUID REFERENCES auth.users(id),
  scope_resource_type TEXT, -- scan, project, org
  scope_resource_id UUID,

  -- Event details
  event_data JSONB NOT NULL, -- engine: count, risk_score, etc

  -- Cryptographic chain
  prev_event_hash TEXT, -- SHA256
  event_hash TEXT GENERATED ALWAYS AS (
    encode(sha256(convert_to(
      seq::text || event_type || org_id::text || event_data::text ||
      (prev_event_hash IS NOT NULL)::text,
      'utf8'
    )), 'hex')
  ) STORED,

  created_at TIMESTAMP DEFAULT now()
);
ALTER TABLE public.audit_log DISABLE ROW LEVEL SECURITY; -- Append-only, no user modification
CREATE INDEX idx_audit_log_org_id ON public.audit_log(org_id);
CREATE INDEX idx_audit_log_timestamp ON public.audit_log(created_at DESC);
CREATE INDEX idx_audit_log_event_type ON public.audit_log(event_type);
COMMENT ON TABLE public.audit_log IS 'Immutable append-only audit log with hash chaining';

-- ============================================================================
-- WEBHOOKS & INTEGRATIONS
-- ============================================================================

CREATE TABLE public.webhook_subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES public.organizations(id),

  -- Webhook config
  url TEXT NOT NULL,
  event_types TEXT[] NOT NULL, -- scan_completed, finding_critical, etc
  active BOOLEAN DEFAULT TRUE,

  -- Auth
  secret_key TEXT NOT NULL, -- HMAC-SHA256 signing

  -- Delivery tracking
  failed_attempts INT DEFAULT 0,
  last_delivery_at TIMESTAMP,
  last_error TEXT,

  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now()
);
CREATE INDEX idx_webhooks_org_id ON public.webhook_subscriptions(org_id);
COMMENT ON TABLE public.webhook_subscriptions IS 'Webhook subscriptions for event notifications';

CREATE TABLE public.webhook_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id UUID NOT NULL REFERENCES public.webhook_subscriptions(id),

  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,

  -- Delivery attempt
  attempt INT DEFAULT 1,
  http_status_code INT,
  response_body TEXT,
  delivery_timestamp TIMESTAMP,
  next_retry_at TIMESTAMP,

  created_at TIMESTAMP DEFAULT now()
);
COMMENT ON TABLE public.webhook_deliveries IS 'Webhook delivery history';

-- ============================================================================
-- MATERIALIZED VIEWS FOR DASHBOARDS
-- ============================================================================

CREATE MATERIALIZED VIEW public.org_risk_trends AS
SELECT
  org_id,
  DATE(created_at) as scan_date,
  AVG(risk_score)::INT as avg_risk,
  MAX(risk_score) as max_risk,
  COUNT(*) as scan_count,
  SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count
FROM public.scans
WHERE status = 'completed'
GROUP BY org_id, DATE(created_at);

CREATE MATERIALIZED VIEW public.findings_by_severity_org AS
SELECT
  org_id,
  severity,
  engine,
  COUNT(*) as count,
  COUNT(DISTINCT scan_id) as scan_count
FROM public.findings
GROUP BY org_id, severity, engine;

CREATE MATERIALIZED VIEW public.compliance_coverage AS
SELECT
  s.org_id,
  cf.slug as framework,
  COUNT(DISTINCT s.id) as scans_evaluated,
  AVG(csm.compliance_score)::INT as avg_compliance_score,
  SUM(CASE WHEN csm.compliance_score >= 80 THEN 1 ELSE 0 END) as passing_scans
FROM public.scans s
JOIN public.compliance_scan_mappings csm ON s.id = csm.scan_id
JOIN public.compliance_frameworks cf ON csm.framework_id = cf.id
WHERE s.status = 'completed'
GROUP BY s.org_id, cf.slug;

CREATE INDEX idx_org_risk_trends_date ON public.org_risk_trends(scan_date DESC);
```

### 2.2 Row-Level Security (RLS) Policies

```sql
-- ============================================================================
-- ENABLE RLS ON ALL TABLES
-- ============================================================================

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.compliance_scan_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fiduciary_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.logic_drift_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_subscriptions ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- POLICY: Org-level isolation
-- ============================================================================

CREATE POLICY org_isolation_on_scans ON public.scans
  USING (org_id = auth.user_org_id());

CREATE POLICY org_isolation_on_findings ON public.findings
  USING (org_id = auth.user_org_id());

CREATE POLICY org_isolation_on_compliance ON public.compliance_scan_mappings
  USING (org_id = auth.user_org_id());

CREATE POLICY org_isolation_on_fiduciary ON public.fiduciary_scores
  USING (org_id = auth.user_org_id());

-- ============================================================================
-- POLICY: Project-level access (editor/admin only can write)
-- ============================================================================

CREATE POLICY project_read_team ON public.projects
  USING (
    org_id = auth.user_org_id() AND
    (auth.user_role() IN ('admin', 'editor'))
  );

CREATE POLICY project_write_admin ON public.projects
  WITH CHECK (org_id = auth.user_org_id() AND auth.user_role() = 'admin');

-- ============================================================================
-- POLICY: Scan visibility with auth check
-- ============================================================================

CREATE POLICY scans_visible_to_org_members ON public.scans
  USING (
    org_id = auth.user_org_id() OR
    (requires_authentication = FALSE AND shared_token IS NOT NULL)
  );

CREATE POLICY scans_writable_by_creator ON public.scans
  WITH CHECK (
    org_id = auth.user_org_id() AND
    (user_id = auth.uid() OR auth.user_role() IN ('admin', 'editor'))
  );

-- ============================================================================
-- POLICY: Findings visible if scan is visible
-- ============================================================================

CREATE POLICY findings_visible_via_org ON public.findings
  USING (
    org_id = auth.user_org_id() OR
    EXISTS (
      SELECT 1 FROM public.scans s
      WHERE s.id = findings.scan_id
        AND (s.requires_authentication = FALSE AND s.shared_token IS NOT NULL)
    )
  );

-- ============================================================================
-- POLICY: Audit log append-only (all users can read own org, only backend writes)
-- ============================================================================

CREATE POLICY audit_log_read_org ON public.audit_log
  USING (org_id = auth.user_org_id());

CREATE POLICY audit_log_write_service ON public.audit_log
  WITH CHECK (auth.user_role() = 'service'); -- Only backend service role

-- ============================================================================
-- Helper Functions for RLS Context
-- ============================================================================

CREATE OR REPLACE FUNCTION auth.user_org_id() RETURNS UUID AS $$
  SELECT (auth.jwt() ->> 'org_id')::UUID;
$$ LANGUAGE SQL STABLE;

CREATE OR REPLACE FUNCTION auth.user_role() RETURNS TEXT AS $$
  SELECT COALESCE(auth.jwt() ->> 'role', 'viewer');
$$ LANGUAGE SQL STABLE;

CREATE OR REPLACE FUNCTION auth.user_permissions() RETURNS TEXT[] AS $$
  SELECT string_to_array(COALESCE(auth.jwt() ->> 'permissions', ''), ',');
$$ LANGUAGE SQL STABLE;
```

---

## PART 3: AUTH DESIGN

### 3.1 Auth Flows

```
┌────────────────────────────────────────────────────────────────────┐
│ FLOW 1: Email/Password (Dev-friendly)                              │
└────────────────────────────────────────────────────────────────────┘

User fills signup form
    │
    ├─► POST /api/auth/signup {email, password, org_name}
    │
    ├─► Backend Auth Service
    │   ├─ Validate email format + password strength
    │   ├─ Call supabase.auth.signUp({email, password})
    │   ├─ Create org + user record with role=admin
    │   └─ Send verification email
    │
    └─► Frontend receives:
        {access_token, refresh_token, user: {id, email, org_id}}
        Store in secure httpOnly cookie (server-side session)


┌────────────────────────────────────────────────────────────────────┐
│ FLOW 2: SSO (Enterprise: Okta / Azure AD / Google Workspace)        │
└────────────────────────────────────────────────────────────────────┘

Admin enables SSO in org settings → Okta SAML config (IDP metadata XML)
    │
    ├─► User clicks login page → "Login with Okta"
    │
    ├─► Frontend redirects to:
    │   https://backend/api/auth/sso/okta?redirect_uri=dashboard&org_id=xxx
    │
    ├─► Backend initiates SAML AuthnRequest
    │   ├─ Okta redirects back with SAML Response (signed)
    │   ├─ Verify signature + timestamp
    │   ├─ Extract: NameID (email), groups[]
    │   ├─ Lookup user by email
    │   │   ├─ If exists: check org + groups
    │   │   └─ If not: JIT provision (create user + assign role from group→role mapping)
    │   └─ Issue JWT with org_id + role + permissions
    │
    └─► User logged in with Okta identity


┌────────────────────────────────────────────────────────────────────┐
│ FLOW 3: CI/CD API Key Auth (GitHub Actions / GitLab CI / Jenkins)   │
└────────────────────────────────────────────────────────────────────┘

Admin generates API key in org settings
    │
    ├─► POST /api/auth/api-keys {name, scopes: ['scan:create', 'findings:read']}
    │
    ├─► Backend creates api_key record (hashed, stored in Supabase)
    │   Returns: {api_key: "ea_xxxx...xxxx", display_once: true}
    │
    ├─► CI/CD stores key in repo secrets (GitHub: AEGIS_API_KEY)
    │
    ├─► Each scan request includes:
    │   curl -X POST https://backend/api/scan \
    │     -H "Authorization: Bearer ea_xxxx" \
    │     -F "files=@code.py"
    │
    ├─► Backend validates:
    │   ├─ Hash(incoming_key) == stored_hash
    │   ├─ Check scopes: can_scan ∈ scopes
    │   ├─ Check rate limit: scans_this_month < org.max_scans_per_month
    │   └─ Create claim: org_id + project_id + source=cicd
    │
    └─► Scan runs with CI/CD org/project context


┌────────────────────────────────────────────────────────────────────┐
│ FLOW 4: Public Scan Share (Anonymous + Link)                        │
└────────────────────────────────────────────────────────────────────┘

User creates public link: POST /api/scans/{id}/share {ttl: 7 days}
    │
    ├─► Backend generates:
    │   ├─ shared_token = random(32 bytes)
    │   ├─ Stores: scans.shared_token, scans.requires_authentication = FALSE
    │   └─ ttl_expires_at = now + 7 days
    │
    ├─► Returns URL: https://dashboard/scan/xyz?token=shared_token
    │
    ├─► Unauthenticated user clicks link
    │
    ├─► Frontend GET /api/scans/{id}?token=shared_token
    │
    ├─► Backend validates:
    │   ├─ SELECT scans WHERE id AND shared_token MATCH
    │   ├─ Check NOT requires_authentication OR shared_token valid
    │   └─ RLS: allows unauthenticated access for this scan
    │
    └─► Returns scan + findings (anonymized)
```

### 3.2 JWT Structure & Claims

```json
{
  "aud": "authenticated",
  "iss": "https://backend.com",
  "sub": "user-uuid",
  "iat": 1712675400,
  "exp": 1712761800,
  "email": "user@company.com",
  "email_verified": true,

  "org_id": "org-uuid",
  "role": "admin",
  "permissions": ["scan:create", "findings:read", "compliance:manage"],

  "sso_provider": "okta",
  "sso_subject": "user@okta.com",
  "groups": ["developers", "security-team"],

  "api_key_id": null | "api-key-uuid" (if API key auth),

  "custom:org_tier": "pro",
  "custom:workspace_ids": ["ws-1", "ws-2"]
}
```

### 3.3 Role Hierarchy & Permissions Matrix

```
ROLE: admin
├─ scan:create (own org)
├─ scan:delete (own org)
├─ findings:suppress
├─ compliance:manage
├─ audit_log:read (own org)
├─ user:create (own org)
├─ user:delete (own org)
├─ billing:view
├─ org:settings:update
└─ webhook:manage

ROLE: editor
├─ scan:create (own org)
├─ findings:suppress
├─ compliance:check
├─ audit_log:read (own org)
└─ project:update

ROLE: viewer
├─ scan:read (own org)
├─ findings:read (own org)
├─ compliance:read (own org)
└─ audit_log:read (own org)

ROLE: service (internal, backend-only)
├─ ALL (backend service account)
└─ Used for: audit_log writes, webhook processing, ML pipeline

API KEY SCOPES (explicit grant per key):
├─ scan:create
├─ scan:read
├─ findings:read
├─ report:download
└─ compliance:export
```

---

## PART 4: API CONTRACT DEFINITIONS

### 4.1 Scan Lifecycle Endpoints

```yaml

POST /api/scans
  Description: Submit files for security scan
  Auth: JWT (user) | API Key (CI/CD) | Anonymous
  Body:
    files: File[] (multipart/form-data)
    org_id: UUID (required if JWT without org context)
    project_id: UUID (required if multi-project org)
    workspace_id: UUID (optional)
    scan_type: adhoc | scheduled | cicd (default: adhoc)
    metadata: {branch, commit_hash, ci_service, repo_url}
    config: {include_sbom: bool, include_pdf: bool, malware_scan: bool}
  Response (202 Accepted):
    {
      scan_id: UUID,
      status: "queued",
      position_in_queue: INT,
      estimated_time_seconds: INT,
      presigned_upload_url: STRING (if chunked upload),
      webhook_url: STRING (for async completion)
    }

GET /api/scans/{scan_id}
  Description: Retrieve scan results
  Auth: JWT | API Key | Public (if shared_token)
  Query Params:
    token: STRING (for public access)
    include: findings | compliance | artifacts | all
  Response:
    {
      id: UUID,
      status: "completed",
      total_findings: INT,
      critical_count: INT,
      risk_level: "HIGH",
      risk_score: INT,
      completed_at: ISO8601,
      findings: [
        {
          id: UUID,
          engine: "semgrep",
          severity: "CRITICAL",
          message: STRING,
          file_path: STRING,
          line_start: INT,
          remediation: STRING,
          suppressed: BOOL,
          evidence: {shap_features: {...}}
        }
      ],
      compliance_mappings: {
        GDPR: {passing: INT, failing: INT, score: INT}
      },
      fiduciary_score: {
        liability_level: "high",
        trend: "degrading",
        vs_previous: INT
      },
      artifacts: {
        pdf_report_url: STRING,
        csv_findings_url: STRING,
        sbom_url: STRING
      }
    }

GET /api/scans
  Description: List scans for org/project
  Auth: JWT | API Key
  Query Params:
    org_id: UUID (required)
    project_id: UUID (optional filter)
    status: queued|scanning|completed|failed
    limit: INT (default 50, max 500)
    offset: INT (default 0)
    sort: created_at | risk_score (default: created_at DESC)
  Response:
    {
      scans: [{...}],
      total: INT,
      limit: INT,
      offset: INT
    }

POST /api/scans/{scan_id}/cancel
  Auth: JWT (if creator or admin) | API Key
  Response: {status: "cancelled"}

DELETE /api/scans/{scan_id}
  Auth: JWT (admin only) | API Key
  Response: {deleted: BOOL}

POST /api/scans/{scan_id}/share
  Description: Create public share link
  Auth: JWT (admin/editor)
  Body: {ttl_days: INT (default 7)}
  Response: {
    shared_url: STRING,
    shared_token: STRING,
    expires_at: ISO8601
  }

```

### 4.2 Findings & Suppression Endpoints

```yaml

GET /api/findings?scan_id=xxx&severity=CRITICAL
  Auth: JWT | API Key
  Response:
    {
      findings: [{id, engine, severity, suppressed, evidence}],
      total_count: INT
    }

POST /api/findings/{finding_id}/suppress
  Auth: JWT (editor+)
  Body: {reason: STRING, ttl_days: INT (null for permanent)}
  Response: {suppressed: TRUE, suppression_expires_at: ISO8601}

POST /api/findings/{finding_id}/appeal
  Auth: JWT (creator of suppression)
  Body: {appeal_reason: STRING}
  Response: {status: "appeal_submitted"}

GET /api/findings/{finding_id}/evidence
  Auth: JWT (admin+)
  Response:
    {
      finding: {...},
      evidence_chain: [
        {type: "code_location", ...},
        {type: "shap_explainability", ...}
      ],
      audit_trail: [
        {timestamp, actor, action, details}
      ]
    }

POST /api/findings/{finding_id}/mark-false-positive
  Auth: JWT (editor+)
  Body: {reason: STRING}
  Response: {marked_false_positive: TRUE}
```

### 4.3 Compliance & Audit Endpoints

```yaml

GET /api/compliance/scan/{scan_id}
  Auth: JWT
  Response:
    {
      frameworks: {
        GDPR: {compliance_score: 85, gaps: [...]},
        HIPAA: {compliance_score: 72, gaps: [...]}
      }
    }

GET /api/audit-log?org_id=xxx&event_type=scan_completed
  Auth: JWT (admin+)
  Query: limit, offset, event_type, timestamp_from, timestamp_to
  Response:
    {
      entries: [
        {
          seq: INT,
          event_type: STRING,
          event_data: OBJECT,
          created_at: ISO8601,
          event_hash: STRING,
          prev_event_hash: STRING
        }
      ],
      total: INT
    }

GET /api/audit-log/verify
  Auth: JWT (admin+)
  Description: Verify hash chain integrity
  Response:
    {
      valid: BOOL,
      entries_checked: INT,
      broken_at_seq: INT | null
    }

POST /api/audit-log/export
  Auth: JWT (admin+)
  Body: {from_date: ISO8601, to_date: ISO8601, format: json|csv}
  Response: {export_url: STRING, expires_at: ISO8601}
```

### 4.4 Webhook Subscription Endpoints

```yaml

POST /api/webhooks
  Auth: JWT (admin)
  Body:
    {
      url: STRING,
      event_types: ["scan_completed", "finding_critical"],
      secret: STRING (will be generated if not provided)
    }
  Response:
    {
      subscription_id: UUID,
      secret: STRING (display once),
      test_payload_sent: BOOL
    }

GET /api/webhooks?org_id=xxx
  Auth: JWT (admin)
  Response: {subscriptions: [...]}

GET /api/webhooks/{id}/deliveries
  Auth: JWT (admin)
  Response: {deliveries: [{timestamp, event_type, status_code, response}]}

POST /api/webhooks/{id}/retry
  Auth: JWT (admin)
  Response: {status: "queued_for_retry"}
```

---

## PART 5: MIGRATION STRATEGY (Zero-Downtime)

### 5.1 Current State Analysis

**In-Memory Components:**
- Scan results (lost on restart)
- Finding history (only last 24h)
- Audit log (local JSON file)
- Compliance mappings (computed on-demand)

**Partial Persistence:**
- Supabase: audit_log table only
- Redis: scan queue (transient)
- S3: PDF reports only

### 5.2 Migration Phases

```
Phase 0: Preparation (Day 1-3)
├─ Deploy schema to staging Supabase
├─ Validate RLS policies in test env
├─ Build dual-write layer (write to both old + new)
└─ Test rollback procedures

Phase 1: Dual-Write (Day 4-7)
├─ Deploy backend with dual-write mode
│  ├─ All scans → in-memory ✓ + Supabase ✓
│  ├─ All findings → findings table ✓
│  ├─ All compliance → compliance_scan_mappings ✓
│  ├─ Audit log → BOTH audit_log.json + audit_log table ✓
│  └─ All errors logged, no user impact
├─ Monitor for conflicts/mismatches
└─ Data validation: count(scans in Supabase) == count(scans in memory)

Phase 2: Read Migration (Day 8-10)
├─ Switch read path to Supabase
│  ├─ GET /api/scans → Query Supabase ✓
│  ├─ GET /api/findings → Join scans + findings ✓
│  ├─ Fallback to memory if Supabase query fails
├─ Monitor query performance (target: <100ms p99)
├─ Test all dashboard views
└─ Run compliance report generation

Phase 3: Cutover (Day 11-12)
├─ Turn off dual-write (write only to Supabase)
├─ Disable in-memory scan results storage
├─ Verify no data loss
├─ Migrate remaining artifacts (PDFs, CSVs) to Supabase artifacts table
└─ Signal GO for prod

Phase 4: Post-Migration (Day 13+)
├─ Monitor error logs for 2 weeks
├─ Clean up dual-write code
├─ Archive old in-memory data
└─ Document cutover (for audit)
```

### 5.3 Dual-Write Logic (Backend Code Sketch)

```python
class ScanService:
  def create_scan(self, files, org_id, project_id):
    # Phase 1: Dual-write
    try:
      # Old path
      scan_id = self._create_scan_in_memory(files)
      results_old = self._scan(files)
      self.memory_store[scan_id] = results_old

      # New path (Supabase)
      scan_record = Supabase.table('scans').insert({
        id: scan_id,
        org_id: org_id,
        project_id: project_id,
        status: 'queued'
      }).execute()

      # Log both
      logger.info(f"Dual-write: scan {scan_id} to memory + Supabase")

    except Exception as e:
      logger.error(f"Dual-write failed: {e}", extra={
        'scan_id': scan_id,
        'failed_path': 'supabase' if supabase_error else 'memory'
      })
      # Continue if one fails

    return scan_id

  def get_scan_result(self, scan_id):
    # Phase 2: Read from Supabase with fallback
    try:
      result = Supabase.table('scans').select('*').eq('id', scan_id).execute()
      logger.info(f"Read scan {scan_id} from Supabase")
      return result
    except:
      # Fallback to memory
      return self.memory_store.get(scan_id)
```

### 5.4 Rollback Plan

**If Supabase Data Corrupt/Lost:**
1. Halt writes to Supabase (set flag: `SUPABASE_WRITE_DISABLED=true`)
2. Revert backend to previous version (in-memory only)
3. Restore Supabase from backup (AWS S3 + pg_dump daily)
4. Re-run Phase 1 dual-write after fix

**Estimated RTO:** 4 hours

---

## PART 6: PRODUCTION CI/CD & DEPLOYMENTS

### 6.1 Environment Promotion Pipeline

```
Dev (Railway Dev Project)
  └─ PR #123: "feat: add SHAP explainability"
     ├─ Deploy branch to `dev-pr-123.railway.app`
     ├─ Run integration tests
     ├─ Lint, type check, SAST scan (Semgrep)
     ├─ Security: check dependencies, sign images
     └─ If ✅ → Merge to main

Staging (Railway Staging Project)
  └─ Push to `staging` branch
     ├─ Deploy to `staging.backend.aegis.com`
     ├─ Run smoke tests (health, auth, sample scan)
     ├─ Load test: 100 concurrent scans
     ├─ Compliance check: audit log integrity, RLS policies
     └─ If ✅ → Tag `v0.5.12` on main

Production (Railway Production Project)
  └─ Tag: `v0.5.12` on main
     ├─ Approval required by Ops
     ├─ Deploy canary: 10% traffic
     │  └─ Monitor error rate, latency, audit log
     ├─ If no increase in errors → 100% traffic
     └─ Post-deploy: sanity scan, compliance verify
```

### 6.2 GitHub Actions Workflow (CD)

```yaml
name: Deploy Aegis to Production

on:
  push:
    tags:
      - 'v*'
  manual: true # Allow manual trigger

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Type Check
        run: cd backend && python -m mypy src/ --strict

      - name: SAST Scan (Semgrep)
        run: semgrep --config=p/security-audit backend/

      - name: Dependency Audit
        run: pip install safety && safety check

      - name: Build & Test
        run: |
          cd backend && poetry install
          pytest tests/ --cov=src

  deploy-staging:
    needs: validate
    runs-on: ubuntu-latest
    environment:
      name: staging
      url: https://staging.backend.aegis.com
    steps:
      - uses: actions/checkout@v4

      - name: Deploy to Railway Staging
        run: |
          railway up --environment staging
        env:
          RAILWAY_TOKEN: ${{ secrets.RAILWAY_TOKEN }}
          SUPABASE_URL: ${{ secrets.STAGING_SUPABASE_URL }}
          SUPABASE_KEY: ${{ secrets.STAGING_SUPABASE_KEY }}

      - name: Smoke Tests
        run: |
          python tests/smoke.py --host staging.backend.aegis.com

      - name: Compliance Check
        run: |
          python tests/compliance_check.py --org staging_test

  deploy-prod-canary:
    needs: deploy-staging
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://api.aegis.com
    steps:
      - uses: actions/checkout@v4

      - name: Deploy Canary (10% traffic)
        run: |
          railway up --environment production --strategy canary --percentage 10
        env:
          RAILWAY_TOKEN: ${{ secrets.RAILWAY_TOKEN }}

      - name: Monitor Canary (5 min)
        run: |
          python tests/monitor_canary.py --duration 300 --error-threshold 0.5%

      - name: Promote to 100%
        if: success()
        run: |
          railway up --environment production --strategy canary --percentage 100
```

### 6.3 Secrets Management

Store in GitHub Actions Environment Secrets:
```
PROD:
  DB_PASSWORD: *** (Supabase password)
  JWT_SECRET: *** (Supabase JWT secret)
  GEMINI_API_KEY: *** (Google Gemini)
  VIRUSTOTAL_API_KEY: *** (VirusTotal API)
  ALIENTVAULT_OTX_API_KEY: *** (AlienVault)
  OKTA_CLIENT_ID: *** (SSO)
  OKTA_CLIENT_SECRET: ***
  OPENTELEMETRY_API_KEY: *** (Datadog OTLP)
  AWS_ACCESS_KEY_ID: *** (S3 artifacts)
  AWS_SECRET_ACCESS_KEY: ***

Use in Railway env:
  SUPABASE_URL=${{ secrets.PROD_SUPABASE_URL }}
  SUPABASE_KEY=${{ secrets.PROD_SUPABASE_KEY }}
```

---

## PART 7: OBSERVABILITY BLUEPRINT

### 7.1 Logging Strategy (Datadog / Axiom)

```python
import logging
import json
from pythonjsonlogger import jsonlogger

logger = logging.getLogger(__name__)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

# Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
logger.error("Scan failed",  extra={
  'scan_id': '123-abc',
  'org_id': 'org-456',
  'error': 'VirusTotal timeout',
  'duration_ms': 5000,
  'user_id': 'user-789',
  'tags': ['production', 'scanning']
})

# All logs ship to Datadog:
# - Parse JSON
# - Extract org_id → tag for tenant filtering
# - Alert if error_rate > 1%
```

### 7.2 Metrics (Prometheus)

```python
from prometheus_client import Counter, Histogram, Gauge

# Counters
scan_total = Counter('aegis_scans_total', 'Total scans', ['org_id', 'status'])
findings_total = Counter('aegis_findings_total', 'Total findings', ['engine', 'severity'])

# Histograms
scan_duration = Histogram('aegis_scan_duration_seconds', 'Scan duration', buckets=[1, 5, 10, 30, 60, 120])
api_latency = Histogram('aegis_api_latency_ms', 'API latency', buckets=[10, 50, 100, 250, 500, 1000])

# Gauges
queue_depth = Gauge('aegis_queue_depth', 'Scan queue depth')
org_scans_this_month = Gauge('aegis_org_scans_monthly', 'Scans this month', ['org_id'])

# Usage
scan_total.labels(org_id='org-123', status='completed').inc()
scan_duration.observe(45.2)
queue_depth.set(12)
```

### 7.3 Distributed Traces (OpenTelemetry → Datadog)

```python
from opentelemetry import trace, metrics
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

otlp_exporter = OTLPSpanExporter(
  endpoint="https://api.datadoghq.com:4317",
  headers={"dd-api-key": os.getenv("DATADOG_API_KEY")}
)
trace.set_tracer_provider(TracerProvider())
trace.get_tracer_provider().add_span_processor(
  BatchSpanProcessor(otlp_exporter)
)

tracer = trace.get_tracer(__name__)

@tracer.start_as_current_span("scan_submission")
def submit_scan(files, org_id):
  tracer.current_span().set_attribute("org_id", org_id)
  tracer.current_span().set_attribute("file_count", len(files))

  with tracer.start_as_current_span("validate_org"):
    validate_org(org_id)

  with tracer.start_as_current_span("store_files"):
    store_files(files)

  with tracer.start_as_current_span("queue_scan"):
    scan_id = queue_scan(org_id)

  return scan_id
```

Datadog displays:
```
Scan Submission
├─ Validate Org (45ms)
├─ Store Files (230ms)
└─ Queue Scan (12ms)
Total: 287ms
```

### 7.4 SLOs & Alert Rules

```yaml
SLO: Scan Completion (99.5% availability)
├─ Threshold: p99 latency < 120 seconds
├─ Target: 99.5% of scans complete successfully
├─ Error budget: 3.6 hours/month
├─ Alert if: Error rate > 1% for 5 min
└─ Escalation: Page on-call after 15 min

SLO: Audit Log Integrity (100%)
├─ Threshold: Zero hash chain breaks
├─ Daily verification check (automated)
├─ Alert if: Broken chain detected
└─ Escalation: Immediate (security incident)

SLO: Auth Response Time (500ms p99)
├─ JWT validation < 50ms
├─ SSO callback < 200ms
├─ Alert if: p99 > 500ms for 10 min

SLO: RLS Policy Enforcement (100%)
├─ Zero unauthorized data access
├─ Weekly audit of failed queries
├─ Alert on: Denied RLS check (possible attack)
```

Alert Rules (Datadog):
```yaml
- name: High Error Rate
  condition: error_rate > 1% for 5 minutes
  notify: team-oncall

- name: Queue Depth Spike
  condition: queue_depth > 500 for 10 minutes
  notify: team-engineering

- name: Audit Log Corruption
  condition: audit_log.verify.valid == false
  notify: team-security, team-oncall

- name: Compliance Scan Failed
  condition: count(compliance_check == failed) > 3 in 1 hour
  notify: team-compliance
```

---

## PART 8: ADVANCED FEATURES

### 8.1 Logic Drift Detection

**Objective:** Detect anomalies in risk patterns over time for the same project.

**Algorithm:**
```sql
-- Every night: batch compute drift stats
INSERT INTO public.logic_drift_events
SELECT
  org_id, project_id,
  NOW() as detection_timestamp,
  CASE
    WHEN ABS(zscore) > 3 THEN 'anomalous_cluster'
    WHEN trend_reversal_180d THEN 'trend_reversal'
    WHEN recent_avg > baseline_avg * 1.5 THEN 'threshold_breach'
    ELSE 'outlier'
  END as event_type,

  baseline_avg,
  recent_avg,
  (recent_avg - baseline_avg) / stddev_population(recent_avg) as zscore,

  'Risk suddenly increased 45% — investigate new malware or compliance regression'
  as explanation

FROM (
  -- Rolling 90-day baseline  vs last 7 days
  SELECT
    org_id, project_id,
    AVG(CASE WHEN age(NOW(), created_at) BETWEEN 90 AND 30 DAYS
        THEN risk_score ELSE NULL END) as baseline_avg,
    AVG(CASE WHEN age(NOW(), created_at) < 7 DAYS
        THEN risk_score ELSE NULL END) as recent_avg,
    ...
  FROM scans
  WHERE status = 'completed'
  GROUP BY org_id, project_id
)
WHERE ABS(zscore) > 3 OR recent_avg > baseline_avg * 1.5;
```

### 8.2 SHAP-Based Explainability Validation

**Objective:** Generate evidence for why a finding flagged.

```python
import shap
import numpy as np

def generate_finding_explanation(finding, code_context):
  """
  Use SHAP to explain Semgrep finding.

  Input: {rule_id, code_snippet, severity}
  Output: {base_value, feature_values, expected_value}
  """

  # Feature extraction
  features = extract_code_features(code_context)
  # {
  #   'has_user_input': 1,
  #   'direct_sql_concat': 0.8,
  #   'no_parameterization': 1,
  #   'string_interpolation': 0.9
  # }

  # Load pretrained model (or use heuristic)
  model = load_semgrep_explainer_model()

  # SHAP kernel explainer
  explainer = shap.KernelExplainer(model.predict, shap.sample(features, 100))
  shap_values = explainer.shap_values(features)

  # Store  evidence
  return {
    'base_value': explainer.expected_value,
    'feature_contributions': dict(zip(features.keys(), shap_values[0])),
    'top_3_reasons': sorted(
      zip(features.keys(), shap_values[0]),
      key=lambda x: abs(x[1]),
      reverse=True
    )[:3]
  }

# Example Result:
# {
#   'base_value': -2.1,  (neutral)
#   'top_3_reasons': [
#     ('has_user_input', +3.5),        → Signal present
#     ('no_parameterization', +2.8),    → Vulnerable pattern
#     ('direct_sql_concat', +1.2)       → Risk indicator
#   ]
# }
```

### 8.3 Fiduciary Risk Score Model

**Formula:**
```
FIDUCIARY_SCORE =
  (risk_score * 0.40) +
  (compliance_gap_ratio * 30) +
  (malware_detected * 20) +
  (drift_trend * 10)

Where:
- risk_score: 0-100 (from Gemini AI)
- compliance_gap_ratio: (failing_checks / total_checks) * 100
- malware_detected: presence of CRITICAL malware (binary 0/20)
- drift_trend: change from baseline (-10 to +10)

Tiers:
- 0-25: Low liability risk
- 26-50: Medium (requires quarterly reviews)
- 51-75: High (requires remediation plan)
- 76-100: Critical (board notification, liability insurance)
```

### 8.4 Tier 3 ML Malware Detection Pipeline

**Architecture:**
```
┌─────────────────────────────────────────┐
│ File received (binary or source)         │
│ - Collect 500+ static features           │
│ - Runtime behavior (sandboxed)           │
│ - Network activity                        │
│ - PE headers, entropy, etc                │
└───────────────┬─────────────────────────┘
                │
         ┌──────▼──────────┐
         │ Feature Set (500D) │
         │ (normalized)     │
         └────────┬────────┘
                │
         ┌──────▼──────────────────┐
         │ Ensemble Models         │
         ├─ Random Forest          │
         ├─ Gradient Boosted Trees │
         ├─ Transformer (5K sample) │
         └───────┬────────────────┘
                │
         ┌──────▼──────────────────┐
         │ Voting Classifier       │
         │ Threshold: 0.75 score   │
         └───────┬────────────────┘
                │
         ┌──────▼──────────────────┐
         │ Decision               │
         ├─ Malware: alert + block │
         ├─ Suspicious: flag       │
         └─ Clean: pass            │
```

**Training Data:**
- YARA + VirusTotal corpus (100k samples)
- Publicly disclosed exploits
- Botnet/ransomware samples (from security repos)
- False positive feedback loop (user feedback)

---

## PART 9: SECURITY HARDENING CHECKLIST

### 9.1 OWASP ASVS v4.0 Mapping

| Control | Status | Implementation |
|---------|--------|-----------------|
| **V1: Architecture** | ✅ | Service boundaries, RLS, auth token validation |
| **V2: Authentication** | ✅ | Supabase Auth, JWT, MFA enforced for admin |
| **V3: Session Mgmt** | ✅ | JWT exp=1h, refresh via HttpOnly cookies |
| **V4: Access Control** | ✅ | RLS policies, RBAC role hierarchy, project isolation |
| **V5: CORS** | ⚠️ | Allowed origins: *.aegis.com, localhost:3000 |
| **V6: Crypto** | ✅ | TLS 1.2+, AES-256 at rest (Supabase), hash: SHA-256 |
| **V7: Error Handling** | ✅ | No stack traces in 500 responses, detailed logs only |
| **V8: Data Protection** | ✅ | Encrypted PII (hashed emails), audit log encrypted |
| **V9: Crypto Failures** | ✅ | No plaintext secrets, rotation quarterly |
| **V10: Malicious Code** | ✅ | SAST on all deps, no eval(), no dynamic imports |
| **V11: Business Logic** | ✅ | Scan quota enforcement, duplicate detection |
| **V12: File Upload** | ✅ | Whitelist exts, max 500MB, scan for malware |
| **V13: API Security** | ✅ | Rate limit 100 req/min, JWT validation, audit log |
| **V14: Config** | ✅ | No secrets in repo, env-var only |

### 9.2 SOC 2 Type II Controls

```
CC6.1: Logical and Physical Access Controls
├─ MFA enforced for production access
├─ SSH key rotation quarterly
├─ VPN required for admin dashboards
├─ Audit log: all access attempts logged

CC7.1: System Monitoring and Activity Detection
├─ Datadog/Axiom logs all API calls
├─ Alert on anomalous access (>1k reqs/min, 50+ failed auths)
├─ Intrusion detection: check for SQL injection attempts

CC9.1: Incident Response
├─ Runbook: https://wiki/oncall/incidents
├─ Page on-call for data breaches or audit log corruption
├─ 1-hour response SLA for critical alerts
├─ Post-incident review and documentation

CC9.2: Disaster Recovery
├─ Daily Supabase backups to S3 (cross-region)
├─ RTO: 4 hours, RPO: 1 hour
├─ Test restore quarterly
└─ DRP runbook documented
```

### 9.3 NYDFS 23-NYCRR-500 Alignment

| Requirement | Implementation |
|-------------|-----------------|
| **500.01 Cybersecurity Program** | Annual risk assessment + policy docs |
| **500.02 Penetration Testing** | Annual + ad-hoc (after major changes) |
| **500.03 Risk Assessments** | Quarterly threat modeling |
| **500.04 Audit Log** | 7-year retention, immutable, hash-chained |
| **500.05 Encryption** | TLS 1.2+ in transit, AES-256 at rest |
| **500.06 MFA** | Enforced for admin accounts |
| **500.07 Access Controls** | RLS + RBAC, principle of least privilege |
| **500.08 Incident Notification** | 72-hour notification to affected users |
| **500.09 3rd Party Risk** | Vendor assessments (VirusTotal, Okta, AWS) |
| **500.10 Employee Training** | Annual InfoSec training |
| **500.11 Data Breach Warning** | Public notice within 30 days |

### 9.4 Incident Response Runbooks

**Runbook: Data Breach (Data Exfiltration)**
```
1. Detect: Datadog alert on "unusual_data_export" > 10 GB in 1 hour
2. Isolate: Kill database connection, pause API
3. Investigate:
   - Query audit_log WHERE event_type IN ('scan_shared', 'report_download')
   - Check last 6 hours of access
   - Determine affected org + user
4. Contain:
   - Revoke user API keys
   - Invalidate JWT tokens for that org
   - Notify user and compliance team
5. Recover:
   - Reset affected user password
   - Re-enable API after 24h review
6. Document: Incident ticket + lessons learned
```

**Runbook: Audit Log Corruption**
```
1. Detect: Daily hash-chain verification fails
2. Alert: Page on-call immediately (CRITICAL)
3. Isolate: Set AUDIT_LOG_READ_ONLY=true in env
4. Investigate:
   - Identify which seq has broken hash
   - Query Supabase WAL logs for unauthorized UPDATE
5. Recover:
   - Restore from S3 backup (daily snapshots)
   - Re-run integrity check
6. Root cause: Check RLS policies for gaps
7. Notify: Compliance team + customers (if audit log affected)
```

---

## PART 10: PERFORMANCE & SCALE PLAN

### 10.1 Capacity Estimates

```
Baseline (Current):
├─ Scans/day: 100
├─ Avg scan time: 45s
├─ Findings/scan: 15
├─ Users: 10 orgs × 5 users = 50

Year 1 Target:
├─ Scans/day: 10,000 (100x growth)
├─ Concurrent scans: 50 (peak)
├─ Database rows:
│  ├─ scans: 365k
│  ├─ findings: 5.5M
│  ├─ audit_log: 10M entries
│  └─ compliance_mappings: 2M
├─ Storage:
│  ├─ Supabase: ~50 GB
│  ├─ S3 artifacts: ~100 GB
│  ├─ Redis queue: 2-5 GB

Infrastructure Costs (Annual):
├─ Railway backend: $200/month = $2,400
├─ Supabase (dedicated): $500/month = $6,000
├─ S3 storage + data transfer: $100/month = $1,200
├─ Datadog logs: $50/month = $600
├─ Total: ~$10,200/year (at scale)
```

### 10.2 Concurrent Scan Model

```python
# Config
MAX_CONCURRENT_SCANS = 4
QUEUE_WAIT_TIMEOUT = 5 min
SCAN_TIMEOUT = 2 min

# Worker pool (Bull + Redis)
worker_pool = WorkerPool(
  concurrency=MAX_CONCURRENT_SCANS,
  max_attempts=3,
  backoff='exponential'
)

# Prioritization
queue.add(job={
  scan_id,
  priority: 10 (urgency, 0-100)
}, {
  priority: 10  # Lower = higher priority in Bull
})

# Example: CI/CD scan (priority=1) bumps adhoc scan(priority=50) down
```

### 10.3 Database Optimization

```sql
-- Indexes for common queries
CREATE INDEX CONCURRENTLY idx_scans_org_created
  ON scans(org_id, created_at DESC)
  WHERE status = 'completed';

CREATE INDEX CONCURRENTLY idx_findings_scan_severity
  ON findings(scan_id, severity)
  WHERE suppressed = FALSE;

-- Partitioning by org_id (sharding benefit)
CREATE TABLE scans_org_1 PARTITION OF scans
  FOR VALUES WITH (MODULUS 10, REMAINDER 1);

-- Materialized View Refresh (hourly)
REFRESH MATERIALIZED VIEW CONCURRENTLY org_risk_trends;

-- Query optimization for dashboard
EXPLAIN ANALYZE
SELECT
  DATE(s.created_at) as date,
  COUNT(*) as scan_count,
  AVG(s.risk_score) as avg_risk
FROM scans s
WHERE s.org_id = $1 AND s.created_at > NOW() - INTERVAL '90 days'
GROUP BY DATE(s.created_at)
ORDER BY date DESC;
-- Target: < 500 ms
```

### 10.4 Queuing & Backpressure

```python
# Backpressure strategy
class ScanQueue:
  def __init__(self, max_queue_size=1000):
    self.max_queue_size = max_queue_size
    self.redis = Redis(...)

  def enqueue(self, scan_job):
    queue_size = self.redis.llen('scan_queue')

    if queue_size >= self.max_queue_size:
      # Backpressure: reject with 503 Unavailable
      raise ServiceUnavailable(
        f"Queue full ({queue_size}/{self.max_queue_size}). Retry in 60s"
      )

    self.redis.rpush('scan_queue', json.dumps(scan_job))

    return {
      'status': 'queued',
      'position': queue_size + 1,
      'estimated_wait_seconds': calculate_eta(queue_size)
    }

  def calculate_eta(self, queue_size):
    # Assume 4 concurrent workers, 45s avg scan time
    return (queue_size / 4) * 45
```

---

## PART 11: 30/60/90 DAY EXECUTION ROADMAP

### Days 1-30: Foundation & Auth

**Goals:** Persistent data layer + multi-tenant auth ready

**Sprint 1 (Days 1-7):**
- [ ] Deploy Supabase PostgreSQL (18 core tables)
- [ ] Create RLS policies (12 policies, test coverage >90%)
- [ ] Implement JWT validator middleware
- [ ] Build auth service: signup/login/SSO (Okta mock)
- **Acceptance:** Auth tests pass, RLS policies verified in staging
- **Staffing:** 1 Backend Lead + 1 DB Admin + 1 QA

**Sprint 2 (Days 8-14):**
- [ ] Dual-write layer deployed (in-memory + Supabase)
- [ ] Scan migration pipeline (in-memory → Supabase)
- [ ] Audit log moved to Supabase (append-only)
- [ ] All 4 compliance frameworks loaded
- **Acceptance:** zero data loss in load test, query latency <100ms
- **Staffing:** same

**Sprint 3 (Days 15-22):**
- [ ] Read-path migration (GET /api/scans → Supabase)
- [ ] Dashboard migrated to use Supabase queries
- [ ] API performance testing (target: p99 < 200ms)
- [ ] Rollback procedures tested
- **Acceptance:** All GET endpoints use Supabase, no fallback to memory
- **Staffing:** +1 frontend for dashboard updates

**Sprint 4 (Days 23-30):**
- [ ] Staging cutover (dual-write disabled)
- [ ] Production readiness review
- [ ] Compliance audit log export tested
- [ ] SLO baseline established
- **Acceptance:** Staging fully persistent, prod ready to go
- **KPIs:**
  - Zero data loss in migration
  - p99 <200ms for all queries
  - RLS verified: zero unauthorized access
  - Audit trail: 100% of events logged

### Days 31-60: Advanced Features & Observability

**Goals:** Explainability + drift detection + production monitoring

**Sprint 5 (Days 31-38):**
- [ ] SHAP integration (generate evidence for top 100 findings)
- [ ] Fiduciary scoring model deployed (formula validated)
- [ ] Logic drift detection baseline computed
- [ ] Datadog / Axiom logging configured
- **Acceptance:** SHAP features tested on sample findings, drift model calibrated
- **Staffing:** +1 ML engineer

**Sprint 6 (Days 39-46):**
- [ ] Prometheus metrics production-ready
- [ ] SLOs defined + alerts configured
- [ ] Distributed tracing deployed (OTEL → Datadog)
- [ ] Dashboard created in Datadog (key metrics)
- **Acceptance:** All 3 pillars (logs, metrics, traces) streaming to Datadog
- **Staffing:** +1 DevOps / Observability engineer

**Sprint 7 (Days 47-54):**
- [ ] Tier 3 ML malware model trained (on YARA corpus)
- [ ] ML pipeline integrated (async, non-blocking)
- [ ] A/B test: Tier 1 vs Tier 1+2+3 (accuracy comparison)
- [ ] Training data update process documented
- **Acceptance:** ML model accuracy >95% on test set, <2s latency per file
- **Staffing:** +1 ML engineer (continued)

**Sprint 8 (Days 55-60):**
- [ ] Compliance audit completed (OWASP, SOC 2, NYDFS partial)
- [ ] Incident response runbooks written + tested
- [ ] Penetration test executed (focused on auth + RLS)
- [ ] Security hardening checklist signed off
- **Acceptance:** Zero critical vulns found, compliance gap list documented
- **KPIs:**
  - SHAP: 95%+ findings have explainability evidence
  - Drift: 100+ anomalies detected in test dataset
  - Monitoring: SLO compliance 99.5%+
  - Security: Zero critical vulns

### Days 61-90: Production Stabilization & Scale

**Goals:** Enterprise-ready, SOC 2 compliance, certified scale

**Sprint 9 (Days 61-68):**
- [ ] SSO production deployment (Okta / Azure AD)
- [ ] JIT provisioning tested with customer's Okta org
- [ ] Group-to-role mapping validated
- [ ] API key authentication for CI/CD hardened
- **Acceptance:** 2+ customers successfully use SSO
- **Staffing:** 1 backend + 1 product for integration

**Sprint 10 (Days 69-76):**
- [ ] Multi-org admin dashboard built
- [ ] Billing integration (Stripe hooks)
- [ ] Usage billing model tested (scans/month quota)
- [ ] Quota enforcement tested (rate limiter)
- **Acceptance:** Billing system end-to-end working in staging
- **Staffing:** +1 billing engineer

**Sprint 11 (Days 77-84):**
- [ ] Load testing: 100 concurrent scans, sustained
- [ ] Database query performance tuned (all <1s p99)
- [ ] Cache warming strategy for compliance data
- [ ] Cost optimization: identify >20% savings opportunities
- **Acceptance:** 100 concurrent scans completed, <$10k/month COGS
- **Staffing:** +1 DevOps / performance engineer

**Sprint 12 (Days 85-90):**
- [ ] SOC 2 audit kickoff (Type II evidence collected)
- [ ] Customer documentation + FAQs
- [ ] Go-to-market collateral (product sheets, case studies)
- [ ] Production incident drill (simulate data breach)
- [ ] Production launch approval
- **Acceptance:** Board sign-off, customer beta program launched
- **KPIs (End of Q2):**
  - Uptime: 99.5%+ SLO
  - Latency: p99 <200ms for scans
  - Audit log: 100% integrity verified
  - Compliance: SOC 2 roadmap on track
  - Scale: 10,000 scans/day capacity proven
  - Revenue: $X MRR from 5+ enterprise pilots

### Dependency Graph

```
Auth (Sprint 1)
  ├─► RLS Policies (Sprint 1)
  ├─► Dual-Write (Sprint 2)
  │   └─► Read Migration (Sprint 2)
  │       └─► Staging Cutover (Sprint 4)
  │           └─► Production Launch (Sprint 12)
  └─► SSO Integration (Sprint 9)

Observability (Sprints 6-7)
  └─► SLOs & Alerting (Sprint 6)
      └─► Incident Drills (Sprint 12)

Security (Sprints 1,3,9)
  ├─► Compliance Audit (Sprint 8)
  └─► Penetration Test (Sprint 8)
      └─► SOC 2 Audit (Sprint 12)

ML/AI (Sprint 7)
  └─► Tier 3 Integration (Sprint 7)
```

---

## PART 12: TOP 10 TECHNICAL RISKS & MITIGATIONS

| # | Risk | Severity | Impact | Mitigation |
|---|------|----------|--------|-----------|
| 1 | **RLS Policy Bypass** | 🔴 CRITICAL | Data leak, compliance failure | Weekly penetration testing, fuzzing of RLS policies, emergency patch procedure |
| 2 | **Audit Log Corruption** | 🔴 CRITICAL | SOC 2 failure, non-compliance | Daily hash-chain verification, immutable S3 backup, versioned rollback |
| 3 | **Scan Queue Collapse** | 🟠 HIGH | DoS, user experience, revenue impact | Backpressure + rate limiting, auto-scaling workers, SLA enforcement |
| 4 | **Gemini API Rate Limit** | 🟠 HIGH | Risk analysis delayed, SLA miss | Query expiration backoff, heuristic fallback, budget alerts |
| 5 | **Supabase Connection Loss** | 🟠 HIGH | Scans fail, no persistence | Redis persist layer, connection pooling, failover to read-replica |
| 6 | **Drift Detection False Positives** | 🟡 MEDIUM | Alert fatigue, customer churn | Strict threshold calibration (zscore > 3), statistical validation, manual review loop |
| 7 | **SHAP Computation Timeout** | 🟡 MEDIUM | Evidence unavailable, frustration | Time-bound computation, fallback to heuristic explanation, async generation |
| 8 | **ML Model Training Data Taint** | 🟡 MEDIUM | Accuracy degradation, customer reports | Data versioning, model validation on holdout set, retraining guardrails |
| 9 | **S3 Artifact Loss** | 🟡 MEDIUM | Reports unavailable | Enable S3 versioning + MFA delete, cross-region replication, cost: +$20/month |
| 10 | **SSO Configuration Vulnerability** | 🟡 MEDIUM | Unauthorized access, compliance gap | Okta config audits quarterly, SAML assertion validation, JIT disable switch |

**Risk Scoring Formula:**
```
Risk Score = Likelihood (1-5) × Impact (1-5) × (1 - Mitigation Effectiveness %)
Green (1-8), Yellow (9-15), Orange (16-20), Red (21-25)
```

---

## APPENDIX A: Schema Migration DDL (From Staging to Prod)

```sql
-- Step 1: Backup before migration
\copy (SELECT * FROM scans LIMIT 1000000) TO '/tmp/scans_backup.csv' WITH CSV;

-- Step 2: Create indices concurrently (zero downtime)
CREATE INDEX CONCURRENTLY idx_scans_org_risk_date
  ON scans(org_id, risk_score DESC, created_at DESC);

-- Step 3: Enable read replicas (for reporting queries)
ALTER SYSTEM SET max_wal_senders = 3;
ALTER SYSTEM SET wal_level = logical;
SELECT pg_reload_conf();

-- Step 4: Enable pgvector for future ML
CREATE EXTENSION IF NOT EXISTS vector;

-- Verify migration
SELECT
  schemaname, tablename, indexname, idx_scan_key
FROM pg_indexes
WHERE indexdef LIKE '%CONCURRENTLY%'
LIMIT 10;
```

---

## APPENDIX B: Sample Test Cases for RLS

```python
# test_rls.py
import pytest
from supabase import create_client

@pytest.fixture
def org_a_user():
  """User with access to Org A only"""
  return {
    'jwt': generate_jwt(org_id='org-a', role='editor'),
    'org_id': 'org-a'
  }

@pytest.fixture
def org_b_user():
  """User with access to Org B only"""
  return {
    'jwt': generate_jwt(org_id='org-b', role='viewer'),
    'org_id': 'org-b'
  }

def test_org_isolation_scans(org_a_user, org_b_user):
  """Org A user cannot see Org B scans"""

  # Org A user queries scans
  sb_a = create_client(url, key)
  sb_a.headers['Authorization'] = f'Bearer {org_a_user["jwt"]}'

  result_a = sb_a.table('scans').select('id').execute()
  org_a_scan_ids = [s['id'] for s in result_a.data]

  # Org B user queries scans
  sb_b = create_client(url, key)
  sb_b.headers['Authorization'] = f'Bearer {org_b_user["jwt"]}'

  result_b = sb_b.table('scans').select('id').execute()
  org_b_scan_ids = [s['id'] for s in result_b.data]

  # Assert no overlap
  assert set(org_a_scan_ids) & set(org_b_scan_ids) == set()

def test_rlss_suppress_finding(org_a_user):
  """Only creator can suppress a finding"""

  # Org A editor creates finding
  sb = create_client(url, key)
  sb.headers['Authorization'] = f'Bearer {org_a_user["jwt"]}'

  finding_id = '...'
  response = sb.table('findings').update({
    'suppressed': True,
    'suppressed_by_user_id': org_a_user['user_id']
  }).eq('id', finding_id).execute()

  assert response.data is not None  # Success
```

---

## SUMMARY: IMPLEMENTATION ROADMAP AT A GLANCE

| Phase | Days | Focus | Deliverables | GTM |
|-------|------|-------|--------------|-----|
| **Foundation** | 1-30 | Auth + Persistence | Supabase + RLS + JWT | N/A |
| **Advanced** | 31-60 | Observability + ML | SHAP + Drift + Metrics | Closed Beta |
| **Production** | 61-90 | Scale + Compliance | SSO + SOC 2 + Load Tests | General Availability |

**Budget:** 3 engineers × 3 months = $450k (salary) + $40k (infra + tools)
**Revenue Target:** $50-100k MRR by end of Q3
**Cost Structure:** $10k/month fixed + $0.10 per scan

---

**End of Enterprise Architecture Blueprint**
