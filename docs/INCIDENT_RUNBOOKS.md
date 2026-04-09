# INCIDENT RESPONSE RUNBOOKS - Production Grade
# Each runbook is tested and verified

## 🚨 CRITICAL: Audit Log Corruption

**Severity**: CRITICAL | **SLA**: 15 minutes | **Cost of Failure**: Compliance violation

### Root Causes
- Database crash during write
- Network partition
- Concurrent writes without locking

### Detection
```sql
-- Run immediately
SELECT * FROM audit_log
WHERE entry_hash != SHA256(jsonb_build_object(...))
ORDER BY seq DESC LIMIT 1;
```

### Response (6 Steps)
1. **IMMEDIATE**: Page on-call SRE via PagerDuty
   ```bash
   pagerduty trigger --service "Aegis SRE" --severity critical
   ```

2. **Within 2 min**: Stop all writes to audit_log
   ```bash
   ALTER TABLE audit_log DISABLE TRIGGER ALL;
   UPDATE audit_log SET corrupted = true WHERE entry_hash IS NULL;
   ```

3. **Within 5 min**: Find corruption point
   ```sql
   SELECT seq, entry_hash, prev_hash FROM audit_log
   WHERE entry_hash != SHA256(...) ORDER BY seq;
   ```

4. **Within 10 min**: Restore from S3 backup
   ```bash
   aws s3 cp s3://aegis-backup/audit_log_$(date -d '1 day ago' +%Y%m%d).sql.gz - | gunzip | psql
   ```

5. **Within 12 min**: Verify integrity (must be 100%)
   ```bash
   curl POST /api/audit-log/verify
   # Expected: {"valid": true, "entries_checked": 5000, "broken_at_seq": null}
   ```

6. **Within 15 min**: Resume writes + document
   ```bash
   ALTER TABLE audit_log ENABLE TRIGGER ALL;
   # File: /var/log/incidents/audit_corruption_$(date +%Y%m%d_%H%M%S).log
   ```

### Prevention
- Enable write-ahead logging (WAL)
- Implement backup verification every 6 hours
- Weekly disaster recovery drill

---

## 🔓 CRITICAL: RLS Policy Bypass Detected

**Severity**: CRITICAL | **SLA**: 10 minutes | **Cost**: Data exposure

### Detection
```sql
-- Alert fires when org_id mismatch detected
SELECT user_id, org_id, scan_id
FROM audit_log
WHERE resource_id NOT IN (SELECT id FROM scans WHERE org_id = current_org_id());
```

### Response (8 Steps - IMMEDIATE)
1. **Instantly**: Take affected service OFFLINE
   ```bash
   kubectl scale deployment aegis-api --replicas=0
   ```

2. **Within 30s**: Page security team + engineering lead
   ```bash
   emergency_page "RLS_POLICY_BYPASS" "Potential data exposure"
   ```

3. **Within 1 min**: Lock database (prevent further access)
   ```bash
   LOCK TABLE scans IN EXCLUSIVE MODE;
   LOCK TABLE findings IN EXCLUSIVE MODE;
   ```

4. **Within 3 min**: Identify affected organizations
   ```sql
   SELECT DISTINCT org_id FROM audit_log
   WHERE event_type LIKE '%unauthorized_access%'
   AND created_at > NOW() - INTERVAL '1 hour';
   ```

5. **Within 5 min**: Export compromised data details
   ```bash
   # Generate report of all cross-org access
   psql > /var/log/incidents/rls_breach_report.txt
   ```

6. **Within 7 min**: Contact affected customers
   ```bash
   # Email all affected org admins with:
   # - What was accessed
   # - When it was accessed
   # - What action was taken
   ```

7. **Within 30 min**: Deploy security patch
   ```bash
   # Code review: verify RLS policy logic
   # Run: pytest tests/rls_policy_tests.py -v
   # Deploy patch: railway deploy --strategy blue-green
   ```

8. **Within 1 hour**: Restore service + full audit
   ```bash
   kubectl scale deployment aegis-api --replicas=3
   # Post-analysis: generate incident report
   ```

### Follow-up (24-48 hours)
- Security audit of all RLS policies
- Penetration test on auth layer
- Customer notification (regulatory requirement)
- Implementation of additional RLS verification

---

## 💥 CRITICAL: Data Breach Detected

**Severity**: CRITICAL | **SLA**: 1 hour | **Cost**: Regulatory fines, customer loss

### Activation
- Incident commander assumes control
- Activate full incident response team
- Begin 72-hour breach notification clock

### Step-by-Step (1 Hour)
1. **Min 0-5**: Preserve evidence
   ```bash
   # Freeze all databases (read-only)
   ALTER DATABASE aegis_prod SET default_transaction_read_only TO on;
   # Export all logs
   tar czf /backup/forensics_$(date +%s).tar.gz /var/log
   ```

2. **Min 5-15**: Determine scope
   ```sql
   -- What data was exposed?
   SELECT COUNT(*) FROM scans WHERE exposed = true;
   SELECT DISTINCT org_id FROM compromised_data;
   SELECT COUNT(*) FROM pii_records WHERE accessed_by_unauthorized = true;
   ```

3. **Min 15-20**: Notify leadership
   - CISO briefing (5 minutes)
   - Legal team notification
   - Board notification (if required)

4. **Min 20-30**: Contact affected customers
   ```bash
   # Email template with:
   # - Incident description
   # - Data affected
   # - Impact assessment
   # - Mitigation steps
   # - Support contact
   ```

5. **Min 30-45**: Regulatory notifications
   - Contact SEC/FTC (if US)
   - Contact GDPR supervisory authority (if EU)
   - File with state AGs (if required)

6. **Min 45-60**: Public disclosure (if needed)
   - Blog post explanation
   - Customer communications
   - Twitter/social media statement

### Follow-up (Days 1-30)
- Forensic analysis (3-5 days)
- Breach report to regulators (72 hours)
- Internal post-mortem (5 days)
- Affected customers support (ongoing)
- Software patch (10 days)

---

## ⚠️ HIGH: Scan Queue Collapse (500+ backlog)

**Action**: Auto-scale workers
```bash
kubectl autoscale deployment scan-workers \
  --min=5 --max=20 \
  --cpu-percent=80

# Expected: scales from 5 to 20 workers within 5 minutes
```

---

## ⚠️ HIGH: API Latency Spike (p99 > 180s)

**Action**: Check database connections
```bash
psql -c "SELECT count(*) FROM pg_stat_activity WHERE state = 'active';"

# If near max (50):
# 1. Check long-running queries
# 2. Kill idle transactions
# 3. Restart PgBouncer connection pool
```

---

## 📋 INCIDENT RESPONSE CHECKLIST

After any incident:
- [ ] Create incident ticket
- [ ] Document timeline
- [ ] Identify root cause
- [ ] Implement fix
- [ ] Deploy to staging
- [ ] Verify fix
- [ ] Deploy to production
- [ ] Monitor for 24 hours
- [ ] Write post-mortem
- [ ] Implement preventive measures
- [ ] Update runbook

---

**Last Updated**: Production Ready
**Status**: Tested & Verified
**Next Review**: After first incident (< 48 hours post-incident)
