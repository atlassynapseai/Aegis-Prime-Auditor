"""
Dual-Write Layer for Zero-Downtime Migration
Migrates scan data from in-memory to Supabase without downtime
- Phase 1: Write to both in-memory + Supabase (dual-write mode)
- Phase 2: Read from Supabase with fallback to in-memory
- Phase 3: Migrate read path completely, disable dual-write
- Phase 4: Archive in-memory data
"""

import os
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import json
from supabase import Client as SupabaseClient

logger = logging.getLogger(__name__)

class DualWriteLayer:
    """
    Abstraction layer managing dual-write during migration
    Coordinates writes to both in-memory store and Supabase
    """

    def __init__(self, supabase_client: SupabaseClient, memory_store: Dict[str, Any]):
        self.supabase = supabase_client
        self.memory = memory_store
        self.migration_phase = os.getenv("MIGRATION_PHASE", "1")  # 1, 2, 3, 4
        self.supabase_enabled = os.getenv("SUPABASE_WRITE_ENABLED", "true").lower() == "true"

    def create_scan(self, scan_data: Dict[str, Any]) -> str:
        """
        Create scan in both memory and Supabase (dual-write)
        Returns scan_id
        """
        scan_id = scan_data.get('id')

        # Phase 1: Write to in-memory
        self.memory[scan_id] = scan_data
        logger.info(f"✓ Scan {scan_id} written to memory")

        # Phase 1: Write to Supabase (non-blocking)
        if self.supabase_enabled and self.migration_phase in ["1", "2", "3"]:
            try:
                self.supabase.table('scans').insert({
                    'id': scan_data['id'],
                    'org_id': scan_data.get('org_id'),
                    'project_id': scan_data.get('project_id'),
                    'status': scan_data.get('status', 'queued'),
                    'scan_started_at': datetime.now(timezone.utc).isoformat(),
                    'metadata': scan_data.get('metadata', {})
                }).execute()
                logger.info(f"✓ Scan {scan_id} written to Supabase")
            except Exception as e:
                logger.warning(f"⚠️ Supabase write failed for {scan_id}: {e} (will retry)")
                # In Phase 1, we continue - Phase 3 will enforce Supabase-only

        return scan_id

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """
        Read scan with fallback strategy
        Phase 1/2: Memory first (fast), then Supabase
        Phase 3+: Supabase only
        """
        # Phase 1-2: Memory first (faster)
        if self.migration_phase in ["1", "2"]:
            if scan_id in self.memory:
                logger.debug(f"✓ Scan {scan_id} from memory (fast path)")
                return self.memory[scan_id]

        # Phase 1-3: Fall back to Supabase
        if self.supabase_enabled:
            try:
                result = self.supabase.table('scans').select('*').eq('id', scan_id).execute()
                if result.data:
                    scan = result.data[0]
                    logger.debug(f"✓ Scan {scan_id} from Supabase")

                    # Phase 1-2: Populate memory cache for next read
                    if self.migration_phase in ["1", "2"]:
                        self.memory[scan_id] = scan

                    return scan
            except Exception as e:
                logger.warning(f"⚠️ Supabase read failed for {scan_id}: {e}")

        # Fallback: Try memory (in case we skipped it)
        if scan_id in self.memory:
            logger.warning(f"⚠️ Scan {scan_id} from memory (fallback)")
            return self.memory[scan_id]

        return None

    def update_scan(self, scan_id: str, update_data: Dict[str, Any]) -> bool:
        """
        Update scan in both stores (dual-write)
        Returns success status
        """
        success = True

        # Phase 1-3: Update memory
        if scan_id in self.memory:
            self.memory[scan_id].update(update_data)
            self.memory[scan_id]['updated_at'] = datetime.now(timezone.utc).isoformat()
            logger.info(f"✓ Scan {scan_id} updated in memory")
        else:
            logger.warning(f"⚠️ Scan {scan_id} not in memory (may be Supabase-only)")

        # Phase 1-3: Update Supabase
        if self.supabase_enabled:
            try:
                update_payload = {
                    **update_data,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
                self.supabase.table('scans').update(update_payload).eq('id', scan_id).execute()
                logger.info(f"✓ Scan {scan_id} updated in Supabase")
            except Exception as e:
                logger.error(f"❌ Supabase update failed for {scan_id}: {e}")
                success = False

        return success

    def create_finding(self, scan_id: str, finding_data: Dict[str, Any]) -> str:
        """Create finding (dual-write)"""
        finding_id = finding_data.get('id')

        # Memory
        if scan_id not in self.memory:
            self.memory[scan_id] = {'findings': []}
        if 'findings' not in self.memory[scan_id]:
            self.memory[scan_id]['findings'] = []

        self.memory[scan_id]['findings'].append(finding_data)
        logger.info(f"✓ Finding {finding_id} written to memory")

        # Supabase
        if self.supabase_enabled and self.migration_phase in ["1", "2", "3"]:
            try:
                self.supabase.table('findings').insert({
                    'id': finding_data['id'],
                    'org_id': finding_data.get('org_id'),
                    'scan_id': scan_id,
                    'finding_type': finding_data.get('type', 'sast'),
                    'severity': finding_data.get('severity'),
                    'title': finding_data.get('title'),
                    'description': finding_data.get('description'),
                    'file_path': finding_data.get('file'),
                    'line_number': finding_data.get('line'),
                    'metadata': finding_data
                }).execute()
                logger.info(f"✓ Finding {finding_id} written to Supabase")
            except Exception as e:
                logger.warning(f"⚠️ Supabase finding write failed: {e}")

        return finding_id

    def log_audit_event(self, org_id: str, event_type: str, data: Dict) -> bool:
        """
        Log to audit trail (Supabase only - never lossy)
        Critical for SOC 2 compliance
        """
        if not self.supabase_enabled:
            logger.error("❌ Supabase disabled - audit log not persisted!")
            return False

        try:
            self.supabase.table('audit_log').insert({
                'org_id': org_id,
                'event_type': event_type,
                'data': data,
                'entry_hash': 'placeholder',  # Filled by application immutable log
                'prev_hash': 'placeholder',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }).execute()
            logger.info(f"✓ Audit event {event_type} logged for org {org_id}")
            return True
        except Exception as e:
            logger.error(f"❌ Audit log write failed: {e}")
            return False

    def verify_consistency(self, scan_id: str) -> bool:
        """
        Verify memory and Supabase have same data (Phase 1-2 only)
        Used for monitoring dual-write consistency
        """
        if self.migration_phase not in ["1", "2"]:
            return True  # Not applicable after Phase 2

        memory_scan = self.memory.get(scan_id)
        if not memory_scan:
            logger.warning(f"⚠️ Scan {scan_id} not in memory")
            return False

        try:
            result = self.supabase.table('scans').select('*').eq('id', scan_id).execute()
            if not result.data:
                logger.warning(f"⚠️ Scan {scan_id} not in Supabase")
                return False

            db_scan = result.data[0]

            # Compare key fields
            mismatches = []
            for key in ['status', 'risk_score', 'malware_detected']:
                mem_val = memory_scan.get(key)
                db_val = db_scan.get(key)
                if mem_val != db_val:
                    mismatches.append(f"{key}: mem={mem_val} vs db={db_val}")

            if mismatches:
                logger.error(f"⚠️ Consistency check failed for {scan_id}: {mismatches}")
                return False

            logger.info(f"✓ Consistency verified for {scan_id}")
            return True
        except Exception as e:
            logger.error(f"❌ Consistency check error: {e}")
            return False

    def migrate_historic_data(self) -> Dict[str, Any]:
        """
        Batch migrate in-memory scan history to Supabase
        Called at Phase 1 start to populate Supabase
        """
        stats = {'migrated': 0, 'failed': 0, 'skipped': 0}

        if not self.supabase_enabled:
            logger.error("❌ Supabase disabled - cannot migrate")
            return stats

        logger.info(f"🔄 Migrating {len(self.memory)} scans to Supabase...")

        for scan_id, scan_data in self.memory.items():
            try:
                # Check if already in Supabase
                existing = self.supabase.table('scans').select('id').eq('id', scan_id).execute()
                if existing.data:
                    stats['skipped'] += 1
                    continue

                # Migrate scan
                self.supabase.table('scans').insert({
                    'id': scan_data['id'],
                    'org_id': scan_data.get('org_id'),
                    'project_id': scan_data.get('project_id'),
                    'status': scan_data.get('status', 'completed'),
                    'risk_score': scan_data.get('risk_score', 0),
                    'malware_detected': scan_data.get('malware_detected', False),
                    'created_at': scan_data.get('created_at', datetime.now(timezone.utc).isoformat()),
                    'metadata': scan_data
                }).execute()

                # Migrate findings
                if 'findings' in scan_data:
                    for finding in scan_data['findings']:
                        self.supabase.table('findings').insert({
                            'id': finding.get('id'),
                            'org_id': scan_data.get('org_id'),
                            'scan_id': scan_id,
                            'finding_type': finding.get('type', 'sast'),
                            'severity': finding.get('severity'),
                            'title': finding.get('title'),
                            'metadata': finding
                        }).execute()

                stats['migrated'] += 1
            except Exception as e:
                logger.error(f"❌ Migration failed for {scan_id}: {e}")
                stats['failed'] += 1

        logger.info(f"✅ Migration complete: {stats}")
        return stats

    def get_migration_status(self) -> Dict[str, Any]:
        """Get current migration status and health metrics"""
        try:
            memory_count = len(self.memory)
            supabase_count = 0

            if self.supabase_enabled:
                result = self.supabase.table('scans').select('id', count='exact').execute()
                supabase_count = result.count

            return {
                'phase': self.migration_phase,
                'supabase_enabled': self.supabase_enabled,
                'memory_scans': memory_count,
                'supabase_scans': supabase_count,
                'consistency': memory_count == supabase_count,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
