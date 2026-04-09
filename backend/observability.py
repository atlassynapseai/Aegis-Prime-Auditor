"""
Observability Layer for Aegis Prime Auditor
Structured logging, metrics, tracing, and SLOs
"""

import os
import logging
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import time
from functools import wraps
from contextlib import contextmanager

from prometheus_client import Counter, Histogram, Gauge
from opentelemetry import trace, metrics
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

# ============================================================================
# STRUCTURED JSON LOGGING (→ Datadog / Axiom)
# ============================================================================

class JSONFormatter(logging.Formatter):
    """Format logs as JSON for structured ingestion"""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }

        # Add extra fields if present
        if hasattr(record, 'org_id'):
            log_data['org_id'] = record.org_id
        if hasattr(record, 'user_id'):
            log_data['user_id'] = record.user_id
        if hasattr(record, 'scan_id'):
            log_data['scan_id'] = record.scan_id
        if hasattr(record, 'tags'):
            log_data['tags'] = record.tags

        # Exception info
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }

        return json.dumps(log_data)

def setup_logging(service_name: str = "aegis-auditor") -> logging.Logger:
    """
    Initialize structured JSON logging with Datadog/Axiom support

    Usage:
        logger = setup_logging("aegis-backend")
        logger.error("Scan failed", extra={
            'org_id': '123',
            'scan_id': 'scan-456',
            'tags': ['production', 'scanning']
        })
    """
    logger = logging.getLogger(service_name)
    logger.setLevel(logging.DEBUG)

    # Console handler with JSON formatting
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(JSONFormatter())
    logger.addHandler(console_handler)

    # File handler (for local dev/debugging)
    file_handler = logging.FileHandler(f"/tmp/{service_name}.log")
    file_handler.setFormatter(JSONFormatter())
    logger.addHandler(file_handler)

    return logger

logger = setup_logging("aegis-auditor")

# ============================================================================
# PROMETHEUS METRICS (→ Grafana / Datadog)
# ============================================================================

# Scan metrics
scans_total = Counter(
    'aegis_scans_total',
    'Total scans initiated',
    ['org_id', 'status', 'environment']
)

scan_duration_seconds = Histogram(
    'aegis_scan_duration_seconds',
    'Scan duration in seconds',
    ['org_id', 'environment'],
    buckets=(1, 5, 10, 30, 60, 120, 300)
)

scan_findings_total = Histogram(
    'aegis_scan_findings_total',
    'Number of findings per scan',
    ['org_id', 'severity', 'environment'],
    buckets=(0, 5, 10, 20, 50, 100, 500)
)

# Queue metrics
queue_depth = Gauge(
    'aegis_queue_depth',
    'Current scan queue depth',
    ['org_id', 'environment']
)

queue_processing_time = Histogram(
    'aegis_queue_processing_time_seconds',
    'Time from queued to completed',
    ['org_id', 'environment']
)

# Auth metrics
auth_requests_total = Counter(
    'aegis_auth_requests_total',
    'Total auth requests',
    ['method', 'status', 'environment']
)

auth_latency_seconds = Histogram(
    'aegis_auth_latency_seconds',
    'Auth latency in seconds',
    ['method', 'environment'],
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0)
)

# Database metrics
db_query_duration_seconds = Histogram(
    'aegis_db_query_duration_seconds',
    'Database query duration',
    ['query_type', 'table', 'environment']
)

db_connection_errors_total = Counter(
    'aegis_db_connection_errors_total',
    'Total database connection errors',
    ['error_type', 'environment']
)

# API metrics
api_requests_total = Counter(
    'aegis_api_requests_total',
    'Total API requests',
    ['endpoint', 'method', 'status', 'environment']
)

api_latency_seconds = Histogram(
    'aegis_api_latency_seconds',
    'API request latency',
    ['endpoint', 'method', 'environment'],
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 5.0)
)

# Audit log metrics
audit_log_writes_total = Counter(
    'aegis_audit_log_writes_total',
    'Audit log entries written',
    ['event_type', 'org_id', 'environment']
)

audit_log_integrity_errors = Counter(
    'aegis_audit_log_integrity_errors_total',
    'Audit log hash chain integrity failures',
    ['environment']
)

# ============================================================================
# OPENTELEMETRY DISTRIBUTED TRACING (→ Datadog / Jaeger)
# ============================================================================

def setup_tracing(service_name: str = "aegis-auditor"):
    """Initialize OpenTelemetry distributed tracing"""

    jaeger_exporter = JaegerExporter(
        agent_host_name=os.getenv("JAEGER_AGENT_HOST", "localhost"),
        agent_port=int(os.getenv("JAEGER_AGENT_PORT", "6831")),
    )

    trace_provider = TracerProvider(
        resource=Resource.create({SERVICE_NAME: service_name})
    )
    trace_provider.add_span_processor(BatchSpanProcessor(jaeger_exporter))

    trace.set_tracer_provider(trace_provider)

    # Auto-instrument FastAPI and SQLAlchemy
    FastAPIInstrumentor().instrument()
    SQLAlchemyInstrumentor().instrument()

    logger.info("✓ OpenTelemetry tracing initialized")

tracer = trace.get_tracer(__name__)

@contextmanager
def trace_span(name: str, attributes: Optional[Dict[str, Any]] = None):
    """Context manager for manual span creation"""
    with tracer.start_as_current_span(name) as span:
        if attributes:
            for key, value in attributes.items():
                span.set_attribute(key, value)
        yield span

def trace_function(func):
    """Decorator to automatically trace function calls"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        with trace_span(f"{func.__module__}.{func.__name__}"):
            return func(*args, **kwargs)
    return wrapper

# ============================================================================
# PERFORMANCE MONITORING CONTEXT
# ============================================================================

class PerformanceMonitor:
    """Track performance metrics for a scan"""

    def __init__(self, scan_id: str, org_id: str):
        self.scan_id = scan_id
        self.org_id = org_id
        self.start_time = time.time()
        self.engine_times = {}

    def record_engine(self, engine_name: str, duration: float):
        """Record engine scan time"""
        self.engine_times[engine_name] = duration

    def finalize(self) -> Dict[str, Any]:
        """Get final metrics"""
        total_duration = time.time() - self.start_time

        # Record to Prometheus
        scan_duration_seconds.labels(
            org_id=self.org_id,
            environment=os.getenv("ENVIRONMENT", "staging")
        ).observe(total_duration)

        return {
            'total_seconds': round(total_duration, 2),
            'engines': self.engine_times
        }

# ============================================================================
# SLO DEFINITION & MONITORING
# ============================================================================

SLO_TARGETS = {
    'scan_completion_p99': {
        'name': 'Scan completion time p99',
        'target_seconds': 120,
        'metric': 'aegis_scan_duration_seconds',
        'percentile': 99,
        'environment': 'production'
    },
    'api_latency_p99': {
        'name': 'API latency p99',
        'target_seconds': 0.5,
        'metric': 'aegis_api_latency_seconds',
        'percentile': 99
    },
    'auth_latency_p95': {
        'name': 'Auth latency p95',
        'target_seconds': 0.2,
        'metric': 'aegis_auth_latency_seconds',
        'percentile': 95
    },
    'audit_log_integrity': {
        'name': 'Audit log 100% integrity',
        'target_percent': 100,
        'metric': 'aegis_audit_log_integrity_errors_total',
        'error_budget_incidents': 0
    },
    'uptime': {
        'name': 'Service uptime',
        'target_percent': 99.5,
        'calculation': 'monthly'
    }
}

# ============================================================================
# ERROR BUDGET & INCIDENTS
# ============================================================================

class ErrorBudget:
    """Track error budget for SLO compliance"""

    def __init__(self, monthly_target_uptime: float = 99.5):
        self.monthly_target = monthly_target_uptime
        self.incidents = []
        self.start_of_month = datetime.now(timezone.utc)

    def record_incident(self, duration_seconds: float, component: str, severity: str):
        """Log an incident and consume error budget"""
        incident = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'component': component,
            'duration_seconds': duration_seconds,
            'severity': severity
        }
        self.incidents.append(incident)

        # Convert to downtime percent
        seconds_in_month = 30 * 24 * 3600
        downtime_percent = (duration_seconds / seconds_in_month) * 100
        remaining_budget = (100 - self.monthly_target) - downtime_percent

        logger.error(f"📊 Incident recorded: {component}", extra={
            'tags': ['incident', 'error_budget'],
            'severity': severity,
            'downtime_percent': downtime_percent,
            'remaining_budget_percent': remaining_budget
        })

        return remaining_budget

    def get_status(self) -> Dict[str, Any]:
        """Get error budget status for dashboard"""
        total_downtime = sum(i['duration_seconds'] for i in self.incidents) / 3600
        budget_remaining = (100 - self.monthly_target) * 30 / 100  # hours per month

        return {
            'monthly_target_percent': self.monthly_target,
            'incident_count': len(self.incidents),
            'total_downtime_hours': total_downtime,
            'budget_remaining_hours': budget_remaining - total_downtime,
            'incidents': self.incidents
        }

error_budget = ErrorBudget(monthly_target_uptime=99.5)

# ============================================================================
# ALERT DEFINITIONS (for Datadog / Alertmanager)
# ============================================================================

ALERTS = [
    {
        'name': 'HighScanQueueDepth',
        'condition': 'aegis_queue_depth > 500 for 10 minutes',
        'severity': 'CRITICAL',
        'action': 'Scale out scan workers'
    },
    {
        'name': 'ScanLatencyP99Exceeded',
        'condition': 'aegis_scan_duration_seconds{quantile="0.99"} > 180s for 5 mins',
        'severity': 'WARNING',
        'action': 'Check engine health'
    },
    {
        'name': 'AuditLogCorruption',
        'condition': 'aegis_audit_log_integrity_errors_total > 0',
        'severity': 'CRITICAL',
        'action': 'Page on-call immediately'
    },
    {
        'name': 'HighErrorRate',
        'condition': 'rate(aegis_api_requests_total{status="5xx"}[5m]) > 0.01',
        'severity': 'CRITICAL',
        'action': 'Investigate service logs'
    },
    {
        'name': 'DatabaseConnectionPool',
        'condition': 'aegis_db_connection_errors_total > 100 for 1 minute',
        'severity': 'CRITICAL',
        'action': 'Check database connectivity'
    }
]

# ============================================================================
# LOGGING UTILITIES
# ============================================================================

def log_scan_event(scan_id: str, org_id: str, event_type: str, data: Dict):
    """Log scan lifecycle event with structure"""
    logger.info(f"Scan event: {event_type}", extra={
        'scan_id': scan_id,
        'org_id': org_id,
        'event_type': event_type,
        'tags': ['scanning', event_type],
        **data
    })

def log_security_finding(scan_id: str, org_id: str, finding: Dict):
    """Log security finding for audit trail"""
    logger.warning(f"Security finding: {finding.get('severity')}", extra={
        'scan_id': scan_id,
        'org_id': org_id,
        'finding_type': finding.get('type'),
        'severity': finding.get('severity'),
        'tags': ['security', 'finding'],
        **finding
    })

def log_auth_attempt(user_id: str, org_id: str, method: str, success: bool):
    """Log authentication attempt"""
    logger.info(f"Auth attempt: {method} ({'success' if success else 'failed'})", extra={
        'user_id': user_id,
        'org_id': org_id,
        'auth_method': method,
        'success': success,
        'tags': ['auth', 'security']
    })

def log_compliance_check(org_id: str, framework: str, status: str, gaps: List[str]):
    """Log compliance check"""
    logger.info(f"Compliance check: {framework} - {status}", extra={
        'org_id': org_id,
        'framework': framework,
        'status': status,
        'gaps_count': len(gaps),
        'tags': ['compliance']
    })
