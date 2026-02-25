"""
Professional Executive Report Generator - Atlas Synapse
Creates board-ready security audit reports with institutional design
"""

from datetime import datetime
from typing import Dict, Any, List


class ReportGenerator:
    """Generate institutional-grade security reports."""
    
    @staticmethod
    def generate_executive_markdown(scan_result: Dict[str, Any], compliance_data: Dict[str, Any] = None) -> str:
        """Generate executive markdown report."""
        
        timestamp = datetime.fromisoformat(scan_result.get("timestamp", datetime.now().isoformat()))
        ai = scan_result.get("ai_analysis", {})
        sev = scan_result.get("severity_breakdown", {})
        perf = scan_result.get("performance", {})
        
        report = f"""# ATLAS SYNAPSE SECURITY AUDIT REPORT

**CONFIDENTIAL — EXECUTIVE LEADERSHIP ONLY**

---

## ENGAGEMENT OVERVIEW

| | |
|---|---|
| **Scan Identifier** | `{scan_result.get("scan_id", "N/A")}` |
| **Target Asset** | `{scan_result.get("file", "N/A")}` |
| **Analysis Date** | {timestamp.strftime("%B %d, %Y")} |
| **Analysis Time** | {timestamp.strftime("%H:%M:%S UTC")} |
| **Execution Duration** | {perf.get("total", "N/A")}s |
| **Report Generated** | {datetime.now().strftime("%B %d, %Y at %H:%M:%S UTC")} |

---

## EXECUTIVE RISK ASSESSMENT

### Overall Security Posture

<div style="text-align: center; padding: 30px; background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border-left: 6px solid {'#dc2626' if ai.get('risk_level') == 'CRITICAL' else '#ea580c' if ai.get('risk_level') == 'HIGH' else '#eab308' if ai.get('risk_level') == 'MEDIUM' else '#22c55e'}; margin: 20px 0;">
  <div style="font-size: 48px; font-weight: 900; color: white; margin-bottom: 10px;">
    {ai.get("risk_score", 0)}<span style="font-size: 32px; color: #94a3b8;">/100</span>
  </div>
  <div style="font-size: 20px; font-weight: 700; color: {'#dc2626' if ai.get('risk_level') == 'CRITICAL' else '#ea580c' if ai.get('risk_level') == 'HIGH' else '#eab308' if ai.get('risk_level') == 'MEDIUM' else '#22c55e'}; text-transform: uppercase; letter-spacing: 2px;">
    {ai.get("risk_level", "UNKNOWN")} RISK
  </div>
</div>

### Analysis Summary

{ai.get("executive_summary", "Analysis unavailable.")}

### Findings Distribution

"""
        
        # Create visual severity bars
        total_findings = scan_result.get("total_findings", 0)
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sev.get(severity, 0)
            if count > 0:
                percentage = int((count / max(total_findings, 1)) * 100)
                color = '#dc2626' if severity == 'CRITICAL' else '#ea580c' if severity == 'HIGH' else '#eab308' if severity == 'MEDIUM' else '#22c55e'
                report += f"""
**{severity}:** {count} findings ({percentage}%)
<div style="width: 100%; height: 8px; background: #1e293b; border-radius: 4px; margin: 8px 0;">
  <div style="width: {percentage}%; height: 100%; background: {color}; border-radius: 4px;"></div>
</div>
"""
        
        # Compliance section
        if compliance_data:
            status = compliance_data.get("overall_status", {})
            report += f"""

---

## REGULATORY COMPLIANCE ASSESSMENT

### Compliance Status

{status.get('recommendation', 'Status unavailable')}

**Critical Compliance Blockers:** {status.get('critical_blockers', 0)}  
**High Priority Issues:** {status.get('high_priority', 0)}  
**Estimated Remediation Effort:** {status.get('estimated_remediation_time', 'N/A')}

### Framework Analysis

| Framework | Compliance | Violations | Controls Impacted |
|-----------|-----------|------------|-------------------|
"""
            
            for framework_id, data in compliance_data.get("frameworks", {}).items():
                name = data.get("name", framework_id)[:40]
                compliance_pct = data.get("compliance_percentage", 0)
                violations = data.get("violations", 0)
                controls = len(data.get("controls_affected", []))
                
                status_icon = "✅" if compliance_pct == 100 else "⚠️" if compliance_pct >= 80 else "❌"
                
                report += f"| {status_icon} {name} | **{compliance_pct}%** | {violations} | {controls} |\n"
            
            # Atlas Synapse Recommendation
            if status.get('critical_blockers', 0) > 0:
                report += f"""

---

### ⚠️ ATLAS SYNAPSE FIDUCIARY ASSESSMENT

This codebase contains **{status.get('critical_blockers')} critical regulatory violations** that constitute material risk to the organization.

**Risk Classification:**
- **Deployment Risk:** UNACCEPTABLE - Code fails baseline security requirements
- **Compliance Risk:** NON-COMPLIANT - Violates {len([f for f in compliance_data.get('frameworks', {}).values() if f.get('violations', 0) > 0])} regulatory frameworks
- **Fiduciary Risk:** MATERIAL BREACH - Deployment may violate duty of care to stakeholders

**Atlas Synapse Recommendation:**

1. **Immediate (0-24 hours):** Halt all deployment activities pending remediation
2. **Short-term (1-7 days):** Engage Atlas Synapse for compliance architecture review
3. **Strategic (30-90 days):** Migrate to Atlas Sovereign Infrastructure for continuous compliance

**Rationale:** Current systems create quantifiable legal exposure. Migration to Atlas infrastructure is not an IT decision—it is a fiduciary necessity.

"""
        
        # Scanning engine results
        report += """

---

## SCANNING METHODOLOGY

### Multi-Engine Analysis

This audit employed four independent security engines operating concurrently:

"""
        
        engines_info = [
            ("Semgrep v1.152.0", "Static Application Security Testing (SAST)", 
             "Pattern-based analysis using 500+ security rules. Detects SQL injection, command injection, hardcoded secrets, and cryptographic weaknesses.",
             perf.get("semgrep", "N/A")),
            ("Gitleaks v8.18.4", "Secrets Detection", 
             "Entropy-based credential scanning with 99.2% precision. Identifies API keys, passwords, tokens, and cloud credentials.",
             perf.get("gitleaks", "N/A")),
            ("Trivy v0.50.1", "Software Composition Analysis (SCA)", 
             "CVE database matching across 15+ ecosystems. Scans dependencies against NVD, GitHub Advisories, updated every 24 hours.",
             perf.get("trivy", "N/A")),
            ("CodeQL Pattern Engine", "Deep Taint Analysis", 
             "Data flow tracking from user input to sensitive operations. Detects second-order injections and complex vulnerability chains.",
             perf.get("codeql", "N/A"))
        ]
        
        for name, category, description, exec_time in engines_info:
            report += f"""
**{name}**  
*{category}*

{description}

- **Execution Time:** {exec_time} seconds
- **Findings:** {len(scan_result.get('engines', {}).get(name.split()[0].lower(), {}).get('findings', []))}

"""
        
        report += f"""
**Google Gemini 2.5 Flash**  
*AI Risk Analysis & Remediation Guidance*

Large language model with 1M+ token context providing risk scoring, executive summaries, and prioritized remediation strategies.

- **Execution Time:** {perf.get('ai_analysis', 'N/A')} seconds
- **Risk Score Generated:** {ai.get('risk_score', 0)}/100

---

## PRIORITY REMEDIATION ROADMAP

"""
        
        priorities = ai.get("top_priorities", [])
        for idx, priority in enumerate(priorities, 1):
            report += f"""
### Priority {idx}

{priority}

"""
        
        # Detailed findings
        report += """

---

## DETAILED VULNERABILITY ANALYSIS

The following section provides line-by-line analysis of detected security issues, ordered by severity and regulatory impact.

"""
        
        findings = scan_result.get("all_findings", [])
        severity_order = {"CRITICAL": 0, "ERROR": 0, "HIGH": 1, "MEDIUM": 2, "WARNING": 2, "LOW": 3}
        sorted_findings = sorted(findings, key=lambda f: (severity_order.get(f.get("severity", "MEDIUM"), 2), f.get("file", "")))
        
        for idx, finding in enumerate(sorted_findings[:30], 1):
            sev = finding.get("severity", "MEDIUM")
            sev_icon = "🔴" if sev in ["CRITICAL", "ERROR"] else "🟠" if sev == "HIGH" else "🟡" if sev in ["MEDIUM", "WARNING"] else "🟢"
            
            report += f"""
### {idx}. {sev_icon} {finding.get('message', 'Security Issue Detected')}

**Classification:**
- Severity: **{sev}**
- Category: {finding.get('category', 'Unknown')}
- Detection Engine: {finding.get('engine', 'unknown').title()}
- Location: `{finding.get('file', '')}` (Line {finding.get('line_start', 0)})

"""
            
            if finding.get("cwe"):
                cwe = finding.get("cwe")
                cwe_str = cwe[0] if isinstance(cwe, list) else cwe
                report += f"**CWE Classification:** {cwe_str}  \n"
            
            if finding.get("owasp"):
                owasp = finding.get("owasp")
                owasp_str = owasp[0] if isinstance(owasp, list) else owasp
                report += f"**OWASP Mapping:** {owasp_str}  \n"
            
            if finding.get("package"):
                report += f"""
**Dependency Information:**
- Package: `{finding.get('package')}`
- Installed Version: {finding.get('installed_version', 'unknown')}
- Fixed Version: {finding.get('fixed_version', 'not available')}
- CVE: {finding.get('cve', 'N/A')}
- CVSS Score: {finding.get('cvss_score', 'N/A')}/10

"""
            
            if finding.get("snippet"):
                report += f"""
**Vulnerable Code:**
```
{finding.get('snippet', '')[:300]}
```

"""
            
            report += "---\n\n"
        
        if len(findings) > 30:
            report += f"*Note: {len(findings) - 30} additional findings not included in executive summary. Full details available via API.*\n\n"
        
        # Appendix
        report += f"""

---

## APPENDIX A: PERFORMANCE METRICS

| Metric | Value |
|--------|-------|
| Total Scan Time | {perf.get('total', 'N/A')} seconds |
| Semgrep (SAST) | {perf.get('semgrep', 'N/A')}s |
| Gitleaks (Secrets) | {perf.get('gitleaks', 'N/A')}s |
| Trivy (SCA) | {perf.get('trivy', 'N/A')}s |
| CodeQL (Deep Analysis) | {perf.get('codeql', 'N/A')}s |
| Gemini AI Analysis | {perf.get('ai_analysis', 'N/A')}s |

**Parallel Efficiency:** {round((sum([perf.get(e, 0) for e in ['semgrep', 'gitleaks', 'trivy', 'codeql']]) / max(perf.get('total', 1), 1)) * 100, 1)}% time savings via concurrent execution

---

## APPENDIX B: REGULATORY FRAMEWORK REFERENCES

**PCI-DSS 4.0** - Payment Card Industry Data Security Standard  
https://www.pcisecuritystandards.org/

**OWASP Top 10 2021** - Web Application Security Risks  
https://owasp.org/Top10/

**NIST SSDF 1.1** - Secure Software Development Framework  
https://csrc.nist.gov/publications/detail/sp/800-218/final

**SOC 2 Type II** - Trust Services Criteria  
https://www.aicpa.org/soc

**NYDFS 23 NYCRR 500** - Cybersecurity Requirements for Financial Services  
https://www.dfs.ny.gov/industry_guidance/

**CWE Top 25** - Most Dangerous Software Weaknesses  
https://cwe.mitre.org/top25/

---

## ABOUT ATLAS SYNAPSE

Atlas Synapse LLC builds sovereign-grade AI infrastructure for enterprises operating under regulatory scrutiny. Unlike "AI wrapper" companies that prioritize speed over compliance, Atlas Synapse delivers systems designed to survive SOC 2, PCI-DSS, and NYDFS audits on day one.

**Core Capabilities:**
- Compliance-First Architecture
- Explainability-by-Default AI Systems
- Regulatory Evidence Generation
- Fiduciary Risk Assessment

**Target Industries:**
- FinTech ($10M+ AUM)
- Insurance Underwriting
- LegalTech Platforms
- Healthcare Systems

**Platform:** https://github.com/atlassynapseai/Aegis-Prime-Auditor  
**Contact:** contact@atlassynapseai.com  
**Documentation:** https://docs.atlassynapseai.com

---

## CLASSIFICATION & DISTRIBUTION

**Report Classification:** CONFIDENTIAL  
**Distribution Restriction:** Executive Leadership, Board of Directors, Legal Counsel, External Auditors (with authorization)  
**Retention Requirement:** Maintain per organizational record-keeping policy and applicable regulatory requirements  
**Unauthorized Disclosure:** Prohibited under attorney-client privilege and work product doctrine (where applicable)

---

*This report was generated by Atlas Synapse Aegis Prime Auditor™ v2.0*

**Powered by:** Semgrep • Gitleaks • Trivy • CodeQL • Google Gemini AI

**© 2026 Atlas Synapse LLC. All rights reserved.**

*Atlas Synapse and Aegis Prime are trademarks of Atlas Synapse LLC.*
"""
        
        return report
    
    @staticmethod
    def generate_html_report(scan_result: Dict[str, Any], compliance_data: Dict[str, Any] = None) -> str:
        """Generate institutional-grade HTML report with professional design."""
        
        timestamp = datetime.fromisoformat(scan_result.get("timestamp", datetime.now().isoformat()))
        ai = scan_result.get("ai_analysis", {})
        sev = scan_result.get("severity_breakdown", {})
        perf = scan_result.get("performance", {})
        findings = scan_result.get("all_findings", [])
        
        # Risk level colors
        risk_level = ai.get("risk_level", "UNKNOWN")
        risk_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e"
        }
        risk_color = risk_colors.get(risk_level, "#64748b")
        
        # Sort findings
        severity_order = {"CRITICAL": 0, "ERROR": 0, "HIGH": 1, "MEDIUM": 2, "WARNING": 2, "LOW": 3}
        sorted_findings = sorted(findings, key=lambda f: (severity_order.get(f.get("severity", "MEDIUM"), 2), f.get("file", "")))
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Atlas Synapse Security Audit Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;900&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            line-height: 1.7;
            color: #1e293b;
            background: #ffffff;
        }}
        
        .page-container {{
            max-width: 1100px;
            margin: 0 auto;
            padding: 60px 40px;
        }}
        
        .header {{
            border-bottom: 6px solid {risk_color};
            padding-bottom: 40px;
            margin-bottom: 50px;
        }}
        
        .logo {{
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .logo-icon {{
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 10px 40px rgba(59, 130, 246, 0.3);
        }}
        
        .company-name {{
            font-size: 32px;
            font-weight: 900;
            background: linear-gradient(135deg, #0f172a 0%, #475569 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
        }}
        
        .tagline {{
            font-size: 14px;
            color: #64748b;
            font-weight: 600;
            letter-spacing: 1px;
            text-transform: uppercase;
        }}
        
        .classification {{
            display: inline-block;
            background: #dc2626;
            color: white;
            padding: 8px 20px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 12px;
            letter-spacing: 1.5px;
            margin-top: 20px;
        }}
        
        h1 {{
            font-size: 36px;
            font-weight: 900;
            color: #0f172a;
            margin: 40px 0 20px 0;
            letter-spacing: -1px;
        }}
        
        h2 {{
            font-size: 24px;
            font-weight: 700;
            color: #1e40af;
            margin: 40px 0 20px 0;
            padding-bottom: 12px;
            border-bottom: 3px solid #e2e8f0;
        }}
        
        h3 {{
            font-size: 18px;
            font-weight: 600;
            color: #3b82f6;
            margin: 30px 0 15px 0;
        }}
        
        .meta-table {{
            width: 100%;
            background: #f8fafc;
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid #e2e8f0;
            margin: 30px 0;
        }}
        
        .meta-table td {{
            padding: 16px 24px;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        .meta-table td:first-child {{
            font-weight: 600;
            color: #475569;
            width: 200px;
            background: #f1f5f9;
        }}
        
        .meta-table td:last-child {{
            color: #0f172a;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 14px;
        }}
        
        .risk-card {{
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            border: 3px solid {risk_color};
            border-radius: 16px;
            padding: 50px;
            text-align: center;
            margin: 40px 0;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1);
        }}
        
        .risk-score {{
            font-size: 80px;
            font-weight: 900;
            color: {risk_color};
            line-height: 1;
            margin-bottom: 10px;
        }}
        
        .risk-score-max {{
            font-size: 48px;
            color: #94a3b8;
        }}
        
        .risk-level {{
            font-size: 28px;
            font-weight: 700;
            color: {risk_color};
            letter-spacing: 3px;
            text-transform: uppercase;
            margin-top: 15px;
        }}
        
        .summary-box {{
            background: white;
            border: 2px solid #e2e8f0;
            border-radius: 12px;
            padding: 30px;
            margin: 30px 0;
            font-size: 16px;
            line-height: 1.8;
            color: #334155;
        }}
        
        .severity-bar {{
            margin: 20px 0;
        }}
        
        .severity-label {{
            font-weight: 600;
            color: #475569;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
        }}
        
        .bar-container {{
            width: 100%;
            height: 12px;
            background: #e2e8f0;
            border-radius: 6px;
            overflow: hidden;
        }}
        
        .bar-fill {{
            height: 100%;
            border-radius: 6px;
            transition: width 0.3s ease;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 30px 0;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }}
        
        th {{
            background: #0f172a;
            color: white;
            padding: 16px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }}
        
        td {{
            padding: 16px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 14px;
        }}
        
        tr:last-child td {{
            border-bottom: none;
        }}
        
        .finding-card {{
            background: white;
            border: 2px solid #e2e8f0;
            border-left: 6px solid;
            border-radius: 12px;
            padding: 30px;
            margin: 25px 0;
            page-break-inside: avoid;
        }}
        
        .finding-card.critical {{ border-left-color: #dc2626; }}
        .finding-card.high {{ border-left-color: #ea580c; }}
        .finding-card.medium {{ border-left-color: #eab308; }}
        .finding-card.low {{ border-left-color: #22c55e; }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 20px;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 6px 14px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 11px;
            letter-spacing: 1px;
            text-transform: uppercase;
            color: white;
        }}
        
        .badge-critical {{ background: #dc2626; }}
        .badge-high {{ background: #ea580c; }}
        .badge-medium {{ background: #eab308; }}
        .badge-low {{ background: #22c55e; }}
        
        .code-block {{
            background: #0f172a;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.6;
            margin: 15px 0;
            border: 1px solid #1e293b;
        }}
        
        .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
            padding: 20px;
            background: #f8fafc;
            border-radius: 8px;
        }}
        
        .metadata-item {{
            font-size: 13px;
        }}
        
        .metadata-label {{
            color: #64748b;
            font-weight: 600;
            margin-bottom: 4px;
        }}
        
        .metadata-value {{
            color: #0f172a;
            font-family: 'Monaco', monospace;
            font-size: 12px;
        }}
        
        .alert-box {{
            background: #fef2f2;
            border: 2px solid #fca5a5;
            border-radius: 12px;
            padding: 30px;
            margin: 30px 0;
        }}
        
        .alert-box h3 {{
            color: #dc2626;
            margin-top: 0;
        }}
        
        .footer {{
            margin-top: 80px;
            padding-top: 40px;
            border-top: 2px solid #e2e8f0;
            font-size: 13px;
            color: #64748b;
            text-align: center;
        }}
        
        .footer-logo {{
            font-weight: 700;
            color: #3b82f6;
        }}
        
        @media print {{
            body {{ background: white; }}
            .page-container {{ max-width: 100%; }}
            .no-print {{ display: none; }}
            h2 {{ page-break-before: always; }}
            .finding-card {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="page-container">
        <!-- Header -->
        <div class="header">
            <div class="logo">
                <div class="logo-icon">
                    <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5">
                        <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                    </svg>
                </div>
                <div>
                    <div class="company-name">ATLAS SYNAPSE</div>
                    <div class="tagline">Security Audit Report</div>
                </div>
            </div>
            
            <div class="classification">CONFIDENTIAL — EXECUTIVE LEADERSHIP ONLY</div>
        </div>
        
        <!-- Engagement Overview -->
        <h1>Security Audit Report</h1>
        
        <table class="meta-table">
            <tr>
                <td>Scan Identifier</td>
                <td>{scan_result.get("scan_id", "N/A")}</td>
            </tr>
            <tr>
                <td>Target Asset</td>
                <td>{scan_result.get("file", "N/A")}</td>
            </tr>
            <tr>
                <td>Analysis Date</td>
                <td>{timestamp.strftime("%B %d, %Y at %H:%M:%S UTC")}</td>
            </tr>
            <tr>
                <td>Execution Duration</td>
                <td>{perf.get("total", "N/A")} seconds</td>
            </tr>
            <tr>
                <td>Report Generated</td>
                <td>{datetime.now().strftime("%B %d, %Y at %H:%M:%S UTC")}</td>
            </tr>
        </table>
        
        <!-- Risk Assessment -->
        <h2>Executive Risk Assessment</h2>
        
        <div class="risk-card">
            <div class="risk-score">
                {ai.get("risk_score", 0)}<span class="risk-score-max">/100</span>
            </div>
            <div class="risk-level">{risk_level} RISK</div>
        </div>
        
        <div class="summary-box">
            {ai.get("executive_summary", "Analysis unavailable.")}
        </div>
        
        <!-- Severity Distribution -->
        <h3>Findings Distribution</h3>
        
"""
        
        # Severity bars
        total_findings = scan_result.get("total_findings", 0)
        for severity, color in [("CRITICAL", "#dc2626"), ("HIGH", "#ea580c"), ("MEDIUM", "#eab308"), ("LOW", "#22c55e")]:
            count = sev.get(severity, 0)
            if count > 0:
                percentage = int((count / max(total_findings, 1)) * 100)
                html += f"""
        <div class="severity-bar">
            <div class="severity-label">
                <span><strong>{severity}</strong></span>
                <span>{count} findings ({percentage}%)</span>
            </div>
            <div class="bar-container">
                <div class="bar-fill" style="width: {percentage}%; background: {color};"></div>
            </div>
        </div>
"""
        
        # Compliance
        if compliance_data:
            status = compliance_data.get("overall_status", {})
            
            html += f"""
        
        <h2>Regulatory Compliance Assessment</h2>
        
        <div class="summary-box">
            <h3 style="color: {'#dc2626' if status.get('critical_blockers', 0) > 0 else '#22c55e'}; margin-bottom: 15px;">
                {status.get('recommendation', 'Status unavailable')}
            </h3>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-top: 20px;">
                <div>
                    <div style="font-size: 12px; color: #64748b; margin-bottom: 5px;">Critical Blockers</div>
                    <div style="font-size: 32px; font-weight: 900; color: #dc2626;">{status.get('critical_blockers', 0)}</div>
                </div>
                <div>
                    <div style="font-size: 12px; color: #64748b; margin-bottom: 5px;">High Priority</div>
                    <div style="font-size: 32px; font-weight: 900; color: #ea580c;">{status.get('high_priority', 0)}</div>
                </div>
                <div>
                    <div style="font-size: 12px; color: #64748b; margin-bottom: 5px;">Est. Remediation</div>
                    <div style="font-size: 20px; font-weight: 700; color: #0f172a;">{status.get('estimated_remediation_time', 'N/A')}</div>
                </div>
            </div>
        </div>
        
        <h3>Framework Compliance Status</h3>
        
        <table>
            <thead>
                <tr>
                    <th>Framework</th>
                    <th style="text-align: center;">Compliance</th>
                    <th style="text-align: center;">Violations</th>
                    <th style="text-align: center;">Controls</th>
                </tr>
            </thead>
            <tbody>
"""
            
            for framework_id, data in compliance_data.get("frameworks", {}).items():
                name = data.get("name", framework_id)
                compliance_pct = data.get("compliance_percentage", 0)
                violations = data.get("violations", 0)
                controls = len(data.get("controls_affected", []))
                
                status_color = "#22c55e" if compliance_pct == 100 else "#eab308" if compliance_pct >= 80 else "#dc2626"
                status_icon = "✅" if compliance_pct == 100 else "⚠️" if compliance_pct >= 80 else "❌"
                
                html += f"""
                <tr>
                    <td>{status_icon} {name}</td>
                    <td style="text-align: center; font-weight: 700; color: {status_color};">{compliance_pct}%</td>
                    <td style="text-align: center;">{violations}</td>
                    <td style="text-align: center;">{controls}</td>
                </tr>
"""
            
            html += """
            </tbody>
        </table>
"""
            
            # Atlas Synapse alert for critical issues
            if status.get('critical_blockers', 0) > 0:
                html += f"""
        
        <div class="alert-box">
            <h3>⚠️ Atlas Synapse Fiduciary Assessment</h3>
            <p style="margin: 15px 0; font-size: 15px; line-height: 1.8;">
                This codebase contains <strong>{status.get('critical_blockers')} critical regulatory violations</strong> 
                that constitute material risk to the organization. Deployment in current state may violate fiduciary 
                duty to stakeholders and create legal exposure.
            </p>
            <p style="margin: 15px 0; font-size: 15px; line-height: 1.8;">
                <strong>Atlas Synapse Recommendation:</strong> Migration to Atlas Sovereign Infrastructure is not 
                an IT decision—it is a fiduciary necessity to maintain regulatory compliance and limit organizational liability.
            </p>
        </div>
"""
        
        # Top priorities
        priorities = ai.get("top_priorities", [])
        if priorities:
            html += """
        
        <h2>Remediation Priorities</h2>
        
        <div style="background: #f8fafc; border-radius: 12px; padding: 30px; margin: 20px 0;">
"""
            
            for idx, priority in enumerate(priorities, 1):
                html += f"""
            <div style="display: flex; gap: 20px; margin: 20px 0; align-items: flex-start;">
                <div style="background: #3b82f6; color: white; width: 40px; height: 40px; border-radius: 8px; 
                           display: flex; align-items: center; justify-content: center; font-weight: 900; 
                           font-size: 18px; flex-shrink: 0;">P{idx}</div>
                <div style="flex: 1; padding-top: 8px; font-size: 15px; color: #334155;">{priority}</div>
            </div>
"""
            
            html += """
        </div>
"""
        
        # Detailed findings
        html += """
        
        <h2>Detailed Vulnerability Analysis</h2>
        
        <p style="color: #64748b; margin-bottom: 30px;">
            The following section provides comprehensive analysis of detected security issues, 
            ordered by severity and regulatory impact. Each finding includes location, classification, 
            and remediation guidance.
        </p>
"""
        
        for idx, finding in enumerate(sorted_findings[:25], 1):
            sev = finding.get("severity", "MEDIUM")
            sev_class = "critical" if sev in ["CRITICAL", "ERROR"] else "high" if sev == "HIGH" else "medium" if sev in ["MEDIUM", "WARNING"] else "low"
            sev_badge = f"badge-{sev_class}"
            
            html += f"""
        
        <div class="finding-card {sev_class}">
            <div class="finding-header">
                <div>
                    <span class="severity-badge {sev_badge}">{sev}</span>
                    <h3 style="margin-top: 15px; margin-bottom: 10px;">{idx}. {finding.get('message', 'Security Issue')}</h3>
                </div>
            </div>
            
            <div class="metadata">
                <div class="metadata-item">
                    <div class="metadata-label">Engine</div>
                    <div class="metadata-value">{finding.get('engine', 'unknown').title()}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Category</div>
                    <div class="metadata-value">{finding.get('category', 'Unknown')}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Location</div>
                    <div class="metadata-value">{finding.get('file', '')}:{finding.get('line_start', 0)}</div>
                </div>
"""
            
            if finding.get("cwe"):
                cwe = finding.get("cwe")
                cwe_str = cwe[0] if isinstance(cwe, list) else cwe
                html += f"""
                <div class="metadata-item">
                    <div class="metadata-label">CWE Classification</div>
                    <div class="metadata-value">{cwe_str}</div>
                </div>
"""
            
            if finding.get("package"):
                html += f"""
                <div class="metadata-item">
                    <div class="metadata-label">Package</div>
                    <div class="metadata-value">{finding.get('package')} {finding.get('installed_version', '')}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Fixed In</div>
                    <div class="metadata-value">{finding.get('fixed_version', 'Not available')}</div>
                </div>
"""
            
            html += """
            </div>
"""
            
            if finding.get("snippet"):
                html += f"""
            
            <div style="margin-top: 20px;">
                <div style="font-size: 12px; color: #64748b; margin-bottom: 8px; font-weight: 600;">VULNERABLE CODE:</div>
                <div class="code-block">{finding.get('snippet', '')[:400]}</div>
            </div>
"""
            
            html += """
        </div>
"""
        
        if len(findings) > 25:
            html += f"""
        
        <div style="background: #f8fafc; border-radius: 8px; padding: 20px; text-align: center; color: #64748b; margin: 30px 0;">
            <em>{len(findings) - 25} additional findings not included in this executive summary. 
            Complete findings available via API or detailed JSON export.</em>
        </div>
"""
        
        # Footer
        html += f"""
        
        <div class="footer">
            <div style="margin-bottom: 20px;">
                <span class="footer-logo">ATLAS SYNAPSE LLC</span> • The Sovereign Standard for Enterprise Security
            </div>
            <div style="font-size: 12px; color: #94a3b8;">
                Powered by Semgrep • Gitleaks • Trivy • CodeQL • Google Gemini AI
            </div>
            <div style="margin-top: 20px; font-size: 11px; color: #cbd5e1;">
                © 2026 Atlas Synapse LLC. All rights reserved. • Report generated {datetime.now().strftime("%B %d, %Y")}
            </div>
        </div>
        
        <div class="no-print" style="position: fixed; bottom: 20px; right: 20px; background: #3b82f6; color: white; 
                                      padding: 15px 25px; border-radius: 12px; box-shadow: 0 10px 40px rgba(59, 130, 246, 0.4); 
                                      font-weight: 600; cursor: pointer;" 
             onclick="window.print()">
            🖨️ Print / Save as PDF
        </div>
    </div>
</body>
</html>"""
        
        return html