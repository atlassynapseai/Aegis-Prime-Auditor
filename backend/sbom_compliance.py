"""
SBOM Generator & Compliance Mapper for Atlas Synapse Auditor
Generates CycloneDX SBOM and maps findings to regulatory frameworks
"""

import json
from datetime import datetime
from typing import List, Dict, Any


class SBOMGenerator:
    """Generate CycloneDX 1.5 SBOM for NIST SSDF compliance."""
    
    @staticmethod
    def generate(scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate SBOM in CycloneDX format."""
        
        components = []
        seen_packages = set()
        
        trivy_findings = scan_result.get("engines", {}).get("trivy", {}).get("findings", [])
        
        for finding in trivy_findings:
            pkg_name = finding.get("package", "")
            pkg_version = finding.get("installed_version", "")
            
            if not pkg_name or (pkg_name, pkg_version) in seen_packages:
                continue
            
            seen_packages.add((pkg_name, pkg_version))
            
            component = {
                "type": "library",
                "name": pkg_name,
                "version": pkg_version,
                "purl": f"pkg:pypi/{pkg_name}@{pkg_version}",
                "properties": [{"name": "aquasecurity:trivy:PkgType", "value": "python-pkg"}]
            }
            
            if finding.get("cve"):
                component["vulnerabilities"] = [{
                    "id": finding.get("cve", ""),
                    "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{finding.get('cve', '')}"},
                    "ratings": [{
                        "score": finding.get("cvss_score", 0),
                        "severity": finding.get("severity", "UNKNOWN"),
                        "method": "CVSSv3"
                    }],
                    "description": finding.get("message", "")
                }]
            
            components.append(component)
        
        return {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [
                    {"vendor": "Atlas Synapse LLC", "name": "Aegis Prime Auditor", "version": "2.0.0"},
                    {"vendor": "Aqua Security", "name": "Trivy", "version": "0.50.1"}
                ],
                "component": {"type": "application", "name": scan_result.get("file", "unknown"), "version": "1.0.0"}
            },
            "components": components
        }


class ComplianceMapper:
    """Map findings to compliance frameworks."""
    
    FRAMEWORKS = {
        "PCI-DSS-4.0": {
            "CWE-89": ["6.5.1 - Injection Flaws"],
            "CWE-78": ["6.5.1 - Injection Flaws"],
            "CWE-79": ["6.5.7 - Cross-Site Scripting"],
            "CWE-798": ["8.2.1 - Strong Cryptography", "8.3.2 - Secure Authentication"],
            "CWE-327": ["4.1 - Encryption", "8.2.1 - Strong Cryptography"],
            "CWE-502": ["6.5.8 - Insecure Deserialization"],
            "CWE-22": ["6.5.1 - Injection Flaws"]
        },
        "OWASP-TOP-10-2021": {
            "CWE-89": ["A03:2021 - Injection"],
            "CWE-78": ["A03:2021 - Injection"],
            "CWE-79": ["A03:2021 - Injection"],
            "CWE-798": ["A07:2021 - Identification and Authentication Failures"],
            "CWE-327": ["A02:2021 - Cryptographic Failures"],
            "CWE-502": ["A08:2021 - Software and Data Integrity Failures"],
            "CWE-22": ["A01:2021 - Broken Access Control"],
            "CWE-95": ["A03:2021 - Injection"]
        },
        "NIST-SSDF": {
            "CWE-89": ["PW.7 - Secure Coding", "RV.1 - Vulnerability Identification"],
            "CWE-78": ["PW.7 - Secure Coding", "RV.1 - Vulnerability Identification"],
            "CWE-798": ["PW.8 - Protect Credentials"],
            "CWE-327": ["PW.8 - Cryptographic Protection"],
            "ANY": ["PO.3 - SBOM Creation", "PS.1 - Protect Software", "RV.1 - Find Vulnerabilities"]
        },
        "SOC-2-TYPE-II": {
            "CWE-89": ["CC6.1 - Logical Access", "CC6.6 - Vulnerability Management"],
            "CWE-798": ["CC6.1 - Logical Access", "CC6.7 - Credential Management"],
            "CWE-327": ["CC6.1 - Encryption"],
            "ANY": ["CC6.1 - System Security", "CC7.1 - Detection", "CC7.2 - Monitoring"]
        },
        "NYDFS-23-NYCRR-500": {
            "CWE-89": ["§500.15 - Penetration Testing"],
            "CWE-798": ["§500.07 - Access Controls"],
            "CWE-327": ["§500.15 - Cybersecurity"],
            "ANY": ["§500.03 - Cybersecurity Program", "§500.14 - Training"]
        }
    }
    
    @staticmethod
    def map_findings_to_compliance(findings: List[Dict]) -> Dict[str, Any]:
        """Map findings to compliance frameworks."""
        
        compliance_report = {"frameworks": {}, "total_violations": 0}
        
        for framework_name, cwe_mappings in ComplianceMapper.FRAMEWORKS.items():
            violations = []
            controls_affected = set()
            
            for finding in findings:
                cwe = finding.get("cwe", "")
                if isinstance(cwe, list):
                    cwe = cwe[0] if cwe else ""
                
                # Extract CWE number (e.g., "CWE-89" from "CWE-89: SQL Injection")
                if ":" in cwe:
                    cwe = cwe.split(":")[0].strip()
                
                if cwe in cwe_mappings:
                    controls = cwe_mappings[cwe]
                    controls_affected.update(controls)
                    
                    violations.append({
                        "finding_id": finding.get("id", ""),
                        "severity": finding.get("severity", ""),
                        "cwe": cwe,
                        "controls": controls,
                        "file": finding.get("file", ""),
                        "line": finding.get("line_start", 0),
                        "message": finding.get("message", "")[:100]
                    })
                
                if "ANY" in cwe_mappings:
                    controls_affected.update(cwe_mappings["ANY"])
            
            compliance_report["frameworks"][framework_name] = {
                "violations": len(violations),
                "controls_affected": sorted(list(controls_affected)),
                "details": violations[:10]
            }
            
            compliance_report["total_violations"] += len(violations)
        
        # Compliance status
        total_findings = len(findings)
        critical_findings = sum(1 for f in findings if f.get("severity") in ["CRITICAL", "ERROR"])
        
        compliance_report["compliance_status"] = {
            "ready_for_production": critical_findings == 0 and total_findings < 10,
            "requires_remediation": critical_findings > 0 or total_findings >= 10,
            "critical_blockers": critical_findings,
            "total_findings": total_findings,
            "recommendation": (
                "✅ PASS - Ready for production deployment" if critical_findings == 0 and total_findings < 5
                else "⚠️ CONDITIONAL - Remediate critical findings before deployment" if critical_findings <= 2
                else "❌ FAIL - Multiple critical vulnerabilities block compliance"
            )
        }
        
        return compliance_report


# ═══════════════════════════════════════════════════════════════════════════════
# ATLAS SYNAPSE REGULATORY RULES
# ═══════════════════════════════════════════════════════════════════════════════

ATLAS_REGULATORY_RULES = {
    "fintech": {
        "fair-lending-proxy-feature": {
            "pattern": r"(zipcode|zip_code|postal_code|geography|geo_location).*(?:credit_score|loan_amount|approval|deny)",
            "severity": "CRITICAL",
            "cwe": "Atlas-Fair-Lending",
            "message": "Fair Lending Act Violation: Geographic data may serve as proxy for protected class in credit decisioning",
            "compliance": ["Fair-Lending-Act", "ECOA", "Regulation-B"],
            "remediation": "Remove geographic features from credit models OR conduct disparate impact analysis to prove non-discrimination",
            "regulatory_citation": "Equal Credit Opportunity Act (ECOA), 15 U.S.C. § 1691 et seq."
        },
        "unexplained-ai-decision": {
            "pattern": r"(predict|ml_model|neural_network|decision_tree)\s*\([^)]*\).*(?:without|no|missing).*(?:explain|shap|lime|interpret)",
            "severity": "HIGH",
            "cwe": "Atlas-Explainability",
            "message": "NYDFS 23 NYCRR §500: Automated decisions in financial services require explainability",
            "compliance": ["NYDFS-500", "SR-11-7-Model-Risk-Management"],
            "remediation": "Implement SHAP values, decision lineage tracking, or rule-based explanations for all model predictions",
            "regulatory_citation": "NYDFS Cybersecurity Regulation 23 NYCRR 500, SR 11-7 Guidance on Model Risk Management"
        },
        "missing-audit-trail": {
            "pattern": r"(transaction|payment|transfer).*(?:without|no).*(?:log|audit|trail|record)",
            "severity": "HIGH",
            "cwe": "Atlas-Audit-Trail",
            "message": "Financial transaction without audit trail violates record-keeping requirements",
            "compliance": ["SOX-404", "FINRA-4511"],
            "remediation": "Implement comprehensive logging for all financial transactions with immutable audit trail",
            "regulatory_citation": "Sarbanes-Oxley Act Section 404, FINRA Rule 4511"
        }
    },
    "insurance": {
        "discriminatory-claims-processing": {
            "pattern": r"(race|ethnicity|gender|religion|national_origin).*(?:claim_amount|payout|settlement|denial)",
            "severity": "CRITICAL",
            "cwe": "Atlas-Discrimination",
            "message": "Insurance Discrimination: Protected attributes may influence claims processing outcomes",
            "compliance": ["State-Insurance-Codes", "Civil-Rights-Act"],
            "remediation": "Remove protected class variables from claims models; conduct algorithmic fairness audit",
            "regulatory_citation": "State Insurance Codes, Civil Rights Act Title VI"
        },
        "unvalidated-actuarial-model": {
            "pattern": r"(actuarial|risk_model|pricing_model).*(?:without|no).*(?:validation|backtesting|review)",
            "severity": "HIGH",
            "cwe": "Atlas-Model-Validation",
            "message": "Actuarial models require independent validation and backtesting per insurance regulations",
            "compliance": ["NAIC-Model-Audit-Rule"],
            "remediation": "Implement model validation framework with independent review and annual backtesting",
            "regulatory_citation": "NAIC Model Audit Rule (MAR)"
        }
    },
    "healthcare": {
        "phi-exposure": {
            "pattern": r"(patient_name|ssn|medical_record|diagnosis|treatment).*(?:log|print|console|debug)",
            "severity": "CRITICAL",
            "cwe": "Atlas-HIPAA",
            "message": "HIPAA Violation: Protected Health Information (PHI) may be exposed in logs or debug output",
            "compliance": ["HIPAA-Security-Rule", "HIPAA-Privacy-Rule"],
            "remediation": "Remove all PHI from logging; implement data masking and encryption at rest",
            "regulatory_citation": "45 CFR §164.312 - HIPAA Security Rule"
        }
    },
    "legal": {
        "inconsistent-contract-interpretation": {
            "pattern": r"(?:parse|extract|interpret).*contract.*(?:varies|different|inconsistent)",
            "severity": "HIGH",
            "cwe": "Atlas-Legal-Consistency",
            "message": "Legal Consistency Violation: Contract clauses interpreted differently across documents",
            "compliance": ["ABA-Model-Rules", "Legal-Professional-Standards"],
            "remediation": "Implement deterministic clause extraction; version control all interpretation rules; maintain decision audit log",
            "regulatory_citation": "ABA Model Rules of Professional Conduct Rule 1.1 (Competence)"
        },
        "missing-version-control": {
            "pattern": r"(legal_document|contract|agreement).*(?:without|no).*(?:version|revision|history)",
            "severity": "MEDIUM",
            "cwe": "Atlas-Document-Control",
            "message": "Legal documents require version control and change tracking for compliance",
            "compliance": ["Document-Retention-Policy"],
            "remediation": "Implement document version control system with immutable change log",
            "regulatory_citation": "Federal Rules of Civil Procedure Rule 26 (e-discovery requirements)"
        }
    }
}


class ComplianceMapper:
    """Map findings to compliance frameworks."""
    
    FRAMEWORKS = {
        "PCI-DSS-4.0": {
            "name": "Payment Card Industry Data Security Standard v4.0",
            "mappings": {
                "CWE-89": ["6.5.1 - Injection Flaws"],
                "CWE-78": ["6.5.1 - Injection Flaws"],
                "CWE-79": ["6.5.7 - Cross-Site Scripting (XSS)"],
                "CWE-798": ["8.2.1 - Strong Cryptography and Security Protocols", "8.3.2 - Secure Authentication"],
                "CWE-327": ["4.1 - Strong Cryptography", "8.2.1 - Encryption Standards"],
                "CWE-502": ["6.5.8 - Insecure Deserialization"],
                "CWE-22": ["6.5.1 - Injection Flaws"],
                "CWE-95": ["6.5.1 - Injection Flaws"]
            }
        },
        "OWASP-TOP-10-2021": {
            "name": "OWASP Top 10 Web Application Security Risks",
            "mappings": {
                "CWE-89": ["A03:2021 - Injection"],
                "CWE-78": ["A03:2021 - Injection"],
                "CWE-79": ["A03:2021 - Injection"],
                "CWE-95": ["A03:2021 - Injection"],
                "CWE-798": ["A07:2021 - Identification and Authentication Failures"],
                "CWE-327": ["A02:2021 - Cryptographic Failures"],
                "CWE-502": ["A08:2021 - Software and Data Integrity Failures"],
                "CWE-22": ["A01:2021 - Broken Access Control"]
            }
        },
        "NIST-SSDF-1.1": {
            "name": "NIST Secure Software Development Framework",
            "mappings": {
                "CWE-89": ["PW.7 - Secure Coding Practices", "RV.1 - Identify Vulnerabilities"],
                "CWE-78": ["PW.7 - Secure Coding Practices", "RV.1 - Identify Vulnerabilities"],
                "CWE-798": ["PW.8 - Reuse Existing Software When Appropriate"],
                "CWE-327": ["PW.8 - Protect All Forms of Code"],
                "ANY": ["PO.3 - Create and Maintain Well-Secured Software", "PS.1 - Protect Software", "RV.1 - Identify Vulnerabilities in Software"]
            }
        },
        "SOC-2-TYPE-II": {
            "name": "SOC 2 Type II Trust Services Criteria",
            "mappings": {
                "CWE-89": ["CC6.1 - Logical and Physical Access Controls", "CC6.6 - Vulnerability Management"],
                "CWE-798": ["CC6.1 - Access Controls", "CC6.7 - Data Encryption and Credentials"],
                "CWE-327": ["CC6.1 - Data Encryption"],
                "CWE-22": ["CC6.1 - Access Controls"],
                "ANY": ["CC6.1 - System Security", "CC7.1 - System Monitoring", "CC7.2 - Detection and Analysis"]
            }
        },
        "NYDFS-23-NYCRR-500": {
            "name": "New York Department of Financial Services Cybersecurity Regulation",
            "mappings": {
                "CWE-89": ["§500.15 - Penetration Testing and Vulnerability Assessments"],
                "CWE-798": ["§500.07 - Access Privilege Controls"],
                "CWE-327": ["§500.15 - Encryption Standards"],
                "CWE-22": ["§500.07 - Access Controls"],
                "ANY": ["§500.03 - Cybersecurity Program", "§500.14 - Training and Monitoring"]
            }
        },
        "CWE-TOP-25-2023": {
            "name": "CWE Top 25 Most Dangerous Software Weaknesses",
            "mappings": {
                "CWE-89": ["#3 - SQL Injection"],
                "CWE-78": ["#4 - OS Command Injection"],
                "CWE-79": ["#2 - Cross-Site Scripting"],
                "CWE-798": ["#8 - Hard-coded Credentials"],
                "CWE-327": ["#11 - Use of Broken Crypto"],
                "CWE-502": ["#9 - Deserialization of Untrusted Data"]
            }
        }
    }
    
    @staticmethod
    def map_findings_to_compliance(findings: List[Dict]) -> Dict[str, Any]:
        """Generate comprehensive compliance report."""
        
        compliance_report = {
            "frameworks": {},
            "total_violations": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        for framework_id, framework_data in ComplianceMapper.FRAMEWORKS.items():
            violations = []
            controls_affected = set()
            severity_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            
            for finding in findings:
                cwe = finding.get("cwe", "")
                if isinstance(cwe, list):
                    cwe = cwe[0] if cwe else ""
                
                # Clean CWE format
                if ":" in cwe:
                    cwe = cwe.split(":")[0].strip()
                
                # Map to framework
                mappings = framework_data.get("mappings", {})
                if cwe in mappings:
                    controls = mappings[cwe]
                    controls_affected.update(controls)
                    
                    violations.append({
                        "finding_id": finding.get("id", ""),
                        "severity": finding.get("severity", "MEDIUM"),
                        "cwe": cwe,
                        "controls": controls,
                        "file": finding.get("file", ""),
                        "line": finding.get("line_start", 0),
                        "message": finding.get("message", "")[:150],
                        "engine": finding.get("engine", "")
                    })
                    
                    # Count severity
                    sev = finding.get("severity", "MEDIUM")
                    if sev in ["CRITICAL", "ERROR"]:
                        severity_dist["CRITICAL"] += 1
                    elif sev in severity_dist:
                        severity_dist[sev] += 1
                
                # "ANY" mappings
                if "ANY" in mappings:
                    controls_affected.update(mappings["ANY"])
            
            compliance_report["frameworks"][framework_id] = {
                "name": framework_data.get("name", framework_id),
                "violations": len(violations),
                "controls_affected": sorted(list(controls_affected)),
                "severity_distribution": severity_dist,
                "details": violations,
                "compliance_percentage": max(0, 100 - (len(violations) * 5))  # Rough estimate
            }
        
        # Overall compliance status
        total_findings = len(findings)
        critical = sum(1 for f in findings if f.get("severity") in ["CRITICAL", "ERROR"])
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        
        compliance_report["overall_status"] = {
            "ready_for_production": critical == 0 and total_findings < 10,
            "requires_remediation": critical > 0 or total_findings >= 10,
            "critical_blockers": critical,
            "high_priority": high,
            "total_findings": total_findings,
            "recommendation": (
                "✅ COMPLIANT - Code meets baseline security standards for production"
                if critical == 0 and total_findings < 5
                else "⚠️ CONDITIONAL COMPLIANCE - Remediate critical/high findings for full compliance"
                if critical <= 2 and high <= 5
                else "❌ NON-COMPLIANT - Multiple critical vulnerabilities prevent regulatory approval"
            ),
            "estimated_remediation_time": (
                f"{critical * 4 + high * 2} developer-hours"
                if critical + high > 0
                else "0 hours - compliant"
            )
        }
        
        return compliance_report