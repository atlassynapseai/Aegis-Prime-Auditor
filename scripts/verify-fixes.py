#!/usr/bin/env python3
"""
Verification script for database schema & API fixes
Tests the key changes made in all 4 phases
"""

import sys
import json
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

def verify_imports():
    """Phase 1: Verify imports are correct"""
    print("🔍 Verifying imports...")
    try:
        from orchestrator import get_finding_type, enrich_findings, CATEGORY_TO_FINDING_TYPE
        from auth_middleware import AuthContext, get_auth_context_optional
        print("  ✅ All imports successful")
        return True
    except ImportError as e:
        print(f"  ❌ Import failed: {e}")
        return False

def verify_category_mapper():
    """Phase 2B: Verify category→finding_type mapper"""
    print("\n🔍 Verifying category mapper...")
    try:
        from orchestrator import get_finding_type, CATEGORY_TO_FINDING_TYPE

        test_cases = {
            "SAST": "sast",
            "Secrets": "secret",
            "SCA": "sca",
            "Deep Analysis": "sast",
            "Configuration Security": "compliance",
            "Infrastructure Security": "iac",
            "Container Security": "iac",
            "Malware Detection": "malware",
        }

        for category, expected_type in test_cases.items():
            actual_type = get_finding_type(category)
            if actual_type == expected_type:
                print(f"  ✅ {category} → {actual_type}")
            else:
                print(f"  ❌ {category} → {actual_type} (expected {expected_type})")
                return False

        return True
    except Exception as e:
        print(f"  ❌ Mapper test failed: {e}")
        return False

def verify_enrichment_function():
    """Phase 2C & 3: Verify enrich_findings adds type and org_id"""
    print("\n🔍 Verifying enrichment function...")
    try:
        from orchestrator import enrich_findings

        test_findings = [
            {
                "id": "f1",
                "message": "Test finding",
                "category": "SAST",
                "severity": "HIGH",
                "file": "test.py"
            },
            {
                "id": "f2",
                "message": "Secret found",
                "category": "Secrets",
                "severity": "CRITICAL",
                "file": "config.yaml"
            }
        ]

        test_org_id = "org-12345-67890"
        enriched = enrich_findings(test_findings, test_org_id)

        # Check first finding
        if enriched[0].get("type") != "sast":
            print(f"  ❌ Finding 1 type missing or wrong: {enriched[0].get('type')}")
            return False
        if enriched[0].get("org_id") != test_org_id:
            print(f"  ❌ Finding 1 org_id missing or wrong: {enriched[0].get('org_id')}")
            return False
        print(f"  ✅ Finding 1 enriched: type=sast, org_id={test_org_id}")

        # Check second finding
        if enriched[1].get("type") != "secret":
            print(f"  ✅ Finding 2 enriched: type=secret, org_id={test_org_id}")
            return False
        if enriched[1].get("org_id") != test_org_id:
            print(f"  ❌ Finding 2 org_id missing or wrong: {enriched[1].get('org_id')}")
            return False
        print(f"  ✅ Finding 2 enriched: type=secret, org_id={test_org_id}")

        return True
    except Exception as e:
        print(f"  ❌ Enrichment test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def verify_auth_context():
    """Phase 1A: Verify AuthContext has org_id"""
    print("\n🔍 Verifying AuthContext...")
    try:
        from auth_middleware import AuthContext

        # Create test context
        ctx = AuthContext(
            user_id="user-123",
            org_id="org-456",
            role="admin",
            permissions=["scan:create"]
        )

        if ctx.org_id != "org-456":
            print(f"  ❌ org_id not set correctly: {ctx.org_id}")
            return False

        if ctx.user_id != "user-123":
            print(f"  ❌ user_id not set correctly: {ctx.user_id}")
            return False

        print(f"  ✅ AuthContext org_id={ctx.org_id}, user_id={ctx.user_id}")
        return True
    except Exception as e:
        print(f"  ❌ AuthContext test failed: {e}")
        return False

def verify_orchestrator_changes():
    """Phase 1B: Verify orchestrator.py has auth in endpoint"""
    print("\n🔍 Verifying orchestrator.py endpoint signature...")
    try:
        import inspect
        from orchestrator import scan_code

        sig = inspect.signature(scan_code)
        params = list(sig.parameters.keys())

        required_params = ["files", "auth", "background_tasks"]

        for param in required_params:
            if param not in params:
                print(f"  ❌ Missing parameter: {param}")
                return False

        print(f"  ✅ scan_code has params: {params}")

        # Check auth has default (optional)
        auth_param = sig.parameters["auth"]
        if auth_param.default == inspect.Parameter.empty:
            print(f"  ⚠️  auth parameter has no default (required)")
        else:
            print(f"  ✅ auth parameter has default (optional)")

        return True
    except Exception as e:
        print(f"  ❌ Orchestrator verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all verifications"""
    print("=" * 60)
    print("DATABASE SCHEMA & API FIXES VERIFICATION")
    print("=" * 60)

    results = []

    # Phase A
    results.append(("Imports", verify_imports()))
    results.append(("Auth Context", verify_auth_context()))
    results.append(("Orchestrator Endpoint", verify_orchestrator_changes()))

    # Phase B
    results.append(("Category Mapper", verify_category_mapper()))
    results.append(("Enrichment Function", verify_enrichment_function()))

    # Summary
    print("\n" + "=" * 60)
    print("VERIFICATION SUMMARY")
    print("=" * 60)

    passed = 0
    failed = 0

    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:.<40} {status}")
        if result:
            passed += 1
        else:
            failed += 1

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("✅ All verifications passed!")
        return 0
    else:
        print(f"❌ {failed} verification(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
