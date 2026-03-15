// Atlas Synapse Aegis Prime Auditor — Jenkins Pipeline Integration
// Runs a security scan on every build and optionally blocks merges on CRITICAL findings.
//
// Required Jenkins environment variables / credentials:
//   AEGIS_BACKEND_URL        — URL of your deployed Aegis backend
//
// Optional:
//   AEGIS_FAIL_ON_CRITICAL   — "true" (default) to fail the build on CRITICAL findings
//   AEGIS_MAX_FILES          — maximum number of source files to upload per scan (default: 10)
//                              Keeping this low avoids API timeouts on large repos.

pipeline {
    agent any

    environment {
        AEGIS_BACKEND_URL      = "${env.AEGIS_BACKEND_URL ?: ''}"
        AEGIS_FAIL_ON_CRITICAL = "${env.AEGIS_FAIL_ON_CRITICAL ?: 'true'}"
        AEGIS_MAX_FILES        = "${env.AEGIS_MAX_FILES ?: '10'}"
    }

    stages {
        stage('Aegis Security Scan') {
            steps {
                script {
                    if (!env.AEGIS_BACKEND_URL) {
                        echo 'WARNING: AEGIS_BACKEND_URL is not configured — skipping Aegis scan.'
                        return
                    }

                    // Write inline Python scan script to workspace
                    writeFile file: 'aegis_scan.py', text: '''
import os, sys, json, glob, requests

backend = os.environ.get("AEGIS_BACKEND_URL", "").rstrip("/")
fail_on_critical = os.environ.get("AEGIS_FAIL_ON_CRITICAL", "true").lower() == "true"
# Limit upload count to avoid API timeouts; raise AEGIS_MAX_FILES as needed
max_files = int(os.environ.get("AEGIS_MAX_FILES", "10"))

patterns = ["**/*.py", "**/*.js", "**/*.ts", "**/*.java", "**/*.go"]
files = []
for pat in patterns:
    files.extend(glob.glob(pat, recursive=True))
files = [f for f in files if ".git" not in f and "node_modules" not in f][:max_files]

if not files:
    print("INFO: No source files found — skipping scan.")
    sys.exit(0)

print(f"Scanning {len(files)} file(s) via {backend}/api/scan ...")

# Upload all collected files in a single multipart request
file_handles = []
try:
    for path in files:
        fh = open(path, "rb")
        file_handles.append(fh)
    resp = requests.post(
        f"{backend}/api/scan",
        files=[("files", (os.path.basename(f), fh, "application/octet-stream"))
               for f, fh in zip(files, file_handles)],
        timeout=180,
    )
finally:
    for fh in file_handles:
        fh.close()

if resp.status_code != 200:
    print(f"ERROR: Scan request failed: {resp.status_code}")
    sys.exit(1)

data = resp.json()
total    = data.get("total_findings", 0)
ai       = data.get("ai_analysis", {})
risk     = ai.get("risk_level", "UNKNOWN")
score    = ai.get("risk_score", 0)
sev      = data.get("severity_breakdown", {})
critical = sev.get("CRITICAL", 0)
high     = sev.get("HIGH", 0)

print("=" * 60)
print("  ATLAS SYNAPSE - AEGIS PRIME SECURITY SCAN RESULTS")
print("=" * 60)
print(f"  Risk Level    : {risk}")
print(f"  Risk Score    : {score}/100")
print(f"  Total Findings: {total}")
print(f"  Critical      : {critical}")
print(f"  High          : {high}")
print("=" * 60)

# Persist results for Jenkins archiving
with open("aegis_results.json", "w") as out:
    json.dump(data, out, indent=2)

if fail_on_critical and critical > 0:
    print(f"ERROR: {critical} CRITICAL finding(s) detected — build failed.")
    sys.exit(1)
elif high > 3:
    print(f"WARNING: {high} HIGH severity findings require review.")
else:
    print("OK: No critical security issues detected.")
'''

                    sh '''
                        python3 -m pip install --quiet requests 2>/dev/null || pip3 install --quiet requests
                        python3 aegis_scan.py
                    '''
                }
            }

            post {
                always {
                    script {
                        if (fileExists('aegis_results.json')) {
                            archiveArtifacts artifacts: 'aegis_results.json', allowEmptyArchive: true
                        }
                        if (fileExists('aegis_scan.py')) {
                            sh 'rm -f aegis_scan.py'
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            echo 'Aegis Prime security scan stage complete.'
        }
        failure {
            echo 'ERROR: Build blocked by Aegis Prime Auditor — resolve CRITICAL vulnerabilities before merging.'
        }
        success {
            echo 'OK: Aegis Prime Auditor — no blocking security issues found.'
        }
    }
}
