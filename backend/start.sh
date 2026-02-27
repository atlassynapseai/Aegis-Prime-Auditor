#!/bin/bash
# Download Gitleaks
wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz
tar -xzf gitleaks_8.18.4_linux_x64.tar.gz
chmod +x gitleaks

# Download Trivy  
wget -q https://github.com/aquasecurity/trivy/releases/download/v0.50.1/trivy_0.50.1_Linux-64bit.tar.gz
tar -xzf trivy_0.50.1_Linux-64bit.tar.gz
chmod +x trivy
./trivy image --download-db-only

# Add to PATH
export PATH=$PATH:.

# Start server
python orchestrator.py
