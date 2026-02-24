#!/bin/bash

# Aegis Prime Auditor - Automated Setup Script
# For GitHub Codespaces or Ubuntu/Debian Linux

set -e  # Exit on error

echo "========================================================================"
echo "AEGIS PRIME AUDITOR - Automated Setup"
echo "========================================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "📋 Checking prerequisites..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 not found${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}✅ Python ${PYTHON_VERSION}${NC}"

# Install Python dependencies
echo ""
echo "📦 Installing Python dependencies..."
cd backend
pip install -q -r requirements.txt
echo -e "${GREEN}✅ Python packages installed${NC}"

# Install Semgrep
echo ""
echo "🔍 Installing Semgrep (SAST engine)..."
if ! command -v semgrep &> /dev/null; then
    pip install -q semgrep
    echo -e "${GREEN}✅ Semgrep installed${NC}"
else
    echo -e "${YELLOW}⚠️  Semgrep already installed${NC}"
fi

# Install Gitleaks
echo ""
echo "🔑 Installing Gitleaks (Secrets engine)..."
if ! command -v gitleaks &> /dev/null; then
    wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz
    tar -xzf gitleaks_8.18.4_linux_x64.tar.gz
    sudo mv gitleaks /usr/local/bin/
    rm gitleaks_8.18.4_linux_x64.tar.gz
    echo -e "${GREEN}✅ Gitleaks installed${NC}"
else
    echo -e "${YELLOW}⚠️  Gitleaks already installed${NC}"
fi

# Install Trivy
echo ""
echo "🔬 Installing Trivy (SCA engine)..."
if ! command -v trivy &> /dev/null; then
    wget -q https://github.com/aquasecurity/trivy/releases/download/v0.50.1/trivy_0.50.1_Linux-64bit.tar.gz
    tar -xzf trivy_0.50.1_Linux-64bit.tar.gz
    sudo mv trivy /usr/local/bin/
    rm trivy_0.50.1_Linux-64bit.tar.gz
    echo -e "${GREEN}✅ Trivy installed${NC}"
    
    echo "   Downloading vulnerability database..."
    trivy image --download-db-only > /dev/null 2>&1
    echo -e "${GREEN}   ✅ Trivy DB updated${NC}"
else
    echo -e "${YELLOW}⚠️  Trivy already installed${NC}"
fi

cd ..

# Setup environment
echo ""
echo "⚙️  Configuring environment..."
if [ ! -f .env ]; then
    cp config/.env.example .env
    echo -e "${YELLOW}⚠️  Created .env - YOU MUST ADD YOUR GEMINI API KEY${NC}"
    echo -e "   Get key at: ${GREEN}https://aistudio.google.com/apikey${NC}"
else
    echo -e "${GREEN}✅ .env already exists${NC}"
fi

# Install frontend dependencies (if Node.js available)
echo ""
if command -v npm &> /dev/null; then
    echo "🎨 Installing frontend dependencies..."
    cd frontend
    npm install --silent
    echo -e "${GREEN}✅ Frontend packages installed${NC}"
    cd ..
else
    echo -e "${YELLOW}⚠️  Node.js not found - skipping frontend setup${NC}"
fi

# Verify all engines
echo ""
echo "========================================================================"
echo "🔍 Verifying Installation"
echo "========================================================================"
echo ""

SEMGREP_OK=$(command -v semgrep &> /dev/null && echo "✅" || echo "❌")
GITLEAKS_OK=$(command -v gitleaks &> /dev/null && echo "✅" || echo "❌")
TRIVY_OK=$(command -v trivy &> /dev/null && echo "✅" || echo "❌")

echo -e "Semgrep:  ${SEMGREP_OK} $(semgrep --version 2>/dev/null || echo 'Not installed')"
echo -e "Gitleaks: ${GITLEAKS_OK} $(gitleaks version 2>/dev/null || echo 'Not installed')"
echo -e "Trivy:    ${TRIVY_OK} $(trivy --version 2>/dev/null | head -1 || echo 'Not installed')"
echo -e "CodeQL:   ✅ (built-in)"

echo ""
echo "========================================================================"
echo "🚀 Setup Complete!"
echo "========================================================================"
echo ""
echo "Next steps:"
echo "1. Edit .env and add your Gemini API key"
echo "2. Run backend: cd backend && python orchestrator.py"
echo "3. Run frontend: cd frontend && npm run dev"
echo "4. Access at: http://localhost:5173"
echo ""
echo "For full deployment guide, see: DEPLOYMENT.md"
echo "========================================================================"
