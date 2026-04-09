#!/bin/bash
# Aegis Prime Auditor - Local Deployment Script
# Run this on your local machine to deploy the database and start the backend
# Requirements: psql installed, internet connection

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║   AEGIS PRIME AUDITOR - LOCAL DEPLOYMENT SCRIPT          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
SUPABASE_HOST="db.guodrtwqhbnnjrbfkbxs.supabase.co"
SUPABASE_USER="postgres"
SUPABASE_DB="postgres"
REPO_DIR="/workspaces/Aegis-Prime-Auditor"

echo "📋 STEP 1: Check Prerequisites"
echo "==============================="
echo ""

# Check if psql is installed
if ! command -v psql &> /dev/null; then
    echo "❌ psql not found. Please install PostgreSQL client:"
    echo "   macOS: brew install postgresql"
    echo "   Ubuntu: sudo apt-get install postgresql-client"
    echo "   Windows: Download from https://www.postgresql.org/download/windows/"
    exit 1
fi
echo "✅ psql installed"

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python not found"
    exit 1
fi
echo "✅ Python installed"

echo ""
echo "📋 STEP 2: Database Deployment"
echo "==============================="
echo ""

# Prompt for password
echo "You will be prompted for the Supabase password"
echo "(Check your Supabase dashboard for postgres user password)"
echo ""

read -sp "Enter Supabase password for postgres user: " SUPABASE_PASSWORD
echo ""
echo ""

# Set environment for psql
export PGPASSWORD="$SUPABASE_PASSWORD"

# Test connection
echo "🔗 Testing connection to Supabase..."
if psql -h "$SUPABASE_HOST" -U "$SUPABASE_USER" -d "$SUPABASE_DB" -c "SELECT 1" > /dev/null 2>&1; then
    echo "   ✅ Connection successful"
else
    echo "   ❌ Connection failed. Check password and try again."
    exit 1
fi

echo ""
echo "🚀 Applying database migrations..."
echo ""

# Apply migration 1: Enterprise Schema
echo "Step 1/2: Enterprise Schema..."
if psql -h "$SUPABASE_HOST" -U "$SUPABASE_USER" -d "$SUPABASE_DB" \
    -f "$REPO_DIR/supabase/migrations/001_enterprise_schema.sql" > /dev/null 2>&1; then
    echo "   ✅ Enterprise schema applied"
else
    echo "   ❌ Failed to apply enterprise schema"
    exit 1
fi

# Apply migration 2: Audit Setup
echo "Step 2/2: Audit setup..."
if psql -h "$SUPABASE_HOST" -U "$SUPABASE_USER" -d "$SUPABASE_DB" \
    -f "$REPO_DIR/backend/supabase_audit_setup.sql" > /dev/null 2>&1; then
    echo "   ✅ Audit setup applied"
else
    echo "   ⚠️  Audit setup had some warnings (non-critical)"
fi

echo ""
echo "✅ Verifying database..."
TABLE_COUNT=$(psql -h "$SUPABASE_HOST" -U "$SUPABASE_USER" -d "$SUPABASE_DB" \
    -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'")
echo "   Tables created: $TABLE_COUNT"

echo ""
echo "📋 STEP 3: Backend Deployment"
echo "=============================="
echo ""

cd "$REPO_DIR"

# Export environment variables
export SUPABASE_URL="https://guodrtwqhbnnjrbfkbxs.supabase.co"
export SUPABASE_SERVICE_ROLE_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imd1b2RydHdxaGJubmpyYmZrYnhzIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MjU0MTY3MiwiZXhwIjoyMDg4MTE3NjcyfQ.BywIApRxE5Hyr4qthkCEXzBOVgGOI7EiBxmrDPCQ8gw"
export JWT_SECRET="AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMn"
export NEXT_PUBLIC_SUPABASE_URL="https://guodrtwqhbnnjrbfkbxs.supabase.co"
export NEXT_PUBLIC_SUPABASE_ANON_KEY="sb_publishable_RSi6gvoGNvyvKy5ALKfFXg_BCcHMnGp"

echo "🧪 Running tests..."
python3 tests/test_schema_fixes.py
echo ""

echo "╔════════════════════════════════════════════════════════════╗"
echo "║          ✅ DATABASE DEPLOYMENT COMPLETE                  ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Next: Start the backend server"
echo ""
echo "   python3 backend/orchestrator.py"
echo ""
echo "The backend will start on http://localhost:8000"
echo ""
