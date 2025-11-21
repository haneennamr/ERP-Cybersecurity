#!/bin/bash

# === Configuration ===
PROJECT_ROOT="$HOME/ERP-for-Konecta"
REPORT_DIR="$PROJECT_ROOT/reports"
COMBINED_CSV="$PROJECT_ROOT/combined_static_report.csv" # Saved to root for easy access
SERVICE_BASE_PATH="src/backend"

# --- Static Report Info ---
PROJECT_NAME="Konecta ERP system"
PROJECT_VERSION="1.0"
GITLEAKS_VERSION="8.16.0"
SNYK_VERSION="1.1300.2"
SEMGREP_VERSION="1.142.1"

# --- Services to Scan ---
SERVICE_NAMES=(
    "auth-service"
    "hr-service"
    "api-geteway"
    "user-management"
    "discovery"
    "config"
    "finance-service"
    "report-service"
    "inventory-service"
    "frontend"               # <--- Added frontend here
)

# === 1. Setup Phase ===
echo "Starting static analysis (SAST) script..."
echo "Project Root: $PROJECT_ROOT"
mkdir -p "$REPORT_DIR"
echo "Report Directory: $REPORT_DIR"

if ! command -v jq &> /dev/null
then
    echo "------------------------------------------------------------------"
    echo "ERROR: 'jq' is not installed, but it's required to create the CSV."
    echo "Please run: sudo apt install jq"
    echo "------------------------------------------------------------------"
    exit 1
fi

# === 2. Run Gitleaks (Secret Scan) ===
echo "------------------------------------------------------------------"
echo "Running Gitleaks scan on $PROJECT_ROOT"
echo "------------------------------------------------------------------"
cd "$PROJECT_ROOT"
gitleaks detect --source . --report-format json --report-path "$REPORT_DIR/gitleaks_report.json"
echo "Gitleaks report saved to $REPORT_DIR/gitleaks_report.json"

# === 3. Run Snyk (Dependency Scans) ===
echo "------------------------------------------------------------------"
echo "Looping and running Snyk on services..."
echo "------------------------------------------------------------------"

for service in "${SERVICE_NAMES[@]}"; do

    # === NEW: frontend path detection ===
    if [ "$service" == "frontend" ]; then
        local_service_path="$PROJECT_ROOT/src/frontend"
    else
        local_service_path="$PROJECT_ROOT/$SERVICE_BASE_PATH/$service"
    fi

    local_report_path="$REPORT_DIR/snyk_report_${service}.json"

    echo "--- Scanning $service ---"

    if [ ! -d "$local_service_path" ]; then
        echo "WARNING: Directory not found, skipping: $local_service_path"
        continue
    fi

    cd "$local_service_path"
    if [ -f "mvnw" ]; then
        chmod +x mvnw
    fi

    snyk test --json-file-output="$local_report_path"
    echo "Snyk report for $service saved to $local_report_path"
done

# === 4. Run Semgrep (SAST Scan) ===
echo "------------------------------------------------------------------"
echo "Running Semgrep SAST scan with --config=auto"
echo "------------------------------------------------------------------"
cd "$PROJECT_ROOT"
semgrep --config=auto . --json > "$REPORT_DIR/semgrep_sast_results.json"
echo "Semgrep report saved to $REPORT_DIR/semgrep_sast_results.json"

# === 5. Combine Reports into CSV (New Format) ===
echo "------------------------------------------------------------------"
echo "Combining all JSON reports into your custom CSV format..."
echo "------------------------------------------------------------------"

# Create the new CSV header
echo "Project,Version,Tool,Tool_Version,Severity,File,Line,Finding,Details,Recommendation" > "$COMBINED_CSV"

# --- Process Gitleaks ---
if [ -s "$REPORT_DIR/gitleaks_report.json" ]; then
    jq -r --arg proj "$PROJECT_NAME" --arg ver "$PROJECT_VERSION" --arg toolver "$GITLEAKS_VERSION" \
    '.[] | [$proj, $ver, "Gitleaks", $toolver, "CRITICAL", .File, .StartLine, .Description, .Match, "Revoke and remove hardcoded secret."] | @csv' \
    "$REPORT_DIR/gitleaks_report.json" >> "$COMBINED_CSV"
fi

# --- Process Snyk ---
echo "Processing Snyk reports..."
for snyk_report in "$REPORT_DIR"/snyk_report_*.json; do
    if [ -s "$snyk_report" ]; then
        echo "Parsing $snyk_report"
        jq -r --arg proj "$PROJECT_NAME" --arg ver "$PROJECT_VERSION" --arg toolver "$SNYK_VERSION" \
        '.vulnerabilities[]? | [$proj, $ver, "Snyk", $toolver, .severity, .from[-1], "N/A", .title, (.packageName + "@" + .version), (if .upgradePath[-1] then "Upgrade to " + .upgradePath[-1] else "See report for remediation." end)] | @csv' \
        "$snyk_report" >> "$COMBINED_CSV"
    else
        echo "Skipping empty or missing Snyk report: $snyk_report"
    fi
done

# --- Process Semgrep ---
if [ -s "$REPORT_DIR/semgrep_sast_results.json" ]; then
    jq -r --arg proj "$PROJECT_NAME" --arg ver "$PROJECT_VERSION" --arg toolver "$SEMGREP_VERSION" \
    '.results[] | [$proj, $ver, "Semgrep", $toolver, .extra.severity, .path, .start.line, (.extra.message | gsub("\n"; " ")), (.extra.lines | gsub("\n"; " ")), (.extra.fix // "See report for remediation." | gsub("\n"; " "))] | @csv' \
    "$REPORT_DIR/semgrep_sast_results.json" >> "$COMBINED_CSV"
fi

echo "✅ All scans complete!"
echo "Combined report is ready at: $COMBINED_CSV"
