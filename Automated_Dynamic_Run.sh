#!/usr/bin/env bash
set -euo pipefail

# =========================
# Part 1/3 — Config & Utils
# =========================

# === Configuration ===
PROJECT_ROOT="/home/kali/ERP-for-Konecta"
PROJECT_NAME="ERP-for-Konecta"
PROJECT_VERSION="1.0"
REPORT_DIR="$PROJECT_ROOT/reports"
WORDLIST_FILE="$PROJECT_ROOT/small.txt"
COMBINED_CSV="$REPORT_DIR/combined_dynamic_report.csv"

HTTP_TARGETS=(
  "http://localhost:8083"
  "http://localhost:8081"
  "http://localhost:4200"
  "http://localhost:8082"
  "http://localhost:8761"
  "http://localhost:8080"
  "http://localhost:8085"
)

FFUF_TARGETS=("${HTTP_TARGETS[@]}")

TCP_PORTS=(
  "localhost:5433"
  "localhost:5432"
  "localhost:5435"
)

CHECK_TIMEOUT=5
WAIT_RETRIES=3
WAIT_INTERVAL=2

log() { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }

# --- HTTP probe (uses curl) ---
probe_http() {
  local url="$1"
  if command -v curl &>/dev/null; then
    curl --silent --head --max-time "$CHECK_TIMEOUT" "$url" >/dev/null 2>&1
  else
    # fallback to /dev/tcp if curl missing
    local host port
    host=$(echo "$url" | sed -E 's~https?://([^/:]+).*~\1~')
    port=$(echo "$url" | sed -E 's~https?://[^/:]+:([0-9]+).*~\1~')
    [[ -z "$port" ]] && port=80
    timeout "$CHECK_TIMEOUT" bash -c "echo > /dev/tcp/$host/$port" >/dev/null 2>&1
  fi
}

# --- TCP probe (uses nc preferred) ---
probe_tcp() {
  local hostport="$1"
  local host="${hostport%%:*}"
  local port="${hostport##*:}"

  if command -v nc &>/dev/null; then
    nc -z -w "$CHECK_TIMEOUT" "$host" "$port" >/dev/null 2>&1
  else
    timeout "$CHECK_TIMEOUT" bash -c "cat < /dev/tcp/$host/$port" >/dev/null 2>&1
  fi
}

wait_for_service() {
  local url="$1" tries="$2" intv="$3"
  for ((i=1;i<=tries;i++)); do
    if probe_http "$url"; then
      log "Service responsive: $url (attempt $i)"
      return 0
    fi
    log "Service not responsive yet: $url (attempt $i/$tries). Waiting ${intv}s..."
    sleep "$intv"
  done
  log "Service did not respond at $url after $tries attempts."
  return 1
}

get_tool_version() {
  local tool="$1"
  case "$tool" in
    nikto)
      nikto -Version 2>/dev/null | head -n 1 || echo "N/A"
      ;;
    ffuf)
      ffuf -V 2>/dev/null | head -n 1 || echo "N/A"
      ;;
    *)
      echo "N/A"
      ;;
  esac
}

# === Pre-checks & setup ===
log "Starting DAST scan..."
mkdir -p "$REPORT_DIR"

# Ensure required binaries exist (fail fast)
for t in nikto ffuf jq curl nc; do
  if ! command -v "$t" &>/dev/null; then
    log "ERROR: Missing dependency: $t"
    exit 1
  fi
done

# create small wordlist if missing
mkdir -p "$(dirname "$WORDLIST_FILE")"
cat > "$WORDLIST_FILE" <<'EOF'
admin
login
swagger
openapi
api
health
metrics
actuator
EOF

# CSV header
echo "project,project version,finding,tool used,tool version,details,recommendation,severity" > "$COMBINED_CSV"
# =========================
# Part 2/3 — Tools logic & mapping
# =========================

# ---------- Nikto helpers & mapping ----------
safe_nikto() {
  local target="$1" out="$2"
  if wait_for_service "$target" "$WAIT_RETRIES" "$WAIT_INTERVAL"; then
    local tmp
    tmp=$(mktemp)
    # capture nikto output; nikto returns non-zero sometimes even on success, so validate JSON
    if nikto -h "$target" -o "$tmp" -Format json >/dev/null 2>&1; then
      # validate JSON
      if jq empty "$tmp" >/dev/null 2>&1; then
        mv "$tmp" "$out"
      else
        log "Nikto produced invalid JSON for $target — discarding"
        rm -f "$tmp"
      fi
    else
      # try to validate anyway; some versions print to stdout differently
      if jq empty "$tmp" >/dev/null 2>&1; then
        mv "$tmp" "$out"
      else
        log "Nikto failed for $target — no report saved"
        rm -f "$tmp"
      fi
    fi
  else
    log "Skipping Nikto for $target (unreachable)"
  fi
}

map_nikto_severity() {
  local msg="$1"
  local severity="Low"
  local recommendation="Informational; review configuration"
  shopt -s nocasematch
  if [[ "$msg" =~ sql\ injection || "$msg" =~ xss || "$msg" =~ "remote code" || "$msg" =~ "remote code execution" || "$msg" =~ "directory indexing" || "$msg" =~ "allows put" || "$msg" =~ "allows delete" || "$msg" =~ trace || "$msg" =~ admin || "$msg" =~ sensitive ]]; then
    severity="High"
    recommendation="Immediate review and patching required"
  elif [[ "$msg" =~ outdated || "$msg" =~ old || "$msg" =~ eol || "$msg" =~ cookie || "$msg" =~ ssl || "$msg" =~ tls || "$msg" =~ missing || "$msg" =~ header ]]; then
    severity="Medium"
    recommendation="Update configuration and apply security hardening"
  else
    severity="Low"
    recommendation="Informational; monitor"
  fi
  shopt -u nocasematch
  echo "$severity|$recommendation"
}

combine_nikto() {
  local file="$1"
  local tool="Nikto"
  local version
  version=$(get_tool_version nikto)
  [[ ! -s "$file" ]] && return
  if ! jq empty "$file" >/dev/null 2>&1; then
    log "Skipping invalid Nikto JSON: $file"
    return
  fi

  # iterate each vulnerability object
  jq -c '.vulnerabilities[]?' "$file" | while read -r vuln; do
    local msg finding map severity recommendation
    msg=$(echo "$vuln" | jq -r '.msg // "N/A"')
    finding="Vulnerability: $msg"
    map=$(map_nikto_severity "$msg")
    severity="${map%%|*}"
    recommendation="${map##*|}"

    # write CSV line (single-line)
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$PROJECT_NAME" \
      "$PROJECT_VERSION" \
      "$finding" \
      "$tool" \
      "$version" \
      "$msg" \
      "$recommendation" \
      "$severity" \
      >> "$COMBINED_CSV"
  done
}

# ---------- ffuf helpers & mapping ----------
safe_ffuf() {
  local base="$1" out="$2"
  base="${base%/}"
  if wait_for_service "$base" "$WAIT_RETRIES" "$WAIT_INTERVAL"; then
    local tmp
    tmp=$(mktemp)
    # capture ffuf stdout/stderr to tmp; only move to out when valid JSON
    if ffuf -u "${base}/FUZZ" -w "$WORDLIST_FILE" -t 30 -mc 200,301,302,403 -fs 0 -of json >"$tmp" 2>&1; then
      # verify JSON validity
      if jq empty "$tmp" >/dev/null 2>&1; then
        mv "$tmp" "$out"
      else
        log "ffuf produced invalid JSON for $base — discarding"
        rm -f "$tmp"
      fi
    else
      # ffuf may still produce JSON; validate and move if valid
      if jq empty "$tmp" >/dev/null 2>&1; then
        mv "$tmp" "$out"
      else
        log "ffuf failed for $base — discarding output"
        rm -f "$tmp"
      fi
    fi
  else
    log "Skipping ffuf for $base (unreachable)"
  fi
}

map_ffuf_severity() {
  local dir="$1"
  local severity="Low"
  local recommendation="Review directory exposure"
  case "$dir" in
    actuator|metrics|api|openapi|swagger)
      severity="High"
      case "$dir" in
        actuator) recommendation="Restrict actuator endpoints to internal-only or secure with Spring Security" ;;
        metrics) recommendation="Disable public metrics or protect behind authentication" ;;
        api) recommendation="Ensure API endpoints require authentication and proper authorization" ;;
        openapi|swagger) recommendation="Disable public API documentation or protect with authentication" ;;
      esac
      ;;
    admin|health)
      severity="Medium"
      if [[ "$dir" == "admin" ]]; then
        recommendation="Restrict admin endpoints with authentication and IP filtering"
      else
        recommendation="Restrict health endpoints or return limited info in production"
      fi
      ;;
    login)
      severity="Low"
      recommendation="Validate login endpoint exposure"
      ;;
    *)
      severity="Low"
      recommendation="Review directory exposure"
      ;;
  esac
  echo "$severity|$recommendation"
}

combine_ffuf() {
  local file="$1"
  local tool="ffuf"
  local version
  version=$(get_tool_version ffuf)
  [[ ! -s "$file" ]] && return
  if ! jq empty "$file" >/dev/null 2>&1; then
    log "Skipping invalid ffuf JSON: $file"
    return
  fi

  jq -c '.results[]?' "$file" | while read -r r; do
    local url status fuzz dir details finding map severity recommendation
    url=$(echo "$r" | jq -r '.url // "N/A"')
    status=$(echo "$r" | jq -r '.status // "N/A"')
    # fuzz may come as input.FUZZ or _path_
    fuzz=$(echo "$r" | jq -r '(.input.FUZZ // .input._path_ // .input // "N/A")')
    # standardize directory token: strip leading slashes, take first path segment if multiple
    dir=$(echo "$fuzz" | sed -e 's~^/~~' -e 's~/.*~~' -e 's~^$~root~')
    if [[ "$dir" == "N/A" || -z "$dir" ]]; then dir="unknown"; fi

    finding="Directory found: $dir"
    details="URL: $url (Status: $status)"
    map=$(map_ffuf_severity "$dir")
    severity="${map%%|*}"
    recommendation="${map##*|}"

    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$PROJECT_NAME" \
      "$PROJECT_VERSION" \
      "$finding" \
      "$tool" \
      "$version" \
      "$details" \
      "$recommendation" \
      "$severity" \
      >> "$COMBINED_CSV"
  done
}
# =========================
# Part 3/3 — Run scans & combine
# =========================

# Run nikto scans
for tgt in "${HTTP_TARGETS[@]}"; do
  safe_name=$(echo "$tgt" | sed -E 's~https?://~~; s~[:/]+~_~g')
  out="$REPORT_DIR/nikto_${safe_name}.json"
  safe_nikto "$tgt" "$out"
done

# Run ffuf scans
for tgt in "${FFUF_TARGETS[@]}"; do
  safe_name=$(echo "$tgt" | sed -E 's~https?://~~; s~[:/]+~_~g')
  out="$REPORT_DIR/ffuf_${safe_name}.json"
  safe_ffuf "$tgt" "$out"
done

# Probe TCP ports and append to CSV using same architecture
probe_tcp_ports() {
  local tool="TCP Probe" version="N/A"
  for hostport in "${TCP_PORTS[@]}"; do
    if probe_tcp "$hostport"; then
      printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$PROJECT_NAME" "$PROJECT_VERSION" \
        "Port $hostport OPEN" \
        "$tool" "$version" \
        "Port status: OPEN" \
        "Ensure firewall rules" \
        "Medium" \
        >> "$COMBINED_CSV"
      log "TCP $hostport OPEN"
    else
      printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$PROJECT_NAME" "$PROJECT_VERSION" \
        "Port $hostport CLOSED" \
        "$tool" "$version" \
        "Port status: CLOSED/UNREACHABLE" \
        "Check service availability" \
        "Low" \
        >> "$COMBINED_CSV"
      log "TCP $hostport CLOSED"
    fi
  done
}

probe_tcp_ports

# Combine Nikto JSON results
for f in "$REPORT_DIR"/nikto_*.json; do
  [[ -e "$f" ]] || continue
  combine_nikto "$f"
done

# Combine ffuf JSON results
for f in "$REPORT_DIR"/ffuf_*.json; do
  [[ -e "$f" ]] || continue
  combine_ffuf "$f"
done

log "DAST complete. Combined CSV generated at: $COMBINED_CSV"
