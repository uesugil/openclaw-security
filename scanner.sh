#!/bin/bash
# scanner.sh - Simplified state machine (3 states: SCAN → REVIEW → REPORT)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="$SCRIPT_DIR/state.json"
RAW_DIR="$SCRIPT_DIR/findings/raw"
REVIEWED_DIR="$SCRIPT_DIR/findings/reviewed"
REPORTED_FILE="$SCRIPT_DIR/reported.jsonl"
SCANNED_FILE="$SCRIPT_DIR/scanned.txt"
LOG_FILE="$SCRIPT_DIR/scanner.log"
WORK_DIR="$SCRIPT_DIR/work"

mkdir -p "$RAW_DIR" "$REVIEWED_DIR" "$WORK_DIR"
touch "$SCANNED_FILE" "$REPORTED_FILE"

MAX_CLONE_SIZE_MB=200

log() { echo "[$(date -Iseconds)] $*" >> "$LOG_FILE"; }

get_state() {
  if [[ -f "$STATE_FILE" ]]; then cat "$STATE_FILE"
  else echo '{"state":"SCAN","repo":"","heartbeat":0}'; fi
}

save_state() {
  local state="$1" repo="$2" hb="$3"
  echo "{\"state\":\"$state\",\"repo\":\"$repo\",\"heartbeat\":$hb}" > "$STATE_FILE"
}

# Pick a repo we have not scanned yet
pick_repo() {
  local queries=("language:python+stars:50..500" "language:javascript+stars:50..500" "language:go+stars:50..500" "language:python+stars:500..5000" "language:javascript+stars:500..5000" "language:typescript+stars:50..500")
  local hb=${1:-0}
  local q_idx=$((hb % ${#queries[@]}))
  local query="${queries[$q_idx]}"
  local page=$(( (RANDOM % 5) + 1 ))

  local response
  response=$(curl -sf -H "Authorization: token ${GH_TOKEN:-}" \
    "https://api.github.com/search/repositories?q=${query}&sort=updated&page=${page}&per_page=10" 2>/dev/null)

  [[ -z "$response" ]] && return 1

  local found=""
  while IFS= read -r repo; do
    if ! grep -qF "$repo" "$SCANNED_FILE" 2>/dev/null; then
      found="$repo"
      break
    fi
  done < <(echo "$response" | grep -oE '"full_name"\s*:\s*"[^"]+"' | sed 's/.*"\([^"]*\)"/\1/')

  if [[ -n "$found" ]]; then
    echo "$found"
  else
    return 1
  fi
}

# SCAN: pick repo + clone + run scanners + cleanup (all in one heartbeat)
do_scan() {
  local hb="$1"

  local repo
  repo=$(pick_repo "$hb") || { log "No new repo found"; save_state "SCAN" "" "$hb"; return 1; }

  log "=== Scanning: $repo ==="
  local safe="${repo//\//_}"
  local clone_dir="$WORK_DIR/$safe"

  rm -rf "$clone_dir"
  if ! git clone --depth 1 --quiet "https://github.com/$repo.git" "$clone_dir" 2>/dev/null; then
    log "Clone failed: $repo"
    echo "$repo" >> "$SCANNED_FILE"
    save_state "SCAN" "" "$hb"
    return 1
  fi

  local size_mb
  size_mb=$(du -sm "$clone_dir" | cut -f1)
  if [[ "$size_mb" -gt "$MAX_CLONE_SIZE_MB" ]]; then
    log "Too large: ${size_mb}MB, skip"
    rm -rf "$clone_dir"
    echo "$repo" >> "$SCANNED_FILE"
    save_state "SCAN" "" "$hb"
    return 1
  fi

  local ts
  ts=$(date +%Y%m%d_%H%M%S)
  "$SCRIPT_DIR/scan-secrets.sh" "$clone_dir" "$RAW_DIR/secrets_${safe}_${ts}.json" 2>/dev/null
  "$SCRIPT_DIR/scan-deps.sh" "$clone_dir" "$RAW_DIR/deps_${safe}_${ts}.json" 2>/dev/null
  "$SCRIPT_DIR/scan-patterns.sh" "$clone_dir" "$RAW_DIR/patterns_${safe}_${ts}.json" 2>/dev/null

  rm -rf "$clone_dir"
  echo "$repo" >> "$SCANNED_FILE"

  local total=0
  for f in "$RAW_DIR"/*_${safe}_${ts}.json; do
    [[ -f "$f" ]] || continue
    local c
    c=$(grep -c '"id":' "$f" 2>/dev/null) || c=0
    total=$((total + c))
  done

  log "Scan done: $repo | ${size_mb}MB | $total findings"

  if [[ "$total" -gt 0 ]]; then
    save_state "REVIEW" "$repo" "$hb"
  else
    save_state "SCAN" "" "$hb"
  fi
}

# REVIEW: filter findings by confidence
do_review() {
  local repo="$1" hb="$2"
  local safe="${repo//\//_}"

  log "=== Reviewing: $repo ==="

  local reviewed_file="$REVIEWED_DIR/reviewed_${safe}.json"
  local tmpf
  tmpf=$(mktemp)
  local id=0

  for f in "$RAW_DIR"/*_${safe}_*.json; do
    [[ -f "$f" ]] || continue
    grep -oE '\{[^{}]*"id":[^{}]*\}' "$f" 2>/dev/null | while IFS= read -r finding; do
      local conf
      conf=$(echo "$finding" | grep -oE '"confidence":[0-9]+' | cut -d: -f2)
      [[ -z "$conf" || "$conf" -lt 4 ]] && continue
      echo "$finding" >> "$tmpf"
    done
  done

  local count
  count=$(wc -l < "$tmpf" | tr -d " ")

  echo "{\"repo\":\"$repo\",\"findings\":[" > "$reviewed_file"
  local first=1
  while IFS= read -r line; do
    [[ "$first" -eq 0 ]] && echo "," >> "$reviewed_file"
    echo "$line" >> "$reviewed_file"
    first=0
  done < "$tmpf"
  echo "]}" >> "$reviewed_file"
  rm -f "$tmpf"

  log "Review done: $count high-confidence findings"

  if [[ "$count" -gt 0 ]]; then
    save_state "REPORT" "$repo" "$hb"
  else
    save_state "SCAN" "" "$hb"
  fi
}

# REPORT: log for Telegram review (training phase)
do_report() {
  local repo="$1" hb="$2"
  local safe="${repo//\//_}"
  local reviewed_file="$REVIEWED_DIR/reviewed_${safe}.json"

  log "=== Reporting: $repo ==="

  local count
  count=$(grep -c '"id":' "$reviewed_file" 2>/dev/null || echo 0)
  echo "{\"repo\":\"$repo\",\"findings\":$count,\"ts\":\"$(date -Iseconds)\",\"status\":\"pending_review\"}" >> "$REPORTED_FILE"

  log "Report logged: $repo ($count findings)"
  save_state "SCAN" "" "$hb"
}

# Main
main() {
  local state_json
  state_json=$(get_state)
  local state repo hb
  state=$(echo "$state_json" | grep -oE '"state":"[^"]*"' | cut -d'"' -f4)
  repo=$(echo "$state_json" | grep -oE '"repo":"[^"]*"' | cut -d'"' -f4)
  hb=$(echo "$state_json" | grep -oE '"heartbeat":[0-9]+' | cut -d: -f2)
  hb=$((hb + 1))

  log "--- Heartbeat #$hb | State: $state | Repo: ${repo:-none} ---"

  case "$state" in
    SCAN)   do_scan "$hb" ;;
    REVIEW) do_review "$repo" "$hb" ;;
    REPORT) do_report "$repo" "$hb" ;;
    *)      log "Unknown state, reset"; save_state "SCAN" "" "$hb" ;;
  esac
}

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main
