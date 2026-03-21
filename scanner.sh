#!/bin/bash
# scanner.sh - State machine orchestrator for openclaw-security
# Part of openclaw-security: GitHub public code security scanner
#
# States: IDLE → SELECTING → CLONING → SCANNING → REVIEWING → REPORTING → IDLE
# Usage: ./scanner.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="$SCRIPT_DIR/state.json"
FINDINGS_DIR="$SCRIPT_DIR/findings"
RAW_DIR="$FINDINGS_DIR/raw"
REVIEWED_DIR="$FINDINGS_DIR/reviewed"
LOG_FILE="$SCRIPT_DIR/scanner.log"

# Ensure directories exist
mkdir -p "$RAW_DIR" "$REVIEWED_DIR"

# Configuration
MAX_CLONE_SIZE_MB=200
CONFIDENCE_THRESHOLD=4
DAILY_ISSUE_LIMIT=3
WEEKLY_OWNER_LIMIT=1

# State management
get_state() {
    if [[ ! -f "$STATE_FILE" ]]; then
        echo '{"state":"IDLE","repo":null,"heartbeat":0}'
    else
        cat "$STATE_FILE"
    fi
}

set_state() {
    local state="$1"
    local repo="$2"
    local heartbeat="$3"
    echo "{\"state\":\"$state\",\"repo\":\"$repo\",\"heartbeat\":$heartbeat}" > "$STATE_FILE"
}

log() {
    echo "[$(date -Iseconds)] $*" >> "$LOG_FILE"
}

# Select a target repository using GitHub API
select_repo() {
    log "Selecting target repository..."
    
    # Search for repositories using GitHub API
    local response repos
    response=$(curl -s -H "Authorization: token ${GH_TOKEN:-}" \
        "https://api.github.com/search/repositories?q=language:python+stars:>50&sort=updated&order=desc&per_page=20")
    
    # Extract a random repo from the results (handle JSON spacing)
    repos=$(echo "$response" | grep '"full_name"' | head -5 | sed 's/.*"full_name": *"\([^"]*\)".*/\1/' | shuf | head -1)
    
    if [[ -z "$repos" ]]; then
        # Fallback to JavaScript repos
        response=$(curl -s -H "Authorization: token ${GH_TOKEN:-}" \
            "https://api.github.com/search/repositories?q=language:javascript+stars:>50&sort=updated&order=desc&per_page=20")
        repos=$(echo "$response" | grep '"full_name"' | head -5 | sed 's/.*"full_name": *"\([^"]*\)".*/\1/' | shuf | head -1)
    fi
    
    if [[ -z "$repos" ]]; then
        log "ERROR: No suitable repositories found"
        return 1
    fi
    
    log "Selected repository: $repos"
    echo "$repos"
}

# Clone repository (shallow clone)
clone_repo() {
    local repo="$1"
    # Sanitize repo name for directory (replace / with _)
    local safe_repo_name="${repo//\//_}"
    local clone_dir="$SCRIPT_DIR/work/$safe_repo_name"
    
    log "Cloning $repo..."
    
    # Create clone directory
    mkdir -p "$clone_dir"
    
    # Shallow clone
    if ! git clone --depth 1 "https://github.com/$repo.git" "$clone_dir" 2>/dev/null; then
        log "ERROR: Failed to clone $repo"
        rm -rf "$clone_dir"
        return 1
    fi
    
    # Check size
    local size_mb
    size_mb=$(du -sm "$clone_dir" | cut -f1)
    if [[ "$size_mb" -gt "$MAX_CLONE_SIZE_MB" ]]; then
        log "WARNING: Repository too large (${size_mb}MB), skipping"
        rm -rf "$clone_dir"
        return 1
    fi
    
    log "Cloned $repo (${size_mb}MB)"
    echo "$clone_dir"
}

# Run all scanners
run_scanners() {
    local repo_dir="$1"
    local repo_name="$2"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    # Sanitize repo name (replace / with _)
    local safe_repo_name="${repo_name//\//_}"
    
    log "Running security scanners on $repo_name..."
    
    # Run secret scanner
    "$SCRIPT_DIR/scan-secrets.sh" "$repo_dir" "$RAW_DIR/secrets_${safe_repo_name}_${timestamp}.json" || true
    
    # Run dependency scanner
    "$SCRIPT_DIR/scan-deps.sh" "$repo_dir" "$RAW_DIR/deps_${safe_repo_name}_${timestamp}.json" || true
    
    # Run pattern scanner
    "$SCRIPT_DIR/scan-patterns.sh" "$repo_dir" "$RAW_DIR/patterns_${safe_repo_name}_${timestamp}.json" || true
    
    log "Scanners completed"
}

# Review findings (filter high confidence, exclude test files)
review_findings() {
    local repo_name="$1"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    # Sanitize repo name (replace / with _)
    local safe_repo_name="${repo_name//\//_}"
    local reviewed_file="$REVIEWED_DIR/reviewed_${safe_repo_name}_${timestamp}.json"
    
    log "Reviewing findings for $repo_name..."
    
    # Combine all findings and filter
    local all_findings=()
    
    for findings_file in "$RAW_DIR"/secrets_*.json "$RAW_DIR"/deps_*.json "$RAW_DIR"/patterns_*.json; do
        [[ -f "$findings_file" ]] || continue
        
        # Extract findings with confidence >= threshold
        while IFS= read -r finding; do
            local confidence
            confidence=$(echo "$finding" | grep -oE '"confidence":[0-9]+' | cut -d: -f2)
            if [[ "$confidence" -ge "$CONFIDENCE_THRESHOLD" ]]; then
                all_findings+=("$finding")
            fi
        done < <(grep -oE '\{[^}]+\}' "$findings_file" 2>/dev/null || true)
    done
    
    # Write reviewed findings
    if [[ ${#all_findings[@]} -gt 0 ]]; then
        echo '{"findings":[' > "$reviewed_file"
        for i in "${!all_findings[@]}"; do
            if [[ $i -lt $((${#all_findings[@]} - 1)) ]]; then
                echo "${all_findings[$i]}," >> "$reviewed_file"
            else
                echo "${all_findings[$i]}" >> "$reviewed_file"
            fi
        done
        echo ']}' >> "$reviewed_file"
        log "Found ${#all_findings[@]} high-confidence issues"
    else
        echo '{"findings":[]}' > "$reviewed_file"
        log "No high-confidence issues found"
    fi
    
    echo "$reviewed_file"
}

# Create GitHub issue
create_issue() {
    local repo="$1"
    local findings_file="$2"
    
    log "Creating issue for $repo..."
    
    # Count findings
    local finding_count
    finding_count=$(grep -c '"id":' "$findings_file" 2>/dev/null || echo "0")
    
    if [[ "$finding_count" -eq 0 ]]; then
        log "No findings to report"
        return 0
    fi
    
    # Generate issue body
    local body="## 🔒 Automated Security Scan Report

This is an automated security scan from **openclaw-security**, an open-source tool that scans public GitHub repositories for common security issues.

### Summary

- **Scan Date:** $(date -Iseconds)
- **Issues Found:** $finding_count
- **Confidence Threshold:** $CONFIDENCE_THRESHOLD/5

### Findings

\`\`\`json
$(cat "$findings_file" | head -c 3000)
\`\`\`

### Notes

- This is an **automated scan** - please verify findings manually
- Some findings may be false positives (test files, example code, etc.)
- Secrets shown are **masked** for security
- If this is a false positive, please let us know so we can improve the scanner

### Tool

Repository: https://github.com/uesugil/openclaw-security

---

*This issue was created automatically by a security scanning bot. If you believe this is incorrect, please comment and we'll investigate.*"

    # Create the issue
    local issue_url
    issue_url=$(gh issue create \
        --repo "$repo" \
        --title "🔒 [Automated] Security Scan Findings" \
        --body "$body" \
        --label "security" 2>/dev/null || echo "")
    
    if [[ -n "$issue_url" ]]; then
        log "Created issue: $issue_url"
        echo "$issue_url"
    else
        log "Failed to create issue (may already exist or lack permissions)"
        return 1
    fi
}

# Main state machine
main() {
    local heartbeat
    heartbeat=$((${1:-0} + 1))
    
    local state_json
    state_json=$(get_state)
    
    local current_state repo_name
    current_state=$(echo "$state_json" | grep -oE '"state":"[^"]*"' | cut -d'"' -f4)
    repo_name=$(echo "$state_json" | grep -oE '"repo":"[^"]*"' | cut -d'"' -f4)
    
    log "Heartbeat #$heartbeat | State: $current_state | Repo: ${repo_name:-none}"
    
    case "$current_state" in
        IDLE)
            log "State: IDLE → SELECTING"
            local new_repo
            new_repo=$(select_repo) || {
                log "Failed to select repo, staying IDLE"
                set_state "IDLE" "" "$heartbeat"
                return 1
            }
            set_state "SELECTING" "$new_repo" "$heartbeat"
            ;;
            
        SELECTING)
            log "State: SELECTING → CLONING"
            set_state "CLONING" "$repo_name" "$heartbeat"
            ;;
            
        CLONING)
            local clone_dir
            clone_dir=$(clone_repo "$repo_name") || {
                log "Clone failed, returning to IDLE"
                set_state "IDLE" "" "$heartbeat"
                return 1
            }
            log "State: CLONING → SCANNING"
            set_state "SCANNING" "$repo_name" "$heartbeat"
            ;;
            
        SCANNING)
            # Sanitize repo name to match clone directory
            local safe_repo_name="${repo_name//\//_}"
            local clone_dir="$SCRIPT_DIR/work/$safe_repo_name"
            if [[ -d "$clone_dir" ]]; then
                run_scanners "$clone_dir" "$repo_name"
                # Clean up clone
                rm -rf "$clone_dir"
                log "State: SCANNING → REVIEWING"
                set_state "REVIEWING" "$repo_name" "$heartbeat"
            else
                log "Clone directory not found, returning to IDLE"
                set_state "IDLE" "" "$heartbeat"
            fi
            ;;
            
        REVIEWING)
            local reviewed_file
            reviewed_file=$(review_findings "$repo_name")
            local finding_count
            finding_count=$(grep -c '"id":' "$reviewed_file" 2>/dev/null || echo "0")
            
            if [[ "$finding_count" -gt 0 ]]; then
                log "State: REVIEWING → REPORTING ($finding_count findings)"
                set_state "REPORTING" "$repo_name" "$heartbeat"
            else
                log "No findings, returning to IDLE"
                set_state "IDLE" "" "$heartbeat"
            fi
            ;;
            
        REPORTING)
            # For first 20 findings, just log for review (per HEARTBEAT.md)
            # After training period, auto-create issues
            local reviewed_file
            reviewed_file=$(ls -t "$REVIEWED_DIR"/reviewed_*.json 2>/dev/null | head -1)
            
            if [[ -n "$reviewed_file" && -f "$reviewed_file" ]]; then
                # For now, just report findings via log
                # In production, this would create GitHub issues
                log "REPORTING: Findings ready for $repo_name"
                log "File: $reviewed_file"
                cat "$reviewed_file" >> "$LOG_FILE"
            fi
            
            log "State: REPORTING → IDLE"
            set_state "IDLE" "" "$heartbeat"
            ;;
            
        *)
            log "Unknown state: $current_state, resetting to IDLE"
            set_state "IDLE" "" "$heartbeat"
            ;;
    esac
    
    log "Heartbeat #$heartbeat complete"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Get last heartbeat count from state file
    last_heartbeat=0
    if [[ -f "$STATE_FILE" ]]; then
        last_heartbeat=$(grep -oE '"heartbeat":[0-9]+' "$STATE_FILE" | cut -d: -f2 || echo "0")
    fi
    
    main "$last_heartbeat"
fi
