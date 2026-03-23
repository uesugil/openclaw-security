#!/bin/bash
# scan-deps.sh - Detect known vulnerable dependencies
# Part of openclaw-security: GitHub public code security scanner
#
# Parses package.json (Node.js) and requirements.txt (Python)
# Compares against a list of high-severity CVEs
# Usage: ./scan-deps.sh <directory>

TARGET_DIR="${1:-.}"
FINDINGS_FILE="${2:-findings/raw/deps.json}"

# Ensure output directory exists
mkdir -p "$(dirname "$FINDINGS_FILE")"

TEMP_FILE=$(mktemp)
finding_id=0

# Vulnerable Node.js packages (package:affected_below_version:cve:severity)
VULN_NODEJS="lodash:4.17.21:CVE-2021-23337:HIGH
axios:0.21.1:CVE-2021-3749:HIGH
minimist:1.2.6:CVE-2021-44906:CRITICAL
moment:2.29.2:CVE-2022-24785:HIGH
json5:2.2.2:CVE-2022-46175:CRITICAL
glob-parent:5.1.2:CVE-2020-28469:HIGH
ansi-regex:5.0.1:CVE-2021-3807:HIGH
shell-quote:1.7.3:CVE-2021-42740:CRITICAL"

# Vulnerable Python packages
VULN_PYTHON="requests:2.31.0:CVE-2023-32681:HIGH
urllib3:2.0.6:CVE-2023-45803:HIGH
pillow:10.0.1:CVE-2023-44271:HIGH
jinja2:3.1.2:CVE-2024-22195:HIGH
flask:2.3.2:CVE-2023-30861:HIGH
django:4.2.7:CVE-2023-46695:CRITICAL
pyyaml:6.0.1:CVE-2020-14343:CRITICAL
cryptography:41.0.4:CVE-2023-49083:HIGH
setuptools:65.5.1:CVE-2022-40897:HIGH"

# Simple version comparison (returns 0 if v1 < v2, returns 1 if v1 >= v2)
version_lt() {
    local v1="$1" v2="$2"
    # Normalize versions - extract only major.minor.patch
    v1=$(echo "$v1" | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?' || echo "$v1")
    v2=$(echo "$v2" | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?' || echo "$v2")
    # If versions are equal, NOT vulnerable (already patched)
    [[ "$v1" == "$v2" ]] && return 1
    # Check if v1 sorts before v2 (v1 < v2)
    local smaller
    smaller=$(printf '%s\n%s\n' "$v1" "$v2" | sort -V | head -n1)
    [[ "$smaller" == "$v1" && "$v1" != "$v2" ]]
}

# Scan package.json
if [[ -f "$TARGET_DIR/package.json" ]]; then
    while IFS=: read -r pkg safe_ver cve severity; do
        [[ -z "$pkg" ]] && continue
        # Extract version from package.json
        version=$(grep -oE "\"$pkg\":\s*\"[^\"]+\"" "$TARGET_DIR/package.json" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
        if [[ -n "$version" ]] && version_lt "$version" "$safe_ver"; then
            echo "{\"id\":$finding_id,\"type\":\"VULNERABLE_DEP\",\"package\":\"$pkg\",\"version\":\"$version\",\"affected\":\"<$safe_ver\",\"cve\":\"$cve\",\"severity\":\"$severity\",\"file\":\"$TARGET_DIR/package.json\",\"confidence\":5}" >> "$TEMP_FILE"
            finding_id=$((finding_id + 1))
        fi
    done <<< "$VULN_NODEJS"
fi

# Scan requirements.txt
if [[ -f "$TARGET_DIR/requirements.txt" ]]; then
    while IFS=: read -r pkg safe_ver cve severity; do
        [[ -z "$pkg" ]] && continue
        # Extract version from requirements.txt
        version=$(grep -iE "^$pkg==" "$TARGET_DIR/requirements.txt" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
        if [[ -n "$version" ]] && version_lt "$version" "$safe_ver"; then
            echo "{\"id\":$finding_id,\"type\":\"VULNERABLE_DEP\",\"package\":\"$pkg\",\"version\":\"$version\",\"affected\":\"<$safe_ver\",\"cve\":\"$cve\",\"severity\":\"$severity\",\"file\":\"$TARGET_DIR/requirements.txt\",\"confidence\":5}" >> "$TEMP_FILE"
            finding_id=$((finding_id + 1))
        fi
    done <<< "$VULN_PYTHON"
fi

# Count and write output
finding_count=$(wc -l < "$TEMP_FILE" 2>/dev/null || echo "0")

if [[ "$finding_count" -gt 0 ]]; then
    echo '{"findings":[' > "$FINDINGS_FILE"
    sed '$!s/$/,/' "$TEMP_FILE" >> "$FINDINGS_FILE"
    echo ']}' >> "$FINDINGS_FILE"
else
    echo '{"findings":[]}' > "$FINDINGS_FILE"
fi

rm -f "$TEMP_FILE"

echo "Scan complete. Found $finding_count vulnerable dependencies."
echo "Results saved to: $FINDINGS_FILE"
