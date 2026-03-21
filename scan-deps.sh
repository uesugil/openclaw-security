#!/bin/bash
# scan-deps.sh - Detect known vulnerable dependencies
# Part of openclaw-security: GitHub public code security scanner
#
# Parses package.json (Node.js) and requirements.txt (Python)
# Compares against a list of 20+ high-severity CVEs
# Usage: ./scan-deps.sh <directory>

set -euo pipefail

TARGET_DIR="${1:-.}"
FINDINGS_FILE="${2:-findings/raw/deps.json}"

# High-severity CVE database (package:affected_versions)
# Format: package_name:version_pattern:cve_id:severity
declare -A VULN_DB=(
    # Node.js vulnerabilities
    ["lodash"]="<4.17.21:CVE-2021-23337:HIGH"
    ["axios"]="<0.21.1:CVE-2021-3749:HIGH"
    ["node-fetch"]="<2.6.7:CVE-2022-0235:HIGH"
    ["express"]="<4.17.3:CVE-2022-24999:HIGH"
    ["minimist"]="<1.2.6:CVE-2021-44906:CRITICAL"
    ["moment"]="<2.29.2:CVE-2022-24785:HIGH"
    ["json5"]="<2.2.2:CVE-2022-46175:CRITICAL"
    ["qs"]="<6.5.3:CVE-2022-24999:HIGH"
    ["glob-parent"]="<5.1.2:CVE-2020-28469:HIGH"
    ["ansi-regex"]="<5.0.1:CVE-2021-3807:HIGH"
    ["async"]="<2.6.4:CVE-2021-23358:HIGH"
    ["shell-quote"]="<1.7.3:CVE-2021-42740:CRITICAL"
    
    # Python vulnerabilities
    ["requests"]="<2.31.0:CVE-2023-32681:HIGH"
    ["urllib3"]="<2.0.6:CVE-2023-45803:HIGH"
    ["pillow"]="<10.0.1:CVE-2023-44271:HIGH"
    ["jinja2"]="<3.1.2:CVE-2024-22195:HIGH"
    ["flask"]="<2.3.2:CVE-2023-30861:HIGH"
    ["django"]="<4.2.7:CVE-2023-46695:CRITICAL"
    ["pyyaml"]="<6.0.1:CVE-2020-14343:CRITICAL"
    ["cryptography"]="<41.0.4:CVE-2023-49083:HIGH"
    ["setuptools"]="<65.5.1:CVE-2022-40897:HIGH"
    ["numpy"]="<1.22.0:CVE-2021-41496:HIGH"
)

findings=()
finding_id=0

# Function to compare versions
version_lt() {
    local v1="$1"
    local v2="$2"
    
    # Simple version comparison using sort -V
    if [[ "$(printf '%s\n%s\n' "$v1" "$v2" | sort -V | head -n1)" == "$v1" ]]; then
        return 0  # v1 < v2
    else
        return 1  # v1 >= v2
    fi
}

# Scan package.json (Node.js)
scan_package_json() {
    local pkg_file="$1"
    
    if [[ ! -f "$pkg_file" ]]; then
        return
    fi
    
    # Extract dependencies using grep and sed (no jq dependency)
    local deps
    deps=$(grep -oE '"[a-z][a-z0-9_-]*":\s*"[^"]+"' "$pkg_file" 2>/dev/null || true)
    
    while IFS= read -r line; do
        if [[ -z "$line" ]]; then
            continue
        fi
        
        local pkg_name pkg_version
        pkg_name=$(echo "$line" | sed 's/"\([^"]*\)".*/\1/')
        pkg_version=$(echo "$line" | sed 's/.*: *"\([^"]*\)"/\1/' | sed 's/^[\^~]//')
        
        # Check against vulnerability database
        for vuln_pkg in "${!VULN_DB[@]}"; do
            if [[ "$pkg_name" == "$vuln_pkg" ]]; then
                local vuln_info="${VULN_DB[$vuln_pkg]}"
                local affected_version cve_id severity
                affected_version=$(echo "$vuln_info" | cut -d: -f1)
                cve_id=$(echo "$vuln_info" | cut -d: -f2)
                severity=$(echo "$vuln_info" | cut -d: -f3)
                
                if version_lt "$pkg_version" "$affected_version"; then
                    findings+=("{\"id\":$finding_id,\"type\":\"VULNERABLE_DEP\",\"package\":\"$pkg_name\",\"version\":\"$pkg_version\",\"affected\":\"<$affected_version\",\"cve\":\"$cve_id\",\"severity\":\"$severity\",\"file\":\"$pkg_file\",\"confidence\":5}")
                    ((finding_id++))
                fi
            fi
        done
    done <<< "$deps"
}

# Scan requirements.txt (Python)
scan_requirements_txt() {
    local req_file="$1"
    
    if [[ ! -f "$req_file" ]]; then
        return
    fi
    
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        
        # Parse package==version or package>=version etc.
        local pkg_name pkg_version
        pkg_name=$(echo "$line" | sed 's/[=<>!].*//' | tr -d ' ')
        pkg_version=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' || echo "0.0.0")
        
        # Check against vulnerability database
        for vuln_pkg in "${!VULN_DB[@]}"; do
            if [[ "$pkg_name" == "$vuln_pkg" ]]; then
                local vuln_info="${VULN_DB[$vuln_pkg]}"
                local affected_version cve_id severity
                affected_version=$(echo "$vuln_info" | cut -d: -f1)
                cve_id=$(echo "$vuln_info" | cut -d: -f2)
                severity=$(echo "$vuln_info" | cut -d: -f3)
                
                if version_lt "$pkg_version" "$affected_version"; then
                    findings+=("{\"id\":$finding_id,\"type\":\"VULNERABLE_DEP\",\"package\":\"$pkg_name\",\"version\":\"$pkg_version\",\"affected\":\"<$affected_version\",\"cve\":\"$cve_id\",\"severity\":\"$severity\",\"file\":\"$req_file\",\"confidence\":5}")
                    ((finding_id++))
                fi
            fi
        done
    done < "$req_file"
}

# Find and scan all dependency files
while IFS= read -r -d '' pkg_file; do
    scan_package_json "$pkg_file"
done < <(find "$TARGET_DIR" -name "package.json" -type f -print0 2>/dev/null)

while IFS= read -r -d '' req_file; do
    scan_requirements_txt "$req_file"
done < <(find "$TARGET_DIR" -name "requirements.txt" -type f -print0 2>/dev/null)

# Write findings to JSON file
if [[ ${#findings[@]} -gt 0 ]]; then
    echo '{"findings":[' > "$FINDINGS_FILE"
    for i in "${!findings[@]}"; do
        if [[ $i -lt $((${#findings[@]} - 1)) ]]; then
            echo "${findings[$i]}," >> "$FINDINGS_FILE"
        else
            echo "${findings[$i]}" >> "$FINDINGS_FILE"
        fi
    done
    echo ']}' >> "$FINDINGS_FILE"
else
    echo '{"findings":[]}' > "$FINDINGS_FILE"
fi

echo "Scan complete. Found $finding_id vulnerable dependencies."
echo "Results saved to: $FINDINGS_FILE"
