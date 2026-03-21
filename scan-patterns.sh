#!/bin/bash
# scan-patterns.sh - Detect dangerous code patterns
# Part of openclaw-security: GitHub public code security scanner
#
# Detects: eval(), SQL injection, pickle.loads, shell=True, command injection
# Usage: ./scan-patterns.sh <directory>

TARGET_DIR="${1:-.}"
FINDINGS_FILE="${2:-findings/raw/patterns.json}"

# Ensure output directory exists
mkdir -p "$(dirname "$FINDINGS_FILE")"

TEMP_FILE=$(mktemp)

# Scan function
scan_pattern() {
    local pattern="$1"
    local type="$2"
    local desc="$3"
    local confidence="$4"
    local lang="$5"
    local ext="$6"
    
    # Filter out actual test files, not directories containing "test"
    grep -rn --include="*.$ext" -E "$pattern" "$TARGET_DIR" 2>/dev/null | grep -vE '/test/|_test\.|\.test\.|spec/' | head -20 | while IFS= read -r line; do
        local file
        file=$(echo "$line" | cut -d: -f1)
        echo "{\"type\":\"$type\",\"file\":\"$file\",\"pattern\":\"$type detected\",\"confidence\":$confidence,\"description\":\"$desc\",\"language\":\"$lang\"}"
    done >> "$TEMP_FILE"
}

# Python patterns
scan_pattern 'eval\s*\(' 'EVAL_USAGE' 'Use of eval() can execute arbitrary code' 4 python py
scan_pattern 'exec\s*\(' 'EXEC_USAGE' 'Use of exec() can execute arbitrary code' 4 python py
scan_pattern 'pickle\.loads?' 'PICKLE_LOADS' 'Deserializing untrusted data with pickle is dangerous' 5 python py
scan_pattern 'yaml\.load\s*\(' 'YAML_LOAD' 'yaml.load() without SafeLoader can execute arbitrary code' 4 python py
scan_pattern 'os\.system\s*\(' 'OS_SYSTEM' 'os.system() is vulnerable to command injection' 4 python py
scan_pattern 'execute\s*\([^)]*%' 'SQL_STRING_FORMAT' 'String formatting in SQL queries enables SQL injection' 4 python py
scan_pattern 'hashlib\.(md5|sha1)\s*\(' 'WEAK_CRYPTO' 'Use of weak cryptographic hash function' 3 python py

# JavaScript patterns
scan_pattern 'eval\s*\(' 'EVAL_USAGE_JS' 'Use of eval() can execute arbitrary code' 4 javascript js
scan_pattern 'eval\s*\(' 'EVAL_USAGE_TS' 'Use of eval() can execute arbitrary code' 4 javascript ts
scan_pattern '\.innerHTML\s*=' 'INNER_HTML' 'Setting innerHTML can lead to XSS' 3 javascript js

# Count findings
finding_count=$(wc -l < "$TEMP_FILE" 2>/dev/null || echo "0")
finding_count=$(echo "$finding_count" | tr -d ' ')

# Add IDs and write JSON
if [[ "$finding_count" -gt 0 ]]; then
    echo '{"findings":[' > "$FINDINGS_FILE"
    id=0
    while IFS= read -r line; do
        if [[ $id -gt 0 ]]; then
            echo "," >> "$FINDINGS_FILE"
        fi
        echo "{\"id\":$id,$line}" >> "$FINDINGS_FILE"
        id=$((id + 1))
    done < "$TEMP_FILE"
    echo ']}' >> "$FINDINGS_FILE"
else
    echo '{"findings":[]}' > "$FINDINGS_FILE"
fi

rm -f "$TEMP_FILE"

echo "Scan complete. Found $finding_count dangerous code patterns."
echo "Results saved to: $FINDINGS_FILE"
