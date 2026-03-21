#!/bin/bash
# scan-secrets.sh - Detect hardcoded secrets in source code
# Part of openclaw-security: GitHub public code security scanner
# 
# Detects: AWS keys, GitHub tokens, passwords, private keys, API keys
# Usage: ./scan-secrets.sh <directory>

TARGET_DIR="${1:-.}"
FINDINGS_FILE="${2:-findings/raw/secrets.json}"

# Ensure output directory exists
mkdir -p "$(dirname "$FINDINGS_FILE")"

# Temp file for findings
TEMP_FILE=$(mktemp)
finding_id=0

# AWS Access Key ID (starts with AKIA)
grep -rn --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" --include="*.rb" --include="*.env" -E 'AKIA[0-9A-Z]{16}' "$TARGET_DIR" 2>/dev/null | while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    match=$(echo "$line" | grep -oE 'AKIA[0-9A-Z]{16}' || echo "AKIA****")
    echo "{\"id\":$finding_id,\"type\":\"AWS_KEY\",\"file\":\"$file\",\"match\":\"${match:0:4}****\",\"confidence\":5}" >> "$TEMP_FILE"
    finding_id=$((finding_id + 1))
done

# GitHub Personal Access Token
grep -rn --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" --include="*.rb" --include="*.env" -E 'ghp_[a-zA-Z0-9]{36}' "$TARGET_DIR" 2>/dev/null | while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    echo "{\"id\":$finding_id,\"type\":\"GITHUB_TOKEN\",\"file\":\"$file\",\"match\":\"ghp_****\",\"confidence\":5}" >> "$TEMP_FILE"
    finding_id=$((finding_id + 1))
done

# Password patterns
grep -rn --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" --include="*.rb" --include="*.env" -iE '(password|passwd|pwd|secret_key|api_key)\s*=\s*["\047][^"\047]{4,}["\047]' "$TARGET_DIR" 2>/dev/null | while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    echo "{\"id\":$finding_id,\"type\":\"HARDCODED_PASSWORD\",\"file\":\"$file\",\"match\":\"[REDACTED]\",\"confidence\":4}" >> "$TEMP_FILE"
    finding_id=$((finding_id + 1))
done

# Private key header
grep -rn --include="*.pem" --include="*.key" --include="*.txt" --include="*.env" -E '-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----' "$TARGET_DIR" 2>/dev/null | while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    echo "{\"id\":$finding_id,\"type\":\"PRIVATE_KEY\",\"file\":\"$file\",\"match\":\"[REDACTED]\",\"confidence\":5}" >> "$TEMP_FILE"
    finding_id=$((finding_id + 1))
done

# Count findings
finding_count=$(wc -l < "$TEMP_FILE" 2>/dev/null || echo "0")

# Write JSON output
if [[ "$finding_count" -gt 0 ]]; then
    echo '{"findings":[' > "$FINDINGS_FILE"
    # Add commas between entries
    sed '$!s/$/,/' "$TEMP_FILE" >> "$FINDINGS_FILE"
    echo ']}' >> "$FINDINGS_FILE"
else
    echo '{"findings":[]}' > "$FINDINGS_FILE"
fi

rm -f "$TEMP_FILE"

echo "Scan complete. Found $finding_count potential secrets."
echo "Results saved to: $FINDINGS_FILE"
