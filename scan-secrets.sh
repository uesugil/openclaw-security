#!/bin/bash
# scan-secrets.sh - Detect hardcoded secrets in source code
# Part of openclaw-security: GitHub public code security scanner
# 
# Detects: AWS keys, GitHub tokens, passwords, private keys, API keys
# Usage: ./scan-secrets.sh <directory>

set -euo pipefail

TARGET_DIR="${1:-.}"
FINDINGS_FILE="${2:-findings/raw/secrets.json}"
CONFIDENCE_THRESHOLD=3

# Initialize findings array
echo '{"findings":[]}' > "$FINDINGS_FILE"

# AWS Access Key ID (starts with AKIA)
aws_pattern='AKIA[0-9A-Z]{16}'

# GitHub Personal Access Token
gh_pattern='ghp_[a-zA-Z0-9]{36}'

# Generic password patterns
password_patterns=(
    'password\s*=\s*["\047][^"\047]{4,}["\047]'
    'passwd\s*=\s*["\047][^"\047]{4,}["\047]'
    'pwd\s*=\s*["\047][^"\047]{4,}["\047]'
    'SECRET_KEY\s*=\s*["\047][^"\047]{8,}["\047]'
    'API_KEY\s*=\s*["\047][^"\047]{8,}["\047]'
)

# Private key header
private_key_pattern='-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'

findings=()
finding_id=0

# Scan for AWS keys
while IFS= read -r line; do
    if [[ -n "$line" ]]; then
        file=$(echo "$line" | cut -d: -f1)
        match=$(echo "$line" | cut -d: -f2-)
        # Mask the key - show only first 4 chars
        masked="${match:0:4}****"
        findings+=("{\"id\":$finding_id,\"type\":\"AWS_KEY\",\"file\":\"$file\",\"match\":\"$masked\",\"confidence\":5}")
        ((finding_id++))
    fi
done < <(grep -rn --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" --include="*.rb" --include="*.env" -E "$aws_pattern" "$TARGET_DIR" 2>/dev/null || true)

# Scan for GitHub tokens
while IFS= read -r line; do
    if [[ -n "$line" ]]; then
        file=$(echo "$line" | cut -d: -f1)
        match=$(echo "$line" | cut -d: -f2-)
        masked="${match:0:4}****"
        findings+=("{\"id\":$finding_id,\"type\":\"GITHUB_TOKEN\",\"file\":\"$file\",\"match\":\"$masked\",\"confidence\":5}")
        ((finding_id++))
    fi
done < <(grep -rn --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" --include="*.rb" --include="*.env" -E "$gh_pattern" "$TARGET_DIR" 2>/dev/null || true)

# Scan for private keys
while IFS= read -r line; do
    if [[ -n "$line" ]]; then
        file=$(echo "$line" | cut -d: -f1)
        findings+=("{\"id\":$finding_id,\"type\":\"PRIVATE_KEY\",\"file\":\"$file\",\"match\":\"[REDACTED]\",\"confidence\":5}")
        ((finding_id++))
    fi
done < <(grep -rn --include="*.pem" --include="*.key" --include="*.txt" --include="*.env" -E "$private_key_pattern" "$TARGET_DIR" 2>/dev/null || true)

# Scan for password patterns
for pattern in "${password_patterns[@]}"; do
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            file=$(echo "$line" | cut -d: -f1)
            findings+=("{\"id\":$finding_id,\"type\":\"HARDCODED_PASSWORD\",\"file\":\"$file\",\"match\":\"[REDACTED]\",\"confidence\":4}")
            ((finding_id++))
        fi
    done < <(grep -rn --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" --include="*.rb" --include="*.env" -iE "$pattern" "$TARGET_DIR" 2>/dev/null || true)
done

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
fi

echo "Scan complete. Found $finding_id potential secrets."
echo "Results saved to: $FINDINGS_FILE"
