#!/bin/bash
# scan-secrets.sh - Detect hardcoded secrets in source code
TARGET_DIR="${1:-.}"
FINDINGS_FILE="${2:-findings/raw/secrets.json}"
mkdir -p "$(dirname "$FINDINGS_FILE")"

TEMP_FILE=$(mktemp)

# All patterns in one grep pass, output file:line:match format
grep -rn \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" --include="*.env" --include="*.yml" \
  --include="*.yaml" --include="*.json" --include="*.toml" --include="*.cfg" \
  -E "AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{20,}|-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----|AIza[0-9A-Za-z_-]{35}" \
  "$TARGET_DIR" 2>/dev/null | grep -vE "/node_modules/|/\.git/|/vendor/|/dist/|/test/|/tests/|/__tests__/|_test\.|/spec/|/mock/|/fixture/|/example/|/sample/" > "$TEMP_FILE" || true

# Also catch password assignments separately (different pattern)
grep -rn \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" --include="*.env" \
  -iE "(password|passwd|secret_key|api_key|api_secret|access_token)\s*[:=]\s*[\"'][^\"']{6,}[\"']" \
  "$TARGET_DIR" 2>/dev/null | grep -vE "/node_modules/|/\.git/|/vendor/|/dist/|/test/|/tests/|/__tests__/|_test\.|/spec/|/mock/|/fixture/|/example/|/sample/|README" >> "$TEMP_FILE" || true

finding_count=$(wc -l < "$TEMP_FILE" | tr -d " ")

if [[ "$finding_count" -gt 0 ]]; then
  echo "{\"findings\":[" > "$FINDINGS_FILE"
  id=0
  while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    # Detect type
    type="SECRET"
    if echo "$line" | grep -qE "AKIA"; then type="AWS_KEY"; fi
    if echo "$line" | grep -qE "ghp_|gho_|ghs_"; then type="GITHUB_TOKEN"; fi
    if echo "$line" | grep -qE "sk-"; then type="OPENAI_KEY"; fi
    if echo "$line" | grep -qiE "password|passwd|secret_key|api_key"; then type="HARDCODED_PASSWORD"; fi
    if echo "$line" | grep -qE "PRIVATE KEY"; then type="PRIVATE_KEY"; fi
    if echo "$line" | grep -qE "AIza"; then type="GOOGLE_API_KEY"; fi
    
    [[ $id -gt 0 ]] && echo "," >> "$FINDINGS_FILE"
    echo "{\"id\":$id,\"type\":\"$type\",\"file\":\"$file\",\"line\":$lineno,\"confidence\":5}" >> "$FINDINGS_FILE"
    id=$((id + 1))
  done < "$TEMP_FILE"
  echo "]}" >> "$FINDINGS_FILE"
else
  echo "{\"findings\":[]}" > "$FINDINGS_FILE"
fi

rm -f "$TEMP_FILE"
echo "Found $finding_count secrets."
