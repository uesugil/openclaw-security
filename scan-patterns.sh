#!/bin/bash
# scan-patterns.sh - Detect dangerous code patterns
TARGET_DIR="${1:-.}"
FINDINGS_FILE="${2:-findings/raw/patterns.json}"
mkdir -p "$(dirname "$FINDINGS_FILE")"

TEMP_FILE=$(mktemp)

# Python dangerous patterns
grep -rn --include="*.py" -E "eval\s*\(|exec\s*\(|pickle\.loads?|yaml\.load\s*\(|os\.system\s*\(|subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True|__import__\s*\(" \
  "$TARGET_DIR" 2>/dev/null | grep -vE "/node_modules/|/\.git/|/vendor/|/test|_test\.|\.test\.|/spec|/mock|/example|/models/|model\.py|torch|tensorflow|keras" > "$TEMP_FILE" || true

# SQL injection patterns (Python + JS)
grep -rn --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  -E "execute\s*\([^)]*(%|\.format|\+|f\")" \
  "$TARGET_DIR" 2>/dev/null | grep -vE "/node_modules/|/\.git/|/vendor/|/test|_test\.|/models/|model\.py|torch|tensorflow|keras|/models/|model\.py|torch|tensorflow|keras" >> "$TEMP_FILE" || true

# JS dangerous patterns
grep -rn --include="*.js" --include="*.ts" -E "eval\s*\(|new\s+Function\s*\(" \
  "$TARGET_DIR" 2>/dev/null | grep -vE "/node_modules/|/\.git/|/vendor/|/test|_test\.|\.test\.|/spec|/dist/|/models/|model\.py|torch|tensorflow|keras|/models/|model\.py|torch|tensorflow|keras" >> "$TEMP_FILE" || true

finding_count=$(wc -l < "$TEMP_FILE" | tr -d " ")

if [[ "$finding_count" -gt 0 ]]; then
  echo "{\"findings\":[" > "$FINDINGS_FILE"
  id=0
  while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    # Detect type
    type="DANGEROUS_PATTERN"
    conf=4
    if echo "$line" | grep -qE "eval\s*\("; then type="EVAL"; fi
    if echo "$line" | grep -qE "pickle"; then type="PICKLE_LOADS"; conf=5; fi
    if echo "$line" | grep -qE "yaml\.load"; then type="UNSAFE_YAML"; fi
    if echo "$line" | grep -qE "os\.system|shell\s*=\s*True"; then type="COMMAND_INJECTION"; fi
    if echo "$line" | grep -qE "execute.*(%|format|\+)"; then type="SQL_INJECTION"; fi
    
    [[ $id -gt 0 ]] && echo "," >> "$FINDINGS_FILE"
    echo "{\"id\":$id,\"type\":\"$type\",\"file\":\"$file\",\"line\":$lineno,\"confidence\":$conf}" >> "$FINDINGS_FILE"
    id=$((id + 1))
  done < "$TEMP_FILE"
  echo "]}" >> "$FINDINGS_FILE"
else
  echo "{\"findings\":[]}" > "$FINDINGS_FILE"
fi

rm -f "$TEMP_FILE"
echo "Found $finding_count patterns."
