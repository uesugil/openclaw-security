#!/bin/bash
# scan-patterns.sh - Detect dangerous code patterns
# Part of openclaw-security: GitHub public code security scanner
#
# Detects: eval(), SQL injection, pickle.loads, shell=True, command injection
# Usage: ./scan-patterns.sh <directory>

set -euo pipefail

TARGET_DIR="${1:-.}"
FINDINGS_FILE="${2:-findings/raw/patterns.json}"

findings=()
finding_id=0

# Pattern definitions with confidence scores
# Format: pattern_name:regex:confidence:description
declare -a PATTERNS=(
    "EVAL_USAGE:eval\s*\(:4:Use of eval() can execute arbitrary code"
    "EXEC_USAGE:exec\s*\(:4:Use of exec() can execute arbitrary code"
    "PICKLE_LOADS:pickle\.loads?\s*\(:5:Deserializing untrusted data with pickle is dangerous"
    "YAML_LOAD:yaml\.load\s*\([^)]*\):4:yaml.load() without SafeLoader can execute arbitrary code"
    "SHELL_TRUE:subprocess\.[a-z]+\s*\([^)]*shell\s*=\s*True:4:shell=True in subprocess enables command injection"
    "OS_SYSTEM:os\.system\s*\(:4:os.system() is vulnerable to command injection"
    "SQL_STRING_FORMAT:execute\s*\(\s*[\"'][^\"']*%[sd]:4:String formatting in SQL queries enables SQL injection"
    "SQL_F_STRING:execute\s*\(\s*f[\"']:4:f-string in SQL queries enables SQL injection"
    "SQL_CONCAT:execute\s*\([^)]*\+:3:String concatenation in SQL queries enables SQL injection"
    "HARDCODED_HOST:https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:3:Hardcoded IP address in URL"
    "WEAK_CRYPTO:md5\s*\(|sha1\s*\(:(3:Use of weak cryptographic hash function"
    "RANDOM_PREDICTABLE:random\.randint|random\.random|Math\.random:2:Use of predictable random number generator"
    "INPUT_RAW:input\s*\(\s*\)[^#]*\n[^#]*eval:5:User input directly passed to eval"
    "PRINTF_FORMAT:%s.*%s.*%s.*%s.*%s:2:Possible format string vulnerability"
    "DESERIALIZE_JSON:json\.loads\s*\(request:3:Deserializing user input with json.loads"
)

# File extensions to scan by language
PY_EXTENSIONS="*.py"
JS_EXTENSIONS="*.js"
TS_EXTENSIONS="*.ts"
JAVA_EXTENSIONS="*.java"
GO_EXTENSIONS="*.go"
RB_EXTENSIONS="*.rb"

# Scan for Python patterns
scan_python() {
    local pattern_name="$1"
    local regex="$2"
    local confidence="$3"
    local description="$4"
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local file match
            file=$(echo "$line" | cut -d: -f1)
            match=$(echo "$line" | cut -d: -f2- | sed 's/^[[:space:]]*//' | head -c 100)
            
            # Skip test files and examples
            if [[ "$file" =~ test|example|sample|demo ]]; then
                continue
            fi
            
            findings+=("{\"id\":$finding_id,\"type\":\"$pattern_name\",\"file\":\"$file\",\"pattern\":\"${match//\"/\\\"}\",\"confidence\":$confidence,\"description\":\"$description\",\"language\":\"python\"}")
            ((finding_id++))
        fi
    done < <(grep -rn --include="*.py" -E "$regex" "$TARGET_DIR" 2>/dev/null | head -100 || true)
}

# Scan for JavaScript/TypeScript patterns
scan_javascript() {
    local pattern_name="$1"
    local regex="$2"
    local confidence="$3"
    local description="$4"
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local file match
            file=$(echo "$line" | cut -d: -f1)
            match=$(echo "$line" | cut -d: -f2- | sed 's/^[[:space:]]*//' | head -c 100)
            
            # Skip test files and examples
            if [[ "$file" =~ test|example|sample|demo|spec ]]; then
                continue
            fi
            
            findings+=("{\"id\":$finding_id,\"type\":\"$pattern_name\",\"file\":\"$file\",\"pattern\":\"${match//\"/\\\"}\",\"confidence\":$confidence,\"description\":\"$description\",\"language\":\"javascript\"}")
            ((finding_id++))
        fi
    done < <(grep -rn --include="*.js" --include="*.ts" -E "$regex" "$TARGET_DIR" 2>/dev/null | head -100 || true)
}

# Scan for eval/exec in Python
while IFS=: read -r name regex conf desc; do
    [[ -z "$name" ]] && continue
    if [[ "$name" == "EVAL_USAGE" || "$name" == "EXEC_USAGE" || "$name" == "PICKLE_LOADS" || "$name" == "YAML_LOAD" || "$name" == "SHELL_TRUE" || "$name" == "OS_SYSTEM" || "$name" == "SQL_STRING_FORMAT" || "$name" == "SQL_F_STRING" || "$name" == "SQL_CONCAT" || "$name" == "WEAK_CRYPTO" || "$name" == "RANDOM_PREDICTABLE" || "$name" == "INPUT_RAW" || "$name" == "DESERIALIZE_JSON" ]]; then
        scan_python "$name" "$regex" "$conf" "$desc"
    fi
done < <(printf '%s\n' "${PATTERNS[@]}")

# Scan for eval/Function in JavaScript
scan_javascript "EVAL_USAGE" "eval\s*\(" "4" "Use of eval() can execute arbitrary code"
scan_javascript "FUNCTION_CONSTRUCTOR" "new\s+Function\s*\(" "4" "Function constructor can execute arbitrary code"
scan_javascript "INNER_HTML" "\.innerHTML\s*=" "3" "Setting innerHTML can lead to XSS"
scan_javascript "DOCUMENT_WRITE" "document\.write\s*\(" "3" "document.write() can lead to XSS"
scan_javascript "SQL_STRING_JS" "query\s*\(\s*[\"'][^\"']*(\+|\$\{)" "4" "String interpolation in SQL queries enables SQL injection"

# Scan for hardcoded credentials patterns
scan_python "HARDCODED_API_KEY" "(api_key|apikey|API_KEY)\s*=\s*[\"'][a-zA-Z0-9]{16,}[\"']" "4" "Hardcoded API key detected"
scan_python "HARDCODED_TOKEN" "(token|TOKEN|auth_token)\s*=\s*[\"'][a-zA-Z0-9_-]{20,}[\"']" "4" "Hardcoded authentication token detected"

scan_javascript "HARDCODED_API_KEY" "(api_key|apikey|API_KEY)\s*:\s*[\"'][a-zA-Z0-9]{16,}[\"']" "4" "Hardcoded API key detected"
scan_javascript "HARDCODED_TOKEN" "(token|TOKEN|auth_token)\s*:\s*[\"'][a-zA-Z0-9_-]{20,}[\"']" "4" "Hardcoded authentication token detected"

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

echo "Scan complete. Found $finding_id dangerous code patterns."
echo "Results saved to: $FINDINGS_FILE"
