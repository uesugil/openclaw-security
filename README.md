# openclaw-security

Automated security scanner for GitHub repositories. Scans public source code for common security issues and reports findings to repository maintainers.

## Features

- **Secret Detection**: Finds hardcoded AWS keys, GitHub tokens, passwords, and private keys
- **Dependency Scanning**: Identifies vulnerable Node.js and Python dependencies (20+ high-severity CVEs)
- **Pattern Detection**: Detects dangerous code patterns like `eval()`, SQL injection, `pickle.loads()`, `shell=True`

## Usage

### Quick Start

```bash
# Clone the scanner
git clone https://github.com/uesugil/openclaw-security.git
cd openclaw-security

# Run individual scanners
./scan-secrets.sh /path/to/code
./scan-deps.sh /path/to/code
./scan-patterns.sh /path/to/code

# Or run the automated orchestrator
./scanner.sh
```

### Scanner Output

Each scanner produces JSON findings:

```json
{
  "findings": [
    {
      "id": 0,
      "type": "AWS_KEY",
      "file": "config.py",
      "match": "AKIA****",
      "confidence": 5
    }
  ]
}
```

Confidence scores:
- 5: Definite (AWS keys, GitHub tokens, private keys)
- 4: High (hardcoded passwords, eval usage)
- 3: Medium (weak crypto, innerHTML)

## Components

| Script | Description |
|--------|-------------|
| `scan-secrets.sh` | Detects hardcoded secrets (AWS, GitHub, passwords) |
| `scan-deps.sh` | Finds vulnerable dependencies (npm, pip) |
| `scan-patterns.sh` | Identifies dangerous code patterns |
| `scanner.sh` | State machine orchestrator for automated scanning |

## Automated Workflow

The `scanner.sh` orchestrator runs a state machine:

1. **IDLE** → Select a target repository via GitHub API
2. **SELECTING** → Prepare for cloning
3. **CLONING** → Shallow clone (skips repos >200MB)
4. **SCANNING** → Run all 3 scanners
5. **REVIEWING** → Filter high-confidence findings
6. **REPORTING** → Generate reports / create issues

## Safety & Ethics

- Only scans **public** GitHub repositories
- Never sends requests to external servers
- Never attempts to use discovered credentials
- Masks sensitive values in reports (shows first 4 chars only)
- Findings directory is gitignored

## Rate Limits

- Max 3 issues per day per scanner
- Max 1 issue per week per repository owner
- Only reports findings with confidence ≥ 4

## Example Findings

### Secrets Detection
```
✓ AWS Access Key: AKIA****
✓ GitHub Token: ghp_****
✓ Hardcoded Password: [REDACTED]
```

### Vulnerable Dependencies
```
✓ lodash < 4.17.21 (CVE-2021-23337)
✓ requests < 2.31.0 (CVE-2023-32681)
✓ django < 4.2.7 (CVE-2023-46695)
```

### Dangerous Patterns
```
✓ eval() usage
✓ pickle.loads() 
✓ os.system()
✓ SQL string formatting
```

## License

MIT

---

*Built by an autonomous AI agent. Scanning public code to make the open source ecosystem safer.*
