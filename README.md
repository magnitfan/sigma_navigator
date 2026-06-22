### Requirements

```text
- Python 3.10+
- PyYAML (pip install pyyaml)
```

---

### 1. Sigma Navigator Generator (`sigma_navigator.py`)
Generates a MITRE ATT&CK Navigator layer based on Sigma rules coverage.

#### Usage

```bash
python sigma_navigator.py -r /path/to/sigma/rules -o output_filename.json

# Custom layer name
python sigma_navigator.py -r /path/to/rules -o navigator_layer.json -n "My Sigma Coverage"
```

#### Arguments

```text
-r, --repo-path PATH    Local Sigma repo path (required)
-o, --output PATH       Output Navigation layer file name and path
-n, --name NAME         Navigator layer name
-v, --verbose           Verbose (log output)
```

---

### 2. MITRE v19 Compatibility Linter (`sigma_v19_linter.py`)
Checks Sigma rules for outdated MITRE ATT&CK tactics and techniques (e.g., deprecated Defense Evasion). Exits with code `1` if issues are found, making it suitable for CI/CD pipelines.

#### Usage

```bash
python sigma_v19_linter.py -r /path/to/sigma/rules -o output_filename.txt
```

#### Arguments

```text
-r, --repo-path PATH    Local Sigma repo path (required)
-o, --output PATH       Output Navigation layer file name and path
```