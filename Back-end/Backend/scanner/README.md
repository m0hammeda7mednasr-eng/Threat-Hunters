# Private Scanner Package

This folder is a V1 private scanner package export for authorized reconnaissance and web security testing. It is designed to be imported as `scanner` from `D:\` or another parent directory, and to produce JSON, Markdown, and HTML reports inside the package.

This is not a full production scanner. Treat it as a handoff-ready scanner core that still needs team review, environment hardening, and target authorization checks before operational use.

## Authorized Use Only

Use this scanner only on systems where you have explicit permission to test. Public or remote target scans require permission confirmation in the runtime configuration or CLI.

This private repository vendors SQLMap under `tools/sqlmap-master` for authorized security testing only. SQLMap includes exploit payload/resource files used by the tool, including payload, stager, shell, and helper resource files. Do not use this scanner or SQLMap on targets without explicit permission.

The vendored copy has SQLMap's automatic GitHub issue-reporting token path disabled so this private export does not carry an upstream credential-like token.

No real API keys, cookies, bearer tokens, passwords, or secrets should be committed. Keep local secrets in ignored local config files or environment variables.

## Install

From a terminal:

```powershell
cd D:\
python -m pip install -r D:\scanner\requirements.txt
```

Optional external tools are discovered from `PATH` or `D:\scanner\tools`:

- `sqlmap` is vendored at `D:\scanner\tools\sqlmap-master\sqlmap.py`
- `nuclei` is used only when explicitly enabled and safety gates allow it
- `nmap` or `naabu` can be used for safe limited port scanning
- `ffuf` or `gobuster` can be used for rate-limited content discovery
- `katana`, `gau`, `dalfox`, and `crlfuzz` are used by related modules when installed and enabled

## Scanner Core Requirements And Tools

### Runtime Requirements

- Python 3.10 or newer
- MongoDB connection for the full Flask backend
- Authorized target permission before running scans

### Backend Python Requirements

These are required by the backend and scanner core:

- `flask==3.0.3`
- `flask-pymongo==2.3.0`
- `flask-bcrypt==1.0.1`
- `flask-cors==4.0.0`
- `pyjwt==2.8.0`
- `email-validator==2.1.1`
- `dnspython==2.6.1`
- `python-dotenv==1.0.1`
- `httpx>=0.27.0`
- `beautifulsoup4>=4.12.0`
- `jinja2>=3.1.0`
- `markdown>=3.5.0`

### Required Scanner Core Files

- `scanner/__init__.py`
- `scanner/runner.py`
- `scanner/wordlists/common.txt`
- `scanner/wordlists/directory-list-2.3-small.txt`
- `scanner/wordlists/directory-list-2.3-medium.txt`
- `scanner/wordlists/raft-large-directories.txt`
- `scanner/wordlists/api/api-small.txt`
- `scanner/wordlists/api/debug-internal-small.txt`
- `scanner/wordlists/api/graphql-seclists.txt`
- `scanner/wordlists/api/swagger-seclists.txt`
- `scanner/tools/sqlmap-master/sqlmap.py`

### Scan Modes

- `light` scan: safe, bounded checks that work without external scanner tools.
- `deep` scan: broader coverage with additional modules enabled where authorized and available.

### Main Scanner Tools

Base/light scans can run without external scanner tools. These tools are optional and are used only when their related module is enabled or available:

1. `sqlmap`
2. `nuclei`
3. `ffuf`
4. `gobuster`
5. `katana`
6. `gau`
7. `dalfox`
8. `crlfuzz`
9. `naabu`
10. `nmap`
11. `subfinder`
12. `amass`
13. `theHarvester`
14. `gowitness`
15. `eyewitness`

### Tool Search Paths

The scanner checks these locations for external tools:

- `scanner/tools`
- `%USERPROFILE%\go\bin`
- `%USERPROFILE%\.local\bin`

### Optional Provider Environment Variables

Use placeholders only in committed example config files. Do not commit real tokens or API keys.

- `GITHUB_TOKEN`
- `VIRUSTOTAL_API_KEY`
- `CENSYS_API_ID`
- `CENSYS_API_SECRET`
- `SHODAN_API_KEY`
- `SECURITYTRAILS_API_KEY`

## Run As A Package

Run from the parent directory so Python can import the package:

```powershell
cd D:\
python -m scanner.cli --target http://127.0.0.1:8081 --mode light
```

Direct script execution such as `python D:\scanner\runner.py` is not supported because the package uses relative imports.

Existing backend imports still work:

```python
import scanner.runner
```

## Scan Modes

Light scan:

```powershell
cd D:\
python -m scanner.cli --target http://127.0.0.1:8081 --mode light
```

Deep scan:

```powershell
cd D:\
python -m scanner.cli --target http://127.0.0.1:8081 --mode deep
```

Optional modules are off unless explicitly enabled:

```powershell
cd D:\
python -m scanner.cli --target http://127.0.0.1:8081 --mode light --enable-fuzz --enable-ports
```

For public/non-local targets, include permission confirmation only when you have authorization:

```powershell
cd D:\
python -m scanner.cli --target https://example.com --mode light --confirm-permission
```

## Reports

Reports are saved inside:

```text
D:\scanner\reports
```

You can override this with:

```powershell
$env:SCANNER_REPORTS_DIR = "D:\scanner\reports"
```

Scan outputs should not be written to a drive root such as `D:\reports`.

## Provider Config

`provider-config.example.yaml` contains environment-variable placeholders only. If you need a real local provider config, copy it to:

```text
D:\scanner\provider-config.yaml
```

`provider-config.yaml` is ignored by Git and must not be committed.

## Wordlists And Safety Defaults

Content discovery is intentionally opt-in. Light mode uses `common.txt` first and can fall back to `directory-list-2.3-small.txt`. Deep mode can use `directory-list-2.3-medium.txt`. The runner does not use a huge raft-large-first default.

Port scanning is also opt-in. Light mode uses a limited top-port scan, and deep mode remains bounded rather than running full destructive or exhaustive checks.

## Push Checklist

Before pushing the private repository:

```powershell
python -m compileall D:\scanner
cd D:\
python -c "import scanner.runner; print('runner import ok')"
python -m scanner.cli --help
```

Also confirm that `provider-config.yaml`, `.env`, cookies, tokens, reports, cache files, and `*.pyc` files are not staged.
