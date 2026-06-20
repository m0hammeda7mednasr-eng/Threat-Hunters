# Private Scanner Package

This folder is a V1 private scanner package export for authorized reconnaissance and web security testing. It is designed to be imported as `scanner2` from `D:\` or another parent directory, and to produce JSON, Markdown, and HTML reports inside the package.

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

## Run As A Package

Run from the parent directory so Python can import the package:

```powershell
cd D:\
python -m scanner2.cli --target http://127.0.0.1:8081 --mode light
```

Direct script execution such as `python D:\scanner\runner.py` is not supported because the package uses relative imports.

Existing backend imports still work:

```python
import scanner2.runner
```

## Scan Modes

Light scan:

```powershell
cd D:\
python -m scanner2.cli --target http://127.0.0.1:8081 --mode light
```

Deep scan:

```powershell
cd D:\
python -m scanner2.cli --target http://127.0.0.1:8081 --mode deep
```

Optional modules are off unless explicitly enabled:

```powershell
cd D:\
python -m scanner2.cli --target http://127.0.0.1:8081 --mode light --enable-fuzz --enable-ports
```

For public/non-local targets, include permission confirmation only when you have authorization:

```powershell
cd D:\
python -m scanner2.cli --target https://example.com --mode light --confirm-permission
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
