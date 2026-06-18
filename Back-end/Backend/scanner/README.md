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

Light scan runs the core useful checks: alive probing, security headers, URL/form extraction,
sensitive file checks, targeted checks, form checks, and WebSocket checks.

```powershell
cd D:\
python -m scanner.cli --target http://127.0.0.1:8081 --mode light
```

Deep scan includes the light checks and also enables bounded content discovery,
limited port scanning, hidden parameter discovery, historical URL discovery,
and CRLF checks by default when the required tools are available.

```powershell
cd D:\
python -m scanner.cli --target http://127.0.0.1:8081 --mode deep
```

For a longer authorized deep run, raise the request cap:

```powershell
cd D:\
python -m scanner.cli --target http://127.0.0.1:8081 --mode deep --max-requests 20000
```

You can still turn those heavier deep defaults off:

```powershell
cd D:\
python -m scanner.cli --target http://127.0.0.1:8081 --mode deep --disable-fuzz --disable-ports --disable-crlfuzz
```

Nuclei remains explicitly opt-in:

```powershell
cd D:\
python -m scanner.cli --target http://127.0.0.1:8081 --mode deep --enable-nuclei
```

For explicitly authorized public app-route checks, use the bounded app profile:

```powershell
cd D:\
python -m scanner.cli --target https://example.com --mode deep --confirm-permission --enable-nuclei --nuclei-profile authorized-app-v1
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

Content discovery is off in light mode and on by default in deep mode. Light mode can still enable it explicitly with `--enable-fuzz`. Fuzzing uses custom wordlists first when present, including matching files from `D:\recon\wordlists`, then fills from `common.txt` in light mode or `directory-list-2.3-medium.txt` in deep mode. The combined list is capped by the scan `max_requests` limit before handing it to external tools. The default cap is 1000 for light and 5000 for deep, and it can be changed with `--max-requests`. The runner does not use a huge raft-large-first default.

Port scanning is off in light mode and on by default in deep mode. It remains bounded rather than running full destructive or exhaustive checks, and can be disabled with `--disable-ports`.

## Push Checklist

Before pushing the private repository:

```powershell
python -m compileall D:\scanner
cd D:\
python -c "import scanner.runner; print('runner import ok')"
python -m scanner.cli --help
```

Also confirm that `provider-config.yaml`, `.env`, cookies, tokens, reports, cache files, and `*.pyc` files are not staged.
