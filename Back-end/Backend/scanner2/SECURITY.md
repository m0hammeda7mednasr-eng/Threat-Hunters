# Security Note

This scanner package is for authorized security testing only. Do not run it against public or third-party systems without explicit written permission.

This private repository vendors SQLMap under `tools/sqlmap-master` intentionally. SQLMap includes payload, stager, shell, helper, and resource files used by the tool. Those files are part of SQLMap and are kept for authorized testing workflows.

SQLMap's automatic GitHub issue-reporting token path is disabled in this vendored export so the package does not carry an upstream credential-like token.

Do not commit real API keys, cookies, bearer tokens, session values, passwords, provider credentials, scan reports, or local environment files. Use `provider-config.example.yaml` as the placeholder template and keep real `provider-config.yaml` files local.
