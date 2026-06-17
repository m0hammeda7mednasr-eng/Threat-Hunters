from __future__ import annotations

import argparse
import json
import sys

from .runner import REPORTS_DIR, run_scan
from .scan_config import ScanConfigError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scanner.cli",
        description="Run the private scanner package against an authorized target.",
    )
    parser.add_argument("--target", required=True, help="Authorized target URL or host.")
    parser.add_argument("--mode", choices=("light", "deep"), default="light", help="Scan profile to run.")
    parser.add_argument("--cookie-header", default=None, help="Optional Cookie header for authorized authenticated checks.")
    parser.add_argument("--confirm-permission", action="store_true", help="Required for public/non-local targets.")
    parser.add_argument("--enable-nuclei", action="store_true", help="Enable Nuclei only where profile safety gates allow it.")
    parser.add_argument("--nuclei-profile", default="public-safe-v1", help="Nuclei template safety profile.")
    parser.add_argument("--enable-fuzz", action="store_true", help="Enable rate-limited content discovery.")
    parser.add_argument("--enable-ports", action="store_true", help="Enable safe limited port scanning.")
    parser.add_argument("--enable-crlfuzz", action="store_true", help="Enable CRLF checks.")
    parser.add_argument("--json", action="store_true", help="Print a compact JSON result.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    module_overrides = {
        "fuzz": args.enable_fuzz,
        "ports": args.enable_ports,
        "crlfuzz": args.enable_crlfuzz,
    }

    try:
        result = run_scan(
            args.target,
            scan_mode=args.mode,
            cookie_header=args.cookie_header,
            enable_nuclei=args.enable_nuclei,
            confirm_permission=args.confirm_permission,
            nuclei_profile=args.nuclei_profile,
            modules=module_overrides,
        )
    except ScanConfigError as exc:
        print(f"Scan configuration error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Scan interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if args.json:
        compact = {
            "scan_id": result.get("scan_id"),
            "report_id": result.get("report_id"),
            "target": result.get("target"),
            "profile": result.get("profile"),
            "summary": result.get("summary", {}),
            "report_files": result.get("report_files", {}),
            "module_telemetry": result.get("module_telemetry", {}),
        }
        print(json.dumps(compact, indent=2))
        return 0

    print(f"Scan complete: {result.get('scan_id')}")
    print(f"Profile: {result.get('profile')}")
    print(f"Reports directory: {REPORTS_DIR}")
    for name, path in (result.get("report_files") or {}).items():
        print(f"{name.upper()}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
