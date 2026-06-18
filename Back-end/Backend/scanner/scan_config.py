from __future__ import annotations

import copy
import ipaddress
import re
from urllib.parse import urljoin, urlparse, urlunparse, urldefrag


REDACTED = "<redacted>"

SENSITIVE_VALUE_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|x-api-key|token|password|passwd|pwd|secret|session|sessionid|php[_-]?sessid|private[_-]?key)"
)
SENSITIVE_EXACT_KEYS = {"cookie", "set-cookie", "authorization", "proxy-authorization"}
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
ASSIGNMENT_SECRET_RE = re.compile(
    r"(?i)\b(cookie|authorization|api[_-]?key|x-api-key|token|password|passwd|pwd|secret|sessionid|php[_-]?sessid)"
    r"\s*[:=]\s*['\"]?[^'\"\s,;]+"
)

BUILTIN_AVOID_PATHS = (
    "/logout",
    "/delete",
    "/payment",
    "/checkout/confirm",
    "/change-password",
    "/admin/delete",
)

EXTERNAL_AUTH_TYPES = {"own_target", "i_own_this_target", "explicit_permission", "permission", "explicit"}
LOCAL_AUTH_TYPES = EXTERNAL_AUTH_TYPES | {"local_lab", "lab", "local"}
NOT_SURE_AUTH_TYPES = {"", "not_sure", "unsure", "unknown", "none"}
EXTERNAL_TOOL_AUTH_PROFILES = {"benchmark", "lab-only", "aggressive-lab-only", "deep"}

PROFILE_ALIASES = {
    "aggressive lab-only": "aggressive-lab-only",
    "aggressive_lab_only": "aggressive-lab-only",
    "lab_only": "lab-only",
    "high_recall_safe": "high-recall-safe",
    "high recall safe": "high-recall-safe",
}


class ScanConfigError(ValueError):
    pass


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        return [line.strip() for line in value.splitlines() if line.strip()]
    return [value]


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on", "confirmed"}
    return bool(value)


def _normalize_auth_type(value: str | None) -> str:
    auth_type = str(value or "").strip().lower()
    auth_type = auth_type.replace("-", "_").replace(" ", "_")
    return auth_type


def _normalize_profile(value: str | None) -> str:
    profile = str(value or "light").strip().lower()
    return PROFILE_ALIASES.get(profile, profile or "light")


def _clean_header_name(name: str) -> str:
    cleaned = str(name or "").strip()
    if not cleaned or "\r" in cleaned or "\n" in cleaned or ":" in cleaned:
        return ""
    if not re.match(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$", cleaned):
        return ""
    return cleaned


def _coerce_headers(raw_headers) -> dict:
    headers: dict[str, str] = {}
    if isinstance(raw_headers, dict):
        iterator = raw_headers.items()
    elif isinstance(raw_headers, str):
        pairs = []
        for line in raw_headers.splitlines():
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            pairs.append((name, value))
        iterator = pairs
    else:
        iterator = []

    for name, value in iterator:
        clean_name = _clean_header_name(name)
        if not clean_name:
            continue
        headers[clean_name] = str(value or "").strip()
    return headers


def _target_hostname(target: str | None, fallback_domain: str = "") -> str:
    raw = str(target or fallback_domain or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    return (parsed.hostname or parsed.path or "").strip("[]").lower()


def _is_local_hostname(hostname: str) -> bool:
    hostname = (hostname or "").lower()
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return True
    if hostname.endswith(".localhost") or hostname.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False




def is_local_target_identifier(value: str | None) -> bool:
    return _is_local_hostname(_target_hostname(value, str(value or "")))


def _target_origin(target: str | None, domain: str) -> str:
    raw = str(target or "").strip()
    if raw:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        if parsed.hostname:
            scheme = parsed.scheme if parsed.scheme in {"http", "https"} else "https"
            netloc = parsed.netloc or parsed.hostname
            return f"{scheme}://{netloc}"
    return f"https://{domain}"


def redact_text(value) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = BEARER_RE.sub("Bearer <redacted>", text)
    text = JWT_RE.sub("<redacted-jwt>", text)
    text = ASSIGNMENT_SECRET_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    return text


def _is_sensitive_key(key: str) -> bool:
    key_text = str(key or "").strip().lower()
    if key_text in SENSITIVE_EXACT_KEYS:
        return True
    return bool(SENSITIVE_VALUE_KEY_RE.search(key_text))


def redact_mapping(value):
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                redacted[key_text] = REDACTED if item not in (None, "") else ""
            else:
                redacted[key_text] = redact_mapping(item)
        return redacted
    if isinstance(value, list):
        return [redact_mapping(item) for item in value]
    if isinstance(value, tuple):
        return [redact_mapping(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _normalize_avoid_paths(paths) -> list[str]:
    seen = set()
    normalized = []
    for item in [*BUILTIN_AVOID_PATHS, *_as_list(paths)]:
        path = str(item or "").strip()
        if not path:
            continue
        if not path.startswith("/"):
            path = "/" + path
        path = path.split("?", 1)[0].split("#", 1)[0].rstrip("/") or "/"
        key = path.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(path)
    return normalized


def _path_is_avoided(path: str, avoid_paths: list[str]) -> bool:
    normalized_path = (path or "/").split("?", 1)[0].rstrip("/") or "/"
    lower_path = normalized_path.lower()
    for avoid in avoid_paths:
        lower_avoid = avoid.lower().rstrip("/") or "/"
        if lower_path == lower_avoid or lower_path.startswith(lower_avoid + "/"):
            return True
    return False


def _normalize_seed_url(seed: str, origin: str) -> str:
    raw = str(seed or "").strip()
    if not raw:
        return ""
    absolute = raw if re.match(r"^https?://", raw, re.I) else urljoin(origin.rstrip("/") + "/", raw)
    absolute, _fragment = urldefrag(absolute)
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    return urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))


def normalize_seed_urls(seed_urls, *, target: str | None, domain: str, avoid_paths: list[str]) -> tuple[list[str], list[dict]]:
    origin = _target_origin(target, domain)
    seen = set()
    accepted = []
    filtered = []
    for seed in _as_list(seed_urls):
        normalized = _normalize_seed_url(str(seed), origin)
        if not normalized:
            continue
        parsed = urlparse(normalized)
        if _path_is_avoided(parsed.path or "/", avoid_paths):
            filtered.append({"url": normalized, "reason": "avoid_path"})
            continue
        key = normalized.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        accepted.append(normalized)
    return accepted, filtered


def _normalize_limits(raw_limits) -> dict:
    raw_limits = raw_limits if isinstance(raw_limits, dict) else {}

    def int_between(name: str, default: int, low: int, high: int) -> int:
        try:
            value = int(raw_limits.get(name, default))
        except (TypeError, ValueError):
            value = default
        return max(low, min(value, high))

    return {
        "max_requests": int_between("max_requests", 500, 1, 50000),
        "concurrency": int_between("concurrency", 3, 1, 50),
        "delay_ms": int_between("delay_ms", 500, 0, 60000),
        "timeout_seconds": int_between("timeout_seconds", 10, 1, 300),
        "stop_on_many_403": _as_bool(raw_limits.get("stop_on_many_403", True)),
        "stop_on_many_429": _as_bool(raw_limits.get("stop_on_many_429", True)),
        "stop_on_many_500": _as_bool(raw_limits.get("stop_on_many_500", True)),
    }


def sanitize_scan_config_for_storage(scan_config: dict | None) -> dict:
    safe = redact_mapping(copy.deepcopy(scan_config or {}))
    if isinstance(safe, dict):
        safe.pop("runtime_headers", None)
        safe.pop("_runtime_headers", None)
        safe.pop("raw_headers", None)
    return safe if isinstance(safe, dict) else {}


def get_runtime_request_headers(scan_config: dict | None, base_headers: dict | None = None) -> dict:
    headers = _coerce_headers(base_headers or {})
    if not isinstance(scan_config, dict):
        return headers
    runtime_headers = _coerce_headers(scan_config.get("runtime_headers") or scan_config.get("_runtime_headers") or {})
    if runtime_headers:
        headers.update(runtime_headers)
    return headers


def external_tool_auth_policy(scan_config: dict | None) -> dict:
    scan_config = scan_config if isinstance(scan_config, dict) else {}
    requested_value = scan_config.get("external_tool_auth_requested", scan_config.get("external_tool_auth_allowed", False))
    requested = _as_bool(requested_value)
    target_is_local = _as_bool(scan_config.get("target_is_local"))
    authorization_confirmed = _as_bool(scan_config.get("authorization_confirmed"))
    profile = _normalize_profile(scan_config.get("profile"))

    if not requested:
        return {"allowed": False, "reason": "disabled_by_policy"}
    if not target_is_local:
        return {"allowed": False, "reason": "non_local_target"}
    if not authorization_confirmed:
        return {"allowed": False, "reason": "authorization_not_confirmed"}
    if profile not in EXTERNAL_TOOL_AUTH_PROFILES:
        return {"allowed": False, "reason": "profile_not_lab_or_benchmark"}
    return {"allowed": True, "reason": "allowed_local_lab"}


def prepare_scan_config(req: dict, *, domain: str, default_profile: str = "light") -> dict:
    raw_config = req.get("scan_config") if isinstance(req.get("scan_config"), dict) else {}
    target = str(raw_config.get("target") or req.get("domain") or domain or "").strip()
    auth_type = _normalize_auth_type(
        raw_config.get("authorization_type")
        or raw_config.get("authorization")
        or req.get("authorization_type")
    )
    authorization_confirmed = _as_bool(raw_config.get("authorization_confirmed"))

    if auth_type in NOT_SURE_AUTH_TYPES:
        authorization_confirmed = False
    if not authorization_confirmed:
        raise ScanConfigError("Authorization confirmation is required before active scanning.")

    hostname = _target_hostname(target, domain)
    is_local = _is_local_hostname(hostname)
    if is_local:
        allowed = auth_type in LOCAL_AUTH_TYPES
    else:
        allowed = auth_type in EXTERNAL_AUTH_TYPES
    if not allowed:
        raise ScanConfigError(
            "External targets require explicit ownership or permission. Local-lab authorization is only valid for local/private targets."
        )

    profile = _normalize_profile(raw_config.get("profile") or req.get("profile") or default_profile)
    headers = _coerce_headers(raw_config.get("headers", {}))
    avoid_paths = _normalize_avoid_paths(raw_config.get("avoid_paths", []))
    seed_urls, filtered_seed_urls = normalize_seed_urls(
        raw_config.get("seed_urls", []),
        target=target,
        domain=domain,
        avoid_paths=avoid_paths,
    )
    limits = _normalize_limits(raw_config.get("limits", {}))
    external_tool_auth_requested = _as_bool(raw_config.get("external_tool_auth_allowed", False))
    external_tool_auth_allowed = bool(
        external_tool_auth_requested
        and is_local
        and authorization_confirmed
        and profile in EXTERNAL_TOOL_AUTH_PROFILES
    )
    nuclei_profile = str(
        raw_config.get("nuclei_profile")
        or raw_config.get("nuclei_template_profile")
        or "public-safe-v1"
    ).strip().lower()
    if nuclei_profile not in {"public-safe-v1", "lab-app-v1", "authorized-app-v1"}:
        nuclei_profile = "public-safe-v1"
    lab_mode = bool(is_local and auth_type in LOCAL_AUTH_TYPES)

    redacted_config = {
        "target": target,
        "authorization_confirmed": True,
        "authorization_type": auth_type,
        "target_is_local": is_local,
        "lab_mode": lab_mode,
        "profile": profile,
        "nuclei_profile": nuclei_profile,
        "authenticated": _as_bool(raw_config.get("authenticated", bool(headers))),
        "auth_mode": str(raw_config.get("auth_mode") or ("manual_headers" if headers else "none")),
        "external_tool_auth_allowed": external_tool_auth_allowed,
        "external_tool_auth_requested": external_tool_auth_requested,
        "headers": redact_mapping(headers),
        "seed_urls": seed_urls,
        "filtered_seed_urls": filtered_seed_urls,
        "workflows": redact_mapping(raw_config.get("workflows", [])),
        "priority_forms": [str(item).strip() for item in _as_list(raw_config.get("priority_forms", [])) if str(item).strip()],
        "avoid_paths": avoid_paths,
        "priority_vuln_types": [str(item).strip() for item in _as_list(raw_config.get("priority_vuln_types", [])) if str(item).strip()],
        "limits": limits,
        "secrets_handling": {
            "raw_auth_headers_runtime_only": True,
            "serialized_headers_redacted": True,
            "external_tool_auth_allowed": external_tool_auth_allowed,
            "external_tool_auth_default_allowed": False,
        },
    }

    runtime_config = copy.deepcopy(redacted_config)
    runtime_config["runtime_headers"] = headers
    runtime_config["headers"] = redact_mapping(headers)

    return {
        "redacted": sanitize_scan_config_for_storage(redacted_config),
        "runtime": runtime_config,
    }


def _host_for_url(url: str) -> str:
    parsed = urlparse(url if "://" in str(url) else f"http://{url}")
    return (parsed.hostname or "").lower()


def _seed_matches_host(seed_url: str, host: dict) -> bool:
    seed_host = _host_for_url(seed_url)
    host_url = str(host.get("url") or "")
    host_host = _host_for_url(host_url)
    host_subdomain = str(host.get("subdomain") or "").lower()
    if not seed_host:
        return False
    if seed_host in {host_host, host_subdomain}:
        return True
    return bool(host_host and (seed_host.endswith("." + host_host) or host_host.endswith("." + seed_host)))


def _merge_unique(existing, additions) -> list:
    merged = []
    seen = set()
    for item in [*_as_list(existing), *_as_list(additions)]:
        text = str(item or "").strip()
        if not text:
            continue
        key = text.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        merged.append(text)
    return merged


def _host_for_url(url: str) -> str:
    parsed = urlparse(url if "://" in str(url) else f"http://{url}")
    return (parsed.hostname or "").lower()


def _seed_matches_host(seed_url: str, host: dict) -> bool:
    seed_host = _host_for_url(seed_url)
    host_url = str(host.get("url") or "")
    host_host = _host_for_url(host_url)
    host_subdomain = str(host.get("subdomain") or "").lower()
    if not seed_host:
        return False
    if seed_host in {host_host, host_subdomain}:
        return True
    return bool(host_host and (seed_host.endswith("." + host_host) or host_host.endswith("." + seed_host)))


def _merge_unique(existing, additions) -> list:
    merged = []
    seen = set()
    for item in [*_as_list(existing), *_as_list(additions)]:
        text = str(item or "").strip()
        if not text:
            continue
        key = text.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        merged.append(text)
    return merged


def inject_seed_urls_into_hosts(alive_hosts: list, scan_config: dict | None) -> list:
    if not isinstance(alive_hosts, list):
        return alive_hosts
    seed_urls = _as_list((scan_config or {}).get("seed_urls", []))
    if not seed_urls:
        return alive_hosts
    matched_any = False
    for host in alive_hosts:
        if not isinstance(host, dict):
            continue
        host_seeds = [seed for seed in seed_urls if _seed_matches_host(seed, host)]
        if host_seeds:
            matched_any = True
            host["seed_urls"] = _merge_unique(host.get("seed_urls", []), host_seeds)
            host["extracted_urls"] = _merge_unique(host.get("extracted_urls", []), host_seeds)
    if not matched_any and seed_urls:
        unmatched = list(seed_urls)
        if alive_hosts and isinstance(alive_hosts[0], dict):
            alive_hosts[0]["seed_urls"] = _merge_unique(alive_hosts[0].get("seed_urls", []), unmatched)
            alive_hosts[0]["extracted_urls"] = _merge_unique(alive_hosts[0].get("extracted_urls", []), unmatched)
        else:
            first_seed = seed_urls[0]
            parsed = urlparse(first_seed)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            alive_hosts.append({
                "url": base_url,
                "ip": parsed.hostname,
                "subdomain": parsed.hostname,
                "title": "Seed Target",
                "status_code": 200,
                "seed_urls": unmatched,
                "extracted_urls": unmatched
            })
    return alive_hosts

