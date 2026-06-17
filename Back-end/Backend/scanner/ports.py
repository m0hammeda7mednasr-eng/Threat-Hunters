from __future__ import annotations

import asyncio
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from .findings import Finding, merge_findings
from .scanner_types import EvidenceItem, utc_now
from .utils import check_tool, get_tool_path, log


MODULE_NAME = "ports"
DEFAULT_TOP_PORTS = 1000
DEEP_PORT_COUNT = 2000

REFERENCES = [
    "https://owasp.org/www-project-web-security-testing-guide/",
    "https://www.cisa.gov/resources-tools/resources/known-exploited-vulnerabilities-catalog",
    "https://www.cisecurity.org/controls/cis-controls-list",
]

COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

HIGH_RISK_PORTS = {
    21: ("ftp", "FTP service exposed on the network.", "medium"),
    23: ("telnet", "Telnet service exposes an insecure cleartext remote shell protocol.", "high"),
    445: ("smb", "SMB service is exposed on the network.", "medium"),
    1433: ("mssql", "Microsoft SQL Server is exposed on the network.", "high"),
    1521: ("oracle", "Oracle database service is exposed on the network.", "high"),
    2049: ("nfs", "NFS service is exposed on the network.", "medium"),
    3306: ("mysql", "MySQL service is exposed on the network.", "high"),
    3389: ("rdp", "RDP service is exposed on the network.", "high"),
    5432: ("postgresql", "PostgreSQL service is exposed on the network.", "high"),
    5900: ("vnc", "VNC service is exposed on the network.", "high"),
    6379: ("redis", "Redis service is exposed on the network.", "high"),
    9200: ("elasticsearch", "Elasticsearch service is exposed on the network.", "high"),
    11211: ("memcached", "Memcached service is exposed on the network.", "high"),
    27017: ("mongodb", "MongoDB service is exposed on the network.", "high"),
}

ADMIN_SERVICE_MARKERS = [
    "admin",
    "jenkins",
    "tomcat",
    "grafana",
    "kibana",
    "webmin",
    "phpmyadmin",
    "adminer",
    "management",
    "console",
]


@dataclass(slots=True)
class PortService:
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: str = "unknown"
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    source_tool: str = "unknown"

    def display(self) -> str:
        details = " ".join(item for item in [self.service_name, self.product, self.version, self.extrainfo] if item).strip()
        return f"{self.port}/{self.protocol}: {details or 'unknown'}"

    def service_summary(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service_name": self.service_name,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "source_tool": self.source_tool,
        }


def _safe_port(value) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _parse_naabu_output(output: str) -> list[int]:
    ports: list[int] = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        candidates = []
        if line.isdigit():
            candidates.append(line)
        candidates.extend(re.findall(r":(\d{1,5})(?=\D|$)", line))
        for candidate in candidates:
            port = _safe_port(candidate)
            if port is not None:
                ports.append(port)
    return sorted(set(ports))


def _parse_nmap_xml(output: str, host: str, source_tool: str = "nmap") -> list[PortService]:
    text = (output or "").strip()
    if not text.startswith("<"):
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []

    services: list[PortService] = []
    for host_node in root.findall(".//host"):
        address = host
        address_node = host_node.find("address")
        if address_node is not None and address_node.attrib.get("addr"):
            address = host or address_node.attrib["addr"]
        for port_node in host_node.findall(".//port"):
            state_node = port_node.find("state")
            state = state_node.attrib.get("state", "") if state_node is not None else ""
            if state != "open":
                continue
            port = _safe_port(port_node.attrib.get("portid"))
            if port is None:
                continue
            service_node = port_node.find("service")
            service_name = "unknown"
            product = ""
            version = ""
            extrainfo = ""
            if service_node is not None:
                service_name = service_node.attrib.get("name") or "unknown"
                product = service_node.attrib.get("product") or ""
                version = service_node.attrib.get("version") or ""
                extrainfo = service_node.attrib.get("extrainfo") or ""
                tunnel = service_node.attrib.get("tunnel") or ""
                if tunnel == "ssl" and service_name == "http":
                    service_name = "https"
            services.append(PortService(
                host=address,
                port=port,
                protocol=port_node.attrib.get("protocol") or "tcp",
                state=state,
                service_name=service_name,
                product=product,
                version=version,
                extrainfo=extrainfo,
                source_tool=source_tool,
            ))
    return sorted(services, key=lambda item: (item.host, item.port, item.protocol))


def _parse_nmap_text(output: str, host: str, source_tool: str = "nmap") -> list[PortService]:
    services: list[PortService] = []
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if "/tcp" not in line and "/udp" not in line:
            continue
        if " open " not in f" {line} ":
            continue
        parts = re.split(r"\s+", line, maxsplit=4)
        if len(parts) < 3:
            continue
        port_proto = parts[0].split("/", 1)
        if len(port_proto) != 2:
            continue
        port = _safe_port(port_proto[0])
        if port is None:
            continue
        product_version = parts[3] if len(parts) > 3 else ""
        services.append(PortService(
            host=host,
            port=port,
            protocol=port_proto[1],
            state=parts[1],
            service_name=parts[2],
            product=product_version,
            source_tool=source_tool,
        ))
    return sorted(services, key=lambda item: (item.host, item.port, item.protocol))


def _parse_nmap_output(output: str, host: str, source_tool: str = "nmap") -> list[PortService]:
    return _parse_nmap_xml(output, host, source_tool=source_tool) or _parse_nmap_text(output, host, source_tool=source_tool)


def _services_from_ports(host: str, ports: list[int], source_tool: str = "naabu") -> list[PortService]:
    services = []
    for port in sorted(set(ports)):
        services.append(PortService(
            host=host,
            port=port,
            protocol="tcp",
            state="open",
            service_name=COMMON_SERVICES.get(port, "unknown"),
            source_tool=source_tool,
        ))
    return services


async def _run_naabu(host: str, profile: str = "light") -> list[int]:
    top_ports = DEEP_PORT_COUNT if profile == "deep" else DEFAULT_TOP_PORTS
    ports_flag = ["-top-ports", str(top_ports)]
    cmd = [
        get_tool_path("naabu"),
        "-host", host,
        *ports_flag,
        "-silent",
        "-rate", "300",
        "-scan-type", "c",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
        err_output = stderr.decode(errors="replace")
        if err_output.strip():
            log.debug(f"[ports] naabu stderr for {host}: {err_output[:300]}")
        return _parse_naabu_output(stdout.decode(errors="replace"))
    except asyncio.TimeoutError:
        log.warning(f"[ports] naabu timed out for {host}")
        return []
    except Exception as exc:
        log.error(f"[ports] naabu error for {host}: {exc}")
        return []


async def _run_nmap_direct(host: str, profile: str = "light") -> list[PortService]:
    top_ports = DEEP_PORT_COUNT if profile == "deep" else DEFAULT_TOP_PORTS
    port_args = ["--top-ports", str(top_ports)]
    cmd = [
        get_tool_path("nmap"),
        "-sT",
        "-sV",
        "-T3",
        "-Pn",
        "--open",
        *port_args,
        "-oX",
        "-",
        host,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        err_output = stderr.decode(errors="replace")
        if err_output.strip():
            log.debug(f"[ports] nmap stderr for {host}: {err_output[:300]}")
        return _parse_nmap_output(stdout.decode(errors="replace"), host, source_tool="nmap")
    except asyncio.TimeoutError:
        log.warning(f"[ports] nmap direct scan timed out for {host}")
        return []
    except Exception as exc:
        log.error(f"[ports] nmap direct scan error for {host}: {exc}")
        return []


async def _run_nmap_service(host: str, ports: list[int]) -> list[PortService]:
    clean_ports = sorted({port for port in ports if _safe_port(port) is not None})
    if not clean_ports:
        return []
    port_str = ",".join(map(str, clean_ports))
    cmd = [
        get_tool_path("nmap"),
        "-sV",
        "-Pn",
        "-p",
        port_str,
        "-oX",
        "-",
        host,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        err_output = stderr.decode(errors="replace")
        if err_output.strip():
            log.debug(f"[ports] nmap service stderr for {host}: {err_output[:300]}")
        services = _parse_nmap_output(stdout.decode(errors="replace"), host, source_tool="nmap")
        if services:
            return services
        return _services_from_ports(host, clean_ports, source_tool="naabu")
    except asyncio.TimeoutError:
        log.warning(f"[ports] nmap service scan timed out for {host}")
        return _services_from_ports(host, clean_ports, source_tool="naabu")
    except Exception as exc:
        log.error(f"[ports] nmap service scan error for {host}: {exc}")
        return _services_from_ports(host, clean_ports, source_tool="naabu")


def _service_text(service: PortService) -> str:
    return " ".join(
        str(item).lower()
        for item in [service.service_name, service.product, service.version, service.extrainfo]
        if item
    )


def _is_admin_candidate(service: PortService) -> bool:
    if service.port not in {8080, 8443, 8000, 8008, 8888, 9000, 9443}:
        return False
    text = _service_text(service)
    return any(marker in text for marker in ADMIN_SERVICE_MARKERS)


def _classification_for_service(service: PortService) -> dict:
    text = _service_text(service)
    service_name = (service.service_name or "").lower()

    if service.port == 23 and ("telnet" in service_name or "telnet" in text):
        return {
            "vuln_type": "risky_service_exposed",
            "status": "candidate",
            "severity": "high",
            "confidence": 0.72,
            "category": "service_exposure",
            "reason": "Telnet service was identified on an open port. This is a high-risk exposure candidate, not a confirmed exploit.",
        }

    if service.port in HIGH_RISK_PORTS:
        label, reason, severity = HIGH_RISK_PORTS[service.port]
        confidence = 0.68 if label in text or service.service_name != "unknown" else 0.55
        return {
            "vuln_type": "risky_service_exposed",
            "status": "candidate",
            "severity": severity,
            "confidence": confidence,
            "category": "service_exposure",
            "reason": reason,
        }

    if _is_admin_candidate(service):
        return {
            "vuln_type": "risky_service_exposed",
            "status": "candidate",
            "severity": "medium",
            "confidence": 0.58,
            "category": "service_exposure",
            "reason": "Admin-looking service marker was observed on a common management port.",
        }

    return {
        "vuln_type": "service_detected" if service.service_name != "unknown" else "open_port",
        "status": "recon",
        "severity": "info",
        "confidence": 0.35 if service.service_name != "unknown" else 0.25,
        "category": "network_recon",
        "reason": "Open service observed. Open ports are recon by default, not vulnerabilities.",
    }


def _response_summary_for_service(service: PortService) -> dict:
    evidence = _evidence_text(service, _classification_for_service(service))
    return {
        "status_code": None,
        "headers": {},
        "body_hash": "",
        "snippet": evidence[:500],
        "elapsed_ms": None,
        "content_type": "network-service",
        "timestamp": utc_now(),
        "service": service.service_summary(),
    }


def _evidence_text(service: PortService, classification: dict) -> str:
    detail = service.display()
    product_text = " ".join(item for item in [service.product, service.version, service.extrainfo] if item).strip()
    extra = f" Product/version: {product_text}." if product_text else ""
    return (
        f"{service.host}:{service.port}/{service.protocol} is open. "
        f"Service evidence: {detail}.{extra} Source tool: {service.source_tool}. "
        f"Reason: {classification['reason']}"
    )


def _remediation(classification: dict) -> str:
    status = classification["status"]
    vuln_type = classification["vuln_type"]
    if status == "recon":
        return "Validate that the exposed service is expected, patched, and protected by appropriate network controls."
    return "Restrict the service to trusted networks, require strong authentication, and verify version exposure with a dedicated safe vulnerability check."


def _make_finding(service: PortService) -> dict:
    classification = _classification_for_service(service)
    evidence_text = _evidence_text(service, classification)
    reproduction_steps = [
        f"Review authorized scan evidence for {service.host}:{service.port}/{service.protocol}.",
        "Confirm whether this service is intentionally exposed on the tested interface.",
        "Use a dedicated safe service/version validation module before making any CVE claim.",
    ]
    return Finding(
        id=classification["vuln_type"],
        scanner_name=MODULE_NAME,
        module_name=MODULE_NAME,
        url=f"{service.host}:{service.port}",
        target=service.host,
        parameter=str(service.port),
        method="TCP",
        category=classification["category"],
        vuln_type=classification["vuln_type"],
        status=classification["status"],
        severity=classification["severity"],
        confidence=classification["confidence"],
        evidence=evidence_text,
        evidence_items=[
            EvidenceItem(
                type="service",
                value=evidence_text,
                location=f"{service.host}:{service.port}/{service.protocol}",
                comparison=classification["reason"],
            )
        ],
        request_summary={},
        response_summary=_response_summary_for_service(service),
        reproduction_steps=reproduction_steps,
        remediation=_remediation(classification),
        references=REFERENCES,
        name=classification["vuln_type"].replace("_", " ").title(),
        description=evidence_text,
        matched_at=f"{service.host}:{service.port}/{service.protocol}",
        raw={
            "service": service.service_summary(),
            "classification_reason": classification["reason"],
        },
    ).to_dict()


def _new_telemetry(hosts_scanned: int, tools_available: dict) -> dict:
    return {
        "module_name": MODULE_NAME,
        "started_at": utc_now(),
        "completed_at": "",
        "hosts_scanned": hosts_scanned,
        "ports_tested": 0,
        "open_ports_found": 0,
        "tools_available": tools_available,
        "tools_used": [],
        "failures": [],
        "timeouts": 0,
        "blocked_or_rate_limited_indicators": 0,
        "scan_duration_seconds": 0.0,
        "module_noise_score": 0.0,
        "module_detection_impact": "not_calibrated",
    }


def _record_tool(telemetry: dict, tool: str) -> None:
    if tool and tool not in telemetry["tools_used"]:
        telemetry["tools_used"].append(tool)


def _finish_telemetry(telemetry: dict, started: float) -> dict:
    telemetry["scan_duration_seconds"] = round(max(0.001, time.monotonic() - started), 3)
    open_ports = max(0, int(telemetry.get("open_ports_found", 0)))
    tested = max(1, int(telemetry.get("ports_tested", 0)))
    if open_ports > 50:
        telemetry["blocked_or_rate_limited_indicators"] += 1
    telemetry["module_noise_score"] = round(min(1.0, telemetry["blocked_or_rate_limited_indicators"] / tested), 4)
    telemetry["completed_at"] = utc_now()
    return telemetry


def _dedupe_services(services: list[PortService]) -> list[PortService]:
    seen = set()
    unique = []
    for service in sorted(services, key=lambda item: (item.host, item.port, item.protocol, item.source_tool)):
        key = (service.host, service.port, service.protocol)
        if key in seen:
            continue
        seen.add(key)
        unique.append(service)
    return unique


async def scan_ports(alive_hosts: list[dict], profile: str = "light", callback=None) -> list[dict]:
    has_naabu = check_tool("naabu")
    has_nmap = check_tool("nmap")

    if not has_naabu and not has_nmap:
        log.warning("[ports] No port scanning tools available. Skipping.")
        if callback:
            await callback("ports", "warning", "No port scanner installed. Skipping.")
        return alive_hosts

    tools_available = {"naabu": has_naabu, "nmap": has_nmap}
    scan_started = time.monotonic()
    scan_telemetry = _new_telemetry(len(alive_hosts), tools_available)

    log.info(f"[ports] Scanning active. (Naabu: {has_naabu}, Nmap: {has_nmap})")
    if callback:
        await callback("ports", "running", f"Scanning {len(alive_hosts)} hosts")

    semaphore = asyncio.Semaphore(5)
    ports_per_host = DEEP_PORT_COUNT if profile == "deep" else DEFAULT_TOP_PORTS

    async def _scan_one(host_info: dict):
        async with semaphore:
            subdomain = host_info["subdomain"]
            is_cdn = host_info.get("is_cdn", False)
            host_telemetry = _new_telemetry(1, tools_available)
            started = time.monotonic()

            if is_cdn:
                log.info(f"[ports] {subdomain} is behind CDN/WAF. Recording normal web ports only.")
                services = [
                    PortService(host=subdomain, port=80, service_name="http", source_tool="cdn-default"),
                    PortService(host=subdomain, port=443, service_name="https", source_tool="cdn-default"),
                ]
                host_telemetry["ports_tested"] = 2
                host_telemetry["open_ports_found"] = 2
                host_telemetry["tools_used"] = ["cdn-default"]
            elif has_naabu:
                _record_tool(host_telemetry, "naabu")
                _record_tool(scan_telemetry, "naabu")
                host_telemetry["ports_tested"] += ports_per_host
                scan_telemetry["ports_tested"] += ports_per_host
                discovered_ports = await _run_naabu(subdomain, profile=profile)
                if len(discovered_ports) > 50:
                    message = f"{subdomain} returned {len(discovered_ports)} open ports; possible tarpitting or WAF behavior."
                    log.warning(f"[ports] {message}")
                    host_telemetry["blocked_or_rate_limited_indicators"] += 1
                    host_telemetry["failures"].append(message)
                    services = []
                elif has_nmap and discovered_ports:
                    _record_tool(host_telemetry, "nmap")
                    _record_tool(scan_telemetry, "nmap")
                    host_telemetry["ports_tested"] += len(discovered_ports)
                    scan_telemetry["ports_tested"] += len(discovered_ports)
                    services = await _run_nmap_service(subdomain, discovered_ports)
                    if not services:
                        services = _services_from_ports(subdomain, discovered_ports, source_tool="naabu")
                else:
                    services = _services_from_ports(subdomain, discovered_ports, source_tool="naabu")
            else:
                _record_tool(host_telemetry, "nmap")
                _record_tool(scan_telemetry, "nmap")
                host_telemetry["ports_tested"] += ports_per_host
                scan_telemetry["ports_tested"] += ports_per_host
                services = await _run_nmap_direct(subdomain, profile=profile)
                if len(services) > 50:
                    message = f"{subdomain} returned {len(services)} open services; possible tarpitting or WAF behavior."
                    log.warning(f"[ports] {message}")
                    host_telemetry["blocked_or_rate_limited_indicators"] += 1
                    host_telemetry["failures"].append(message)
                    services = []

            services = _dedupe_services(services)
            host_telemetry["open_ports_found"] = len(services)
            scan_telemetry["open_ports_found"] += len(services)

            host_info["ports"] = [service.display() for service in services]
            host_info["port_services"] = [service.service_summary() for service in services]
            host_info["port_findings"] = [_make_finding(service) for service in services]
            host_info["ports_telemetry"] = _finish_telemetry(host_telemetry, started)

            promoted = [
                finding for finding in host_info["port_findings"]
                if finding.get("status") in {"candidate", "confirmed"}
            ]
            if promoted:
                host_info["vulns"] = merge_findings(host_info.get("vulns", []), promoted)

            if services:
                log.info(f"[ports] {subdomain} -> discovered {len(services)} services")

    tasks = [_scan_one(host) for host in alive_hosts]
    await asyncio.gather(*tasks, return_exceptions=True)
    scan_telemetry = _finish_telemetry(scan_telemetry, scan_started)

    for host in alive_hosts:
        host.setdefault("ports_scan_telemetry", scan_telemetry)

    total_services = sum(len(host.get("ports", [])) for host in alive_hosts)
    log.info(f"[ports] Scan complete. Found {total_services} services total.")

    if callback:
        await callback("ports", "done", f"Found {total_services} services across {len(alive_hosts)} hosts")

    return alive_hosts

