"""Command injection detection tools.

Migrated from Shannon's injection analysis knowledge base.  Covers:
  - Shell metacharacter probing (; | `` ` `` $() & || \\n)
  - Time-based blind command injection
  - Response content analysis for command output
  - Error-based detection
  - Stacked command vs argument injection distinction
"""

from __future__ import annotations

import difflib
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from langchain_core.tools import tool

from .http_client import normalize_url, request
from .results import Evidence, Finding, RequestRecord, ToolResult, error_result, response_record

# ── Command injection markers ─────────────────────────────────────────

PAYLOAD_FILE = Path(__file__).parent.parent / "payloads" / "injection.json"

CMD_OUTPUT_MARKERS = [
    # Unix command output
    ("uid=", "id command output"),
    ("gid=", "id command output"),
    ("root:", "/etc/passwd content via cmd"),
    ("/bin/bash", "shell list via cmd"),
    ("x:", "password file content"),
    ("daemon:", "user list via cmd"),
    # Directory listing
    ("total ", "ls -la output header"),
    ("drwx", "directory listing"),
    ("-rw", "file listing"),
    ("index.", "common file in directory"),
    # Windows
    ("Windows", "Windows OS identification"),
    ("[fonts]", "Windows win.ini content"),
    ("Program Files", "Windows directory listing"),
    ("Users\\", "Windows users directory"),
    # Network
    ("PING", "ping command output"),
    ("bytes from", "ping response"),
    ("ttl=", "network TTL in output"),
    ("1 packets transmitted", "ping statistics"),
    # Error patterns
    ("command not found", "shell error exposed"),
    ("not recognized", "Windows cmd error exposed"),
    ("sh:", "shell error message"),
    ("bash:", "bash error message"),
    ("Segmentation fault", "binary execution"),
]

BLIND_CMD_MARKERS = [
    # These indicate command was executed but output not reflected
    "syntax error",
    "unexpected token",
    "parse error",
    "cannot execute",
]

TIMING_THRESHOLD = 2.5  # seconds — response delay indicating sleep/ping executed

INVALID_VALUE = "myagent-cmd-invalid-control"


def _payloads(category: str = "command_injection") -> list[str]:
    with PAYLOAD_FILE.open(encoding="utf-8") as handle:
        loaded = json.load(handle)
    values = loaded.get(category, [])
    if not isinstance(values, list):
        raise ValueError(f"invalid payload config for {category}")
    return values


def _replace_param(url: str, param: str, value: str, location: str = "query", body: str = "") -> tuple[str, str | None]:
    """Replace parameter in the appropriate location. Returns (url, body_or_none)."""
    if location == "query":
        parsed = urlparse(url)
        pairs = [(k, value if k == param else v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
        if not any(k == param for k, _ in pairs):
            pairs.append((param, value))
        return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True))), None
    elif location == "body":
        pairs = parse_qsl(body, keep_blank_values=True)
        replaced = [(k, value if k == param else v) for k, v in pairs]
        if not any(k == param for k, _ in replaced):
            replaced.append((param, value))
        return url, urlencode(replaced, doseq=True)
    return url, None


def _analyze_response(text: str, elapsed: float, baseline_elapsed: float) -> tuple[int, list[str]]:
    """Score a command injection probe response."""
    score = 0
    signals: list[str] = []
    lower = text.lower()

    # Check for command output markers
    for marker, label in CMD_OUTPUT_MARKERS:
        if marker.lower() in lower:
            score += 60
            signals.append(f"command output: {label}")
            break

    # Check for blind execution markers
    for marker, label in [(m, "error exposure") for m in BLIND_CMD_MARKERS]:
        if marker in lower:
            score += 30
            signals.append(f"blind cmd: {label}")
            break

    # Timing-based detection
    if elapsed > baseline_elapsed * 3 and elapsed > TIMING_THRESHOLD:
        score += 50
        signals.append(f"timing anomaly: {elapsed:.1f}s vs baseline {baseline_elapsed:.1f}s")
    elif elapsed > baseline_elapsed * 2:
        score += 25
        signals.append(f"timing deviation: {elapsed:.1f}s vs baseline {baseline_elapsed:.1f}s")

    return score, signals


# ── Public Tools ──────────────────────────────────────────────────────


@tool
def test_command_injection(
    url: str,
    param: str,
    method: str = "GET",
    param_location: str = "query",
    body: str = "",
) -> str:
    """Verify suspected OS command injection with bounded shell-metacharacter probes.

    Each probe is compared against a baseline and invalid-control request.
    Detection methods:
      - Response content: command output (uid=, drwx, root:), error leakage
      - Timing: sleep/ping commands causing response delay > 2.5s
      - Differential: response similarity vs baseline/invalid

    Common injectable parameters are those passed to system(), exec(), popen(),
    or backtick evaluation in templates.

    Parameters:
        url: Target URL with the suspected injectable parameter.
        param: The parameter name to test.
        method: GET or POST.
        param_location: "query" (URL parameter) or "body" (form field).
        body: Form-encoded body for POST requests (e.g. "cmd=ping&host=127.0.0.1").
    """
    target = normalize_url(url)
    method_norm = method.strip().upper()
    if method_norm not in ("GET", "POST"):
        return error_result("test_command_injection", target, "only GET and POST supported").to_text()

    try:
        payloads = _payloads("command_injection")
    except Exception as exc:
        return error_result("test_command_injection", target, f"payload load error: {exc}").to_text()

    # Baseline + invalid control
    try:
        baseline_url, baseline_data = _replace_param(target, param, "normal_value", param_location, body)
        invalid_url, invalid_data = _replace_param(target, param, INVALID_VALUE, param_location, body)
        baseline_start = time.monotonic()
        baseline = request(method_norm, baseline_url, data=baseline_data, timeout=10)
        baseline_elapsed = time.monotonic() - baseline_start
        invalid = request(method_norm, invalid_url, data=invalid_data, timeout=10)
    except Exception as exc:
        return error_result("test_command_injection", target, f"baseline failed: {exc}").to_text()

    attempts: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    best: dict[str, Any] | None = None

    for payload in payloads[:6]:
        probe_url, probe_data = _replace_param(target, param, payload, param_location, body)
        try:
            start = time.monotonic()
            response = request(method_norm, probe_url, data=probe_data, timeout=10)
            elapsed = time.monotonic() - start

            score, signals = _analyze_response(response.text, elapsed, baseline_elapsed)

            # Add differential analysis
            baseline_ratio = difflib.SequenceMatcher(None, baseline.text[:4000], response.text[:4000]).ratio()
            invalid_ratio = difflib.SequenceMatcher(None, invalid.text[:4000], response.text[:4000]).ratio()
            if baseline_ratio < 0.85:
                score += 10
                signals.append("response differs from baseline")
            if invalid_ratio < 0.85:
                score += 10
                signals.append("response differs from invalid control")

            attempt = {
                "payload": payload[:120],
                "url": probe_url,
                "method": method_norm,
                "status": response.status_code,
                "length": len(response.text),
                "elapsed": round(elapsed, 3),
                "score": score,
                "signals": signals,
                "baseline_similarity": round(baseline_ratio, 3),
                "invalid_similarity": round(invalid_ratio, 3),
            }
            attempts.append(attempt)

            if best is None or score > int(best.get("score", 0)):
                best = attempt
            if score >= 80:
                break
        except Exception as exc:
            errors.append({"kind": "connection_error", "message": f"{payload[:60]}: {exc}"})

    if best is None:
        return ToolResult(
            tool="test_command_injection", target=target, status="error",
            summary="所有命令注入 payload 请求失败",
            errors=errors or [{"kind": "tool_bug", "message": "no probes sent"}],
            raw_excerpt=f"[test_command_injection] {target}\nAll probes failed.",
            request=RequestRecord(method_norm, target, parameters={"param": param}),
            response=response_record(baseline),
            data={"baseline": response_record(baseline).__dict__, "invalid": response_record(invalid).__dict__},
        ).to_text()

    # ── Resolve confidence ─────────────────────────────────────────
    best_score = int(best["score"])
    best_signals = list(best["signals"])
    has_cmd_output = any(s.startswith("command output:") for s in best_signals)
    has_timing = any("timing anomaly" in s for s in best_signals)

    if best_score >= 80 and (has_cmd_output or has_timing):
        confidence = "confirmed"
    elif best_score >= 40:
        confidence = "likely"
    elif best_score > 0:
        confidence = "weak"
    else:
        confidence = "unconfirmed"

    # ── Format output ─────────────────────────────────────────────
    lines = [
        f"[test_command_injection] {target}",
        f"Parameter: {param} | Method: {method_norm} | Location: {param_location}",
        f"Baseline: {baseline.status_code} {len(baseline.text)} chars, {baseline_elapsed:.2f}s",
        f"Invalid:   {invalid.status_code} {len(invalid.text)} chars",
        f"Best payload: {best['payload']}",
        f"Signals: {'; '.join(best_signals) or '(none)'}",
        f"Score: {best_score} → {confidence}",
    ]

    readable = "\n".join(lines)
    evidence = Evidence(
        "command_injection_probe",
        "; ".join(best_signals) or "No material signal.",
        str(best["url"]),
        {"payload": best["payload"], "score": best_score, "elapsed": best["elapsed"]},
    )

    finding = Finding(
        title="命令注入 (Command Injection) 验证结果",
        severity="critical" if confidence == "confirmed" else "high",
        confidence=confidence,
        category="command_injection",
        evidence=[evidence],
        reproduction=[
            f"发送 {method_norm} {best['url']}",
            f"参数 {param} 携带 shell 元字符 payload: {best['payload']}",
            "与 baseline/无效对照请求比较响应内容与时序差异",
        ],
    )

    return ToolResult(
        tool="test_command_injection",
        target=target,
        status="ok",
        summary=f"命令注入 验证结论：{confidence}",
        raw_excerpt=readable,
        findings=[finding],
        errors=errors,
        request=RequestRecord(method_norm, target, parameters={"param": param}, payload=str(best["payload"])),
        response=response_record(baseline),
        data={
            "baseline": response_record(baseline).__dict__,
            "invalid": response_record(invalid).__dict__,
            "best": best,
            "attempts": attempts,
        },
    ).to_text()


@tool
def test_ssti(
    url: str,
    param: str,
    method: str = "GET",
    param_location: str = "query",
    body: str = "",
    template_engine: str = "auto",
) -> str:
    """Test for Server-Side Template Injection (SSTI).

    Sends mathematical expression payloads ({{7*7}}, ${7*7}, etc.) and looks
    for the expected result (49, 7777777) in the response, indicating template
    evaluation.  Also probes with type-coercion payloads for blind detection.

    Parameters:
        url: Target URL with the suspected injectable parameter.
        param: Parameter name to test.
        method: GET or POST.
        param_location: "query" or "body".
        body: Form body for POST requests.
        template_engine: "auto", "jinja2", "freemarker", "velocity", "smarty", or "dotnet".
    """
    target = normalize_url(url)
    method_norm = method.strip().upper()
    if method_norm not in ("GET", "POST"):
        return error_result("test_ssti", target, "unsupported method").to_text()

    try:
        ssti_payloads = _payloads("ssti")
    except Exception:
        ssti_payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]

    # Baseline
    try:
        baseline_url, baseline_data = _replace_param(target, param, "normal_value", param_location, body)
        baseline = request(method_norm, baseline_url, data=baseline_data, timeout=10)
    except Exception as exc:
        return error_result("test_ssti", target, f"baseline failed: {exc}").to_text()

    # SSTI eval markers
    SSTI_MATH_MARKERS = [
        ("49", "{{7*7}} evaluated to 49 (Jinja2/Twig)"),
        ("7777777", "${7*7} = 7777777 (Java concatenation)"),
        ("49", "<%= 7*7 %> evaluated (ERB)"),
        ("49", "#{7*7} evaluated (Ruby)"),
        ("49", "expression result in response"),
    ]

    SSTI_ERROR_MARKERS = [
        ("jinja2", "Jinja2 template engine"),
        ("werkzeug", "Werkzeug debugger (Flask/Jinja2)"),
        ("freemarker", "FreeMarker template"),
        ("velocity", "Velocity template"),
        ("smarty", "Smarty template"),
        ("twig", "Twig template"),
        ("stringtemplate", "StringTemplate"),
        ("pebble", "Pebble template"),
        ("django.template", "Django template"),
        ("razor", "ASP.NET Razor"),
        ("view source", "template source leakage"),
    ]

    attempts: list[dict[str, Any]] = []
    best_score = 0
    best_signals: list[str] = []
    best_payload = ""

    for payload in ssti_payloads[:5]:
        probe_url, probe_data = _replace_param(target, param, payload, param_location, body)
        try:
            response = request(method_norm, probe_url, data=probe_data, timeout=10)
            lower = response.text.lower()
            score = 0
            signals: list[str] = []

            # Math eval detection
            for marker, label in SSTI_MATH_MARKERS:
                if marker.lower() in lower and marker.lower() not in baseline.text.lower():
                    # Make sure the original value doesn't contain 49 naturally
                    if marker == "49":
                        score += 80
                    else:
                        score += 60
                    signals.append(f"template eval: {label}")
                    break

            # Error-based detection
            for marker, label in SSTI_ERROR_MARKERS:
                if marker.lower() in lower:
                    score += 50
                    signals.append(f"engine exposure: {label}")
                    break

            # Differential
            ratio = difflib.SequenceMatcher(None, baseline.text[:4000], response.text[:4000]).ratio()
            if ratio < 0.85:
                score += 15
                signals.append("response differs from baseline")

            attempts.append({
                "payload": payload,
                "status": response.status_code,
                "length": len(response.text),
                "score": score,
                "signals": signals,
            })

            if score > best_score:
                best_score = score
                best_signals = signals
                best_payload = payload

            if score >= 80:
                break
        except Exception as exc:
            attempts.append({"payload": payload, "status": "error", "score": 0, "signals": [str(exc)]})

    # Confidence
    if best_score >= 80:
        confidence = "confirmed"
    elif best_score >= 35:
        confidence = "likely"
    elif best_score > 0:
        confidence = "weak"
    else:
        confidence = "unconfirmed"

    readable = "\n".join([
        f"[test_ssti] {target}",
        f"Parameter: {param} | Engine hint: {template_engine}",
        f"Best payload: {best_payload} (score={best_score})",
        f"Signals: {'; '.join(best_signals) if best_signals else '(none)'}",
        f"Conclusion: {confidence}",
    ])

    finding = None
    if confidence in ("confirmed", "likely"):
        finding = Finding(
            title="服务端模板注入 (SSTI) 验证结果",
            severity="critical" if confidence == "confirmed" else "high",
            confidence=confidence,
            category="ssti",
            evidence=[Evidence(
                "ssti_probe",
                "; ".join(best_signals),
                target,
                {"payload": best_payload, "score": best_score},
            )],
            reproduction=[
                f"发送 {method_norm} 请求，参数 {param}={best_payload}",
                "检查响应中是否包含数学表达式求值结果 (49) 或模板引擎错误",
            ],
        )

    return ToolResult(
        tool="test_ssti",
        target=target,
        status="ok",
        summary=f"SSTI 验证结论：{confidence}",
        raw_excerpt=readable,
        findings=[finding] if finding else [],
        request=RequestRecord(method_norm, target, parameters={"param": param}, payload=best_payload),
        response=response_record(baseline),
        data={"attempts": attempts, "best_score": best_score, "confidence": confidence},
    ).to_text()
