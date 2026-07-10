"""Bounded active verification for SQLi, XSS, and LFI.

The verifier is deliberately small: every probe has a baseline and invalid
control, only GET and form-style POST are allowed, and no payload is retried
outside the configured list.  A result is confirmed only when a strong,
type-specific response signal is present alongside the control comparison.
"""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from langchain_core.tools import tool

from .http_client import normalize_url, request
from .results import Evidence, Finding, RequestRecord, ToolResult, error_kind, error_result, response_record


PAYLOAD_FILE = Path(__file__).parent.parent / "payloads" / "injection.json"
ALLOWED_TYPES = frozenset({"sqli", "xss", "lfi"})
ALLOWED_METHODS = frozenset({"GET", "POST"})
INVALID_VALUE = "myagent-invalid-control"

SQL_ERRORS = (
    "sql syntax", "mysql", "postgresql", "sqlite", "ora-", "odbc", "unclosed quotation",
)
LFI_MARKERS = (
    "root:x:0:0", "/bin/bash", "[fonts]", "[extensions]", "http_user_agent=",
    "cm9vddp4oja6mdp",  # Lowercased Base64 prefix of "root:x:0:0:root".
)
XSS_MARKER = "myagent-xss-probe"


def _payloads(vuln_type: str) -> list[str]:
    with PAYLOAD_FILE.open(encoding="utf-8") as handle:
        loaded = json.load(handle)
    values = loaded.get(vuln_type, [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"invalid payload configuration for {vuln_type}")
    return values[:4]


def _replace_query(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    updated: list[tuple[str, str]] = []
    for key, old_value in pairs:
        if key == param:
            updated.append((key, value))
            replaced = True
        else:
            updated.append((key, old_value))
    if not replaced:
        updated.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))


def _replace_form(data: str, param: str, value: str) -> str:
    pairs = parse_qsl(data, keep_blank_values=True)
    if not any(key == param for key, _ in pairs):
        pairs.append((param, value))
    else:
        pairs = [(key, value if key == param else old_value) for key, old_value in pairs]
    return urlencode(pairs, doseq=True)


def _signal_score(vuln_type: str, text: str, baseline: str, invalid: str) -> tuple[int, list[str], dict[str, object]]:
    score = 0
    signals: list[str] = []
    details: dict[str, object] = {}
    baseline_ratio = difflib.SequenceMatcher(None, baseline[:6000], text[:6000]).ratio()
    invalid_ratio = difflib.SequenceMatcher(None, invalid[:6000], text[:6000]).ratio()
    details["baseline_similarity"] = round(baseline_ratio, 3)
    details["invalid_similarity"] = round(invalid_ratio, 3)
    if baseline_ratio < 0.85:
        score += 10
        signals.append("response differs from baseline")
    if invalid_ratio < 0.85:
        score += 10
        signals.append("response differs from invalid control")

    lower = text.lower()
    if vuln_type == "sqli":
        markers = [marker for marker in SQL_ERRORS if marker in lower]
        if markers:
            score += 70
            signals.append(f"database error marker: {markers[0]}")
    elif vuln_type == "xss" and XSS_MARKER in lower:
        score += 80
        signals.append("exact XSS probe marker reflected in response")
    elif vuln_type == "lfi":
        markers = [marker for marker in LFI_MARKERS if marker in lower]
        if markers:
            score += 70
            signals.append(f"file-content marker: {markers[0]}")
    return score, signals, details


def _confidence(score: int, signals: list[str]) -> str:
    has_strong_signal = any(
        signal.startswith(("database error marker", "exact XSS", "file-content marker")) for signal in signals
    )
    if score >= 80 and has_strong_signal:
        return "confirmed"
    if score >= 35:
        return "likely"
    if score > 0:
        return "weak"
    return "unconfirmed"


@tool
def verify_injection(
    url: str,
    param: str,
    vuln_type: str,
    method: str = "GET",
    form_data: str = "",
) -> str:
    """Verify one SQLi, XSS, or LFI input point using bounded control probes.

    Only use this against an authorized same-origin target discovered during the
    scan.  GET changes one query parameter. POST sends form-urlencoded data;
    pass the original form body through form_data.  The tool sends baseline,
    invalid-control, and at most four configured payload requests.
    """
    normalized_type = vuln_type.strip().lower()
    normalized_method = method.strip().upper()
    target = normalize_url(url)
    if normalized_type not in ALLOWED_TYPES:
        return error_result("verify_injection", target, f"unsupported vuln_type: {vuln_type}").to_text()
    if normalized_method not in ALLOWED_METHODS:
        return error_result("verify_injection", target, "only GET and POST verification are allowed").to_text()

    try:
        payloads = _payloads(normalized_type)
        if normalized_method == "GET":
            baseline_url, baseline_data = target, None
            invalid_url, invalid_data = _replace_query(target, param, INVALID_VALUE), None
        else:
            baseline_url, baseline_data = target, form_data
            invalid_url, invalid_data = target, _replace_form(form_data, param, INVALID_VALUE)
        baseline = request(normalized_method, baseline_url, data=baseline_data)
        invalid = request(normalized_method, invalid_url, data=invalid_data)
    except Exception as exc:
        return error_result("verify_injection", target, exc).to_text()

    attempts: list[dict[str, object]] = []
    errors: list[dict[str, str]] = []
    best: dict[str, object] | None = None
    for payload in payloads:
        if normalized_method == "GET":
            probe_url, probe_data = _replace_query(target, param, payload), None
        else:
            probe_url, probe_data = target, _replace_form(form_data, param, payload)
        try:
            response = request(normalized_method, probe_url, data=probe_data)
            score, signals, diff = _signal_score(normalized_type, response.text, baseline.text, invalid.text)
            attempt: dict[str, object] = {
                "payload": payload, "url": probe_url, "method": normalized_method, "data": probe_data,
                "response": response_record(response).__dict__, "score": score, "signals": signals, "diff": diff,
            }
            attempts.append(attempt)
            if best is None or int(attempt["score"]) > int(best["score"]):
                best = attempt
            if _confidence(score, signals) == "confirmed":
                break
        except Exception as exc:
            errors.append({"kind": error_kind(exc), "message": f"payload {payload[:80]}: {exc}"})

    if best is None:
        return ToolResult(
            tool="verify_injection", target=target, status="error", summary="所有 payload 请求失败",
            errors=errors or [{"kind": "tool_bug", "message": "No payload requests were sent."}],
            raw_excerpt=f"[verify_injection] {normalized_type} {target}\nAll payload requests failed.",
            request=RequestRecord(normalized_method, target, parameters={"param": param}), response=response_record(baseline),
            data={"baseline": response_record(baseline).__dict__, "invalid": response_record(invalid).__dict__, "attempts": attempts},
        ).to_text()

    confidence = _confidence(int(best["score"]), list(best["signals"]))
    evidence = Evidence(
        "differential_probe", "; ".join(best["signals"]) or "No material differential signal.", str(best["url"]),
        {"payload": best["payload"], "diff": best["diff"], "response": best["response"]},
    )
    finding = Finding(
        title=f"{normalized_type.upper()} 验证结果", severity="high" if confidence in {"confirmed", "likely"} else "info",
        confidence=confidence, category=normalized_type, evidence=[evidence],
        reproduction=[
            f"发送 {normalized_method} {best['url']}",
            f"参数 {param} 使用 payload: {best['payload']}",
            "与 baseline 和无效值控制请求比较响应状态、长度、片段及相似度。",
        ],
    )
    readable = (
        f"[verify_injection] {normalized_type.upper()} {target}\n"
        f"Parameter: {param} | Method: {normalized_method}\n"
        f"Baseline: status={baseline.status_code}, length={len(baseline.text)}\n"
        f"Invalid control: status={invalid.status_code}, length={len(invalid.text)}\n"
        f"Best payload: {best['payload']}\n"
        f"Signals: {'; '.join(best['signals']) or '(none)'}\n"
        f"Result: {confidence}"
    )
    return ToolResult(
        tool="verify_injection", target=target, status="ok", summary=f"{normalized_type.upper()} 验证结论：{confidence}",
        raw_excerpt=readable, findings=[finding], errors=errors,
        request=RequestRecord(normalized_method, target, parameters={"param": param}, payload=str(best["payload"])),
        response=response_record(baseline),
        data={"baseline": response_record(baseline).__dict__, "invalid": response_record(invalid).__dict__, "attempts": attempts},
    ).to_text()
