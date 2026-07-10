"""
Agent skill tools for the self-evolution system (v1.3).

These tools allow the agent to:
  - Create reusable skills from successful exploitation techniques
  - Load skills into context for future scans
  - List, patch, and manage the skill library
  - Reflect on a completed scan and auto-generate skills

Inspired by Hermes Agent's skill_manage + curator system.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool

from ..skill_manager import CATEGORIES, VALID_STATES, get_skill_manager
from .results import Evidence, Finding, ToolResult, error_result


def _category_help() -> str:
    lines = ["可用技能分类:"]
    for key, label in CATEGORIES.items():
        lines.append(f"  {key} — {label}")
    return "\n".join(lines)


@tool
def skill_list(category: str = "") -> str:
    """List all learned skills in the agent's skill library.

    Call this before planning a scan to understand what prior experience
    the agent can bring to bear.  Skills capture proven detection and
    exploitation techniques from past scans.

    Parameters:
        category: Optional filter.  One of: sqli, xss, lfi, ssrf,
                  css_injection, auth, recon, csp_bypass, general.
                  Omit to list all.
    """
    mgr = get_skill_manager()
    cat = category.strip().lower() if category else ""
    if cat and cat not in CATEGORIES:
        return error_result("skill_list", f"category={cat}", f"Unknown category. {_category_help()}").to_text()

    skills = mgr.list_all(cat if cat else None)
    if not skills:
        hint = f" in category '{cat}'" if cat else ""
        return ToolResult(
            tool="skill_list", target="skills", status="ok",
            summary=f"技能库为空（{len(skills)} 个技能{hint}）",
            raw_excerpt=f"[skill_list] 尚未创建任何技能{hint}。\n{_category_help()}\n提示：完成一次成功的漏洞利用后，用 skill_create 沉淀经验。",
            data={"skills": [], "categories": list(CATEGORIES.keys())},
        ).to_text()

    lines = [f"[skill_list] 技能库（{len(skills)} 个技能）", ""]
    for s in skills:
        state_mark = {"active": "●", "stale": "○", "archived": "✕"}.get(s["state"], "?")
        lines.append(f"  {state_mark} [{s['category']}] {s['name']} — {s['description'][:80]}")
        if s["tags"]:
            lines.append(f"     标签: {', '.join(s['tags'])}  |  使用 {s['use_count']} 次  |  {s['state']}")
    lines.append("")
    lines.append(_category_help())

    return ToolResult(
        tool="skill_list", target="skills", status="ok",
        summary=f"技能库共 {len(skills)} 个技能",
        raw_excerpt="\n".join(lines),
        data={"skills": skills, "total": len(skills)},
    ).to_text()


@tool
def skill_load(name: str) -> str:
    """Load and activate a skill from the library for the current scan.

    The skill's full instructions are loaded into the agent's context,
    providing proven techniques for detecting and exploiting specific
    vulnerability types.  Loading a skill increments its use count.

    Parameters:
        name: The skill name (e.g. "time-based-sqli", "css-exfil-otp").
              Use skill_list to see available skills.
    """
    mgr = get_skill_manager()
    content = mgr.load(name.strip())
    if content is None:
        available = [s["name"] for s in mgr.list_all()]
        return ToolResult(
            tool="skill_load", target=name, status="error",
            summary=f"技能 '{name}' 不存在",
            raw_excerpt=f"[skill_load] 未找到技能 '{name}'。\n可用技能: {', '.join(available) if available else '(空)'}",
            data={"available": available},
        ).to_text()

    meta = mgr.load_metadata(name.strip())
    readable = (
        f"[skill_load] 已加载技能: {name}\n"
        f"分类: {meta.category if meta else '?'}\n"
        f"描述: {meta.description if meta else '?'}\n"
        f"使用次数: {meta.use_count if meta else 0}\n"
        f"--- 技能内容 ---\n"
        f"{content[:6000]}"
    )

    return ToolResult(
        tool="skill_load", target=name, status="ok",
        summary=f"已加载技能 '{name}'",
        raw_excerpt=readable,
        data={
            "name": name,
            "category": meta.category if meta else "general",
            "description": meta.description if meta else "",
            "content": content,
        },
    ).to_text()


@tool
def skill_create(
    title: str,
    description: str,
    body: str,
    category: str = "general",
    tags: str = "",
) -> str:
    """Create a new skill from a successful technique or discovery.

    Call this after completing a successful exploit, discovering a novel
    vulnerability pattern, or finding an effective workaround.  The skill
    becomes part of the agent's permanent knowledge and will be available
    for future scans via skill_load.

    Parameters:
        title: Short skill title (kebab-case, e.g. "css-exfil-otp").
        description: One-sentence summary of what this skill does (max 1024 chars).
        body: Full Markdown instructions.  Include: when to use, prerequisites,
              step-by-step procedure, example payloads, pitfalls, and
              verification steps.
        category: Vulnerability category.  One of: sqli, xss, lfi, ssrf,
                  css_injection, auth, recon, csp_bypass, general.
        tags: Comma-separated tags (e.g. "time-based,mysql,waf-bypass").
    """
    mgr = get_skill_manager()
    cat = category.strip().lower()
    if cat not in CATEGORIES:
        return error_result("skill_create", title, f"Unknown category '{cat}'. {_category_help()}").to_text()

    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    meta = mgr.create(
        title=title.strip(),
        description=description.strip()[:1024],
        body=body.strip(),
        category=cat,
        tags=tag_list,
    )

    readable = (
        f"[skill_create] 技能已创建\n"
        f"名称: {meta.name}\n"
        f"分类: {meta.category}\n"
        f"描述: {meta.description[:120]}\n"
        f"标签: {', '.join(meta.tags) if meta.tags else '(无)'}\n"
        f"路径: skills/{meta.category}/{meta.name}/SKILL.md\n"
        f"\n技能已保存到技能库。后续扫描中可通过 skill_load('{meta.name}') 加载使用。"
    )

    return ToolResult(
        tool="skill_create", target=meta.name, status="ok",
        summary=f"已创建技能 '{meta.name}' ({meta.category})",
        raw_excerpt=readable,
        findings=[
            Finding(
                title=f"新技能已沉淀: {meta.name}",
                severity="info", confidence="confirmed", category="skill_evolution",
                evidence=[Evidence("skill_created", meta.description, f"skills/{meta.category}/{meta.name}/SKILL.md")],
                reproduction=[f"使用 skill_load('{meta.name}') 在后续扫描中激活此技能。"],
            )
        ],
        data={"name": meta.name, "category": meta.category, "tags": meta.tags, "path": f"skills/{meta.category}/{meta.name}/SKILL.md"},
    ).to_text()


@tool
def skill_patch(name: str, old_text: str, new_text: str) -> str:
    """Improve an existing skill by replacing a section of its instructions.

    Use this when you've discovered a better approach, a new payload variant,
    or need to fix an error in a skill.  The old_text must match exactly
    (including whitespace) for the patch to apply.

    Parameters:
        name: The skill name to patch.
        old_text: The exact text to replace.
        new_text: The replacement text.
    """
    mgr = get_skill_manager()
    ok = mgr.patch(name.strip(), old_text, new_text)
    if not ok:
        return ToolResult(
            tool="skill_patch", target=name, status="error",
            summary=f"技能 '{name}' 补丁应用失败",
            raw_excerpt=f"[skill_patch] 补丁应用失败。请确认技能名和 old_text 完全匹配（包括缩进和空白）。",
            data={"success": False},
        ).to_text()

    readable = (
        f"[skill_patch] 技能已更新\n"
        f"名称: {name}\n"
        f"已将匹配文本替换为新内容。"
    )

    return ToolResult(
        tool="skill_patch", target=name, status="ok",
        summary=f"技能 '{name}' 已更新",
        raw_excerpt=readable,
        data={"success": True, "name": name},
    ).to_text()


@tool
def scan_reflect(target: str, findings_summary: str, successful_techniques: str = "", failed_attempts: str = "") -> str:
    """Reflect on a completed scan and produce actionable lessons learned.

    Call this at the END of every scan.  The tool analyzes what worked and
    what didn't, then suggests whether to create new skills or update
    existing ones.

    Parameters:
        target: The scan target URL.
        findings_summary: Brief summary of confirmed/suspected findings.
        successful_techniques: What worked well — tools, payload patterns,
                               bypass methods, etc.
        failed_attempts: What didn't work — blocked payloads, WAF triggers,
                         timeouts, false positives, etc.
    """
    mgr = get_skill_manager()
    existing = [s["name"] for s in mgr.list_all()]

    lines = [
        f"[scan_reflect] 扫描反思 — {target}",
        "",
        "## 发现概要",
        findings_summary.strip() or "(无)",
        "",
    ]

    suggestions: list[dict[str, Any]] = []

    if successful_techniques.strip():
        lines.append("## 成功经验")
        lines.append(successful_techniques.strip())
        lines.append("")
        suggestions.append({
            "action": "consider_skill_create",
            "reason": "成功的技术应沉淀为技能，供后续扫描复用",
            "source": successful_techniques.strip()[:500],
        })

    if failed_attempts.strip():
        lines.append("## 失败教训")
        lines.append(failed_attempts.strip())
        lines.append("")
        suggestions.append({
            "action": "note_pitfalls",
            "reason": "失败的尝试记录为经验，避免后续扫描重复踩坑",
            "source": failed_attempts.strip()[:500],
        })

    lines.append("## 建议操作")
    if successful_techniques.strip():
        lines.append("✅ 调用 skill_create 将成功经验沉淀为技能。")
        lines.append("   格式: skill_create(title='...', description='...', body='...', category='...')")
    if failed_attempts.strip():
        lines.append("⚠️ 在最终报告中记录失败路径，避免重复尝试已被 WAF/过滤器阻止的 payload。")
    if existing:
        lines.append(f"ℹ️ 已有 {len(existing)} 个技能: {', '.join(existing[:8])}")

    lines.append("")
    lines.append("提示：反思是 Agent 自进化的关键环节。每次扫描后的反思 → skill_create 循环会使 Agent 持续变强。")

    return ToolResult(
        tool="scan_reflect", target=target, status="ok",
        summary=f"扫描反思完成（{len(suggestions)} 条建议）",
        raw_excerpt="\n".join(lines),
        findings=[
            Finding(
                title="扫描反思",
                severity="info", confidence="confirmed", category="self_evolution",
                evidence=[Evidence("reflection", "\n".join(lines), target)],
                reproduction=["根据建议调用 skill_create 或 skill_patch 沉淀经验。"],
            )
        ],
        data={"target": target, "suggestions": suggestions, "existing_skills": existing},
    ).to_text()
