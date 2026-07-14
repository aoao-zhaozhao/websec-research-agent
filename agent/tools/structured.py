"""Compatibility wrapper that gives existing LangChain tools the v0.9 protocol.

v1.8: 新增 mcp_tool_adapter() —— 将 MCP 工具桥接到 LangChain StructuredTool。
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from langchain_core.tools import StructuredTool

from .results import parse_tool_result, legacy_result


def structured_tool(tool: Any) -> StructuredTool:
    """Preserve a tool's input schema while wrapping its output in ToolResult."""

    def invoke(**kwargs: Any) -> str:
        func = getattr(tool, "func", None)
        output = func(**kwargs) if callable(func) else tool.invoke(kwargs, config={"callbacks": []})
        _readable, result = parse_tool_result(output)
        if result is not None:
            return str(getattr(output, "content", output))
        return legacy_result(tool.name, kwargs, output).to_text()

    return StructuredTool.from_function(
        func=invoke,
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        infer_schema=False,
    )


def _json_schema_to_pydantic(schema: dict, tool_name: str) -> Any:
    """将 JSON Schema 简单映射为 Pydantic 模型。

    仅处理顶层 properties（平铺）—— MCP 工具 schema 绝大多数为平铺类型。
    """
    from pydantic import BaseModel, Field, create_model

    TYPE_MAP: dict[str, type] = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "object": dict,
        "array": list,
    }

    properties = schema.get("properties", {}) or {}
    required: set[str] = set(schema.get("required", []) or [])
    fields: dict[str, tuple[type, Any]] = {}

    for prop_name, prop_schema in properties.items():
        prop_type = prop_schema.get("type", "string")
        py_type = TYPE_MAP.get(prop_type, str)
        default = ... if prop_name in required else None
        description = prop_schema.get("description", "")
        fields[prop_name] = (py_type, Field(default=default, description=description))

    if not fields:
        fields["_"] = (str, Field(default="", description="No arguments"))

    model_name = f"MCP_{tool_name.replace('-', '_').replace('.', '_')}"
    return create_model(model_name, **fields)  # type: ignore[call-overload]


def mcp_tool_adapter(
    tool_name: str,
    server_name: str,
    input_schema: dict[str, Any],
    description: str,
    lifecycle_manager: Any,
) -> StructuredTool:
    """将 MCP 工具包装为 LangChain StructuredTool。

    Args:
        tool_name: MCP 工具名
        server_name: 所属 MCP 服务名
        input_schema: JSON Schema 格式的输入参数定义
        description: 工具描述
        lifecycle_manager: MCPLifecycleManager 实例
    """
    ArgsModel = _json_schema_to_pydantic(input_schema, tool_name)

    def invoke(**kwargs: Any) -> str:
        from .results import ToolResult, error_result

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        async def _call() -> dict:
            return await lifecycle_manager.call_tool(tool_name, kwargs)

        if loop is not None and loop.is_running():
            # 在已有事件循环中（如 FastAPI），创建新任务
            import concurrent.futures
            future = concurrent.futures.Future()

            def _runner() -> None:
                try:
                    result = asyncio.run(_call())
                    future.set_result(result)
                except Exception as exc:
                    future.set_exception(exc)

            thread = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            thread.submit(_runner)
            try:
                mcp_result = future.result(timeout=330)  # 略大于 tool_timeout
            except Exception as exc:
                return error_result(
                    tool_name, "", f"MCP 调用失败 [{server_name}/{tool_name}]: {exc}"
                ).to_text()
        else:
            try:
                mcp_result = asyncio.run(_call())
            except Exception as exc:
                return error_result(
                    tool_name, "", f"MCP 调用失败 [{server_name}/{tool_name}]: {exc}"
                ).to_text()

        if not mcp_result.get("ok"):
            error_msg = mcp_result.get("message", "未知错误")
            suggestion = mcp_result.get("suggestion", "")
            hint = f"\n提示: {suggestion}" if suggestion else ""
            return error_result(
                tool_name, "", f"[{server_name}] {error_msg}{hint}"
            ).to_text()

        content = mcp_result.get("content", "")
        structured_data = mcp_result.get("structured_content")
        summary = str(content)[:240] if content else f"{tool_name} 完成"

        return ToolResult(
            tool=tool_name,
            target="",
            status="ok",
            summary=summary,
            raw_excerpt=str(content)[:6000] if content else "",
            data={
                "mcp_server": server_name,
                "mcp_tool": tool_name,
                "structured": structured_data,
            },
        ).to_text()

    return StructuredTool.from_function(
        func=invoke,
        name=tool_name,
        description=f"[MCP:{server_name}] {description}",
        args_schema=ArgsModel,
        infer_schema=False,
    )
