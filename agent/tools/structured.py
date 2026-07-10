"""Compatibility wrapper that gives existing LangChain tools the v0.9 protocol."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool

from .results import parse_tool_result, legacy_result


def structured_tool(tool: Any) -> StructuredTool:
    """Preserve a tool's input schema while wrapping its output in ToolResult."""

    def invoke(**kwargs: Any) -> str:
        output = tool.invoke(kwargs)
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
