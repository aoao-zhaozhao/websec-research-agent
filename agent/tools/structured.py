"""Compatibility wrapper that gives existing LangChain tools the v0.9 protocol."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool

from .results import parse_tool_result, legacy_result


def structured_tool(tool: Any) -> StructuredTool:
    """Preserve a tool's input schema while wrapping its output in ToolResult."""

    def invoke(**kwargs: Any) -> str:
        # Calling ``tool.invoke`` here creates a nested LangChain tool run with
        # the same name as the wrapper, which duplicates lifecycle telemetry.
        # The wrapper has already validated the input against the original schema.
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
