"""Anthropic API client wrapping the structured-extraction tool-use call."""

from __future__ import annotations

from anthropic import Anthropic

from .models import ExtractionContent, Usage

MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 4096
TOOL_NAME = "record_extraction"

PROMPT_TEMPLATE = """Extract threat intelligence from the following report. Use the {tool_name} tool.

- Use entity names only, without parenthetical context or descriptive qualifiers (e.g., "Conti" not "Conti operators", "Paige Thompson" not "Paige Thompson (former Amazon employee)").
- Do not invent generic placeholder values for affected_sectors or affected_regions. Forbidden values: "Global", "Worldwide", "All sectors", "Multiple sectors". When specific sectors or regions appear in the report, extract them.
- Do not repeat the same entity within a list.

Report:
{text}"""


class ExtractionTruncatedError(Exception):
    """Raised when the model's response was truncated by max_tokens."""


def extract(text: str) -> tuple[ExtractionContent, Usage]:
    client = Anthropic()
    tool = {
        "name": TOOL_NAME,
        "description": "Record the extracted threat intelligence.",
        "input_schema": ExtractionContent.model_json_schema(),
    }
    prompt = PROMPT_TEMPLATE.format(tool_name=TOOL_NAME, text=text)
    response = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        tools=[tool],
        tool_choice={"type": "tool", "name": TOOL_NAME},
        messages=[{"role": "user", "content": prompt}],
    )

    if response.stop_reason == "max_tokens":
        raise ExtractionTruncatedError(
            f"Model response was truncated (hit max_tokens={MAX_TOKENS})."
        )

    usage = Usage(
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
    )

    for block in response.content:
        if block.type == "tool_use":
            content = ExtractionContent(**block.input)
            return content, usage
    raise RuntimeError("No tool_use block in response")
