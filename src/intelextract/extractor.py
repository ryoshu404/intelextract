"""Anthropic API client wrapping the structured-extraction tool-use call."""

from __future__ import annotations

from anthropic import Anthropic

from .models import ExtractionContent

MODEL = "claude-sonnet-4-6"
TOOL_NAME = "record_extraction"

PROMPT_TEMPLATE = """Extract threat intelligence from the following report. Use the {tool_name} tool.

- Use entity names only, without parenthetical context or descriptive qualifiers (e.g., "Conti" not "Conti operators", "Paige Thompson" not "Paige Thompson (former Amazon employee)").
- Do not invent generic placeholder values for affected_sectors or affected_regions. Forbidden values: "Global", "Worldwide", "All sectors", "Multiple sectors". When specific sectors or regions appear in the report, extract them.
- Do not repeat the same entity within a list.

Report:
{text}"""


def extract(text: str) -> ExtractionContent:
    client = Anthropic()
    tool = {
        "name": TOOL_NAME,
        "description": "Record the extracted threat intelligence.",
        "input_schema": ExtractionContent.model_json_schema(),
    }
    prompt = PROMPT_TEMPLATE.format(tool_name=TOOL_NAME, text=text)
    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        tools=[tool],
        tool_choice={"type": "tool", "name": TOOL_NAME},
        messages=[{"role": "user", "content": prompt}],
    )
    for block in response.content:
        if block.type == "tool_use":
            return ExtractionContent(**block.input)
    raise RuntimeError("No tool_use block in response")
