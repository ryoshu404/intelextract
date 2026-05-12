"""Anthropic API client wrapping the structured-extraction tool-use call."""

from __future__ import annotations

from anthropic import Anthropic

from intelextract.models import Extraction

MODEL = "claude-sonnet-4-6"


def extract(text: str) -> Extraction:
    """Send text to Claude and return the validated Extraction."""

    client = Anthropic()
    prompt = f"Extract threat intelligence from the following report.\n\n{text}"

    tool = {
        "name": "record_extraction",
        "description": "Record the structured threat intel extracted from the provided report text.",
        "input_schema": Extraction.model_json_schema(),
        }

    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        tools=[tool],
        tool_choice={"type": "tool", "name": "record_extraction"},
        messages=[{"role": "user", "content": prompt}],
        )

    for block in response.content:
        if block.type == "tool_use":
            return Extraction(**block.input)
    raise RuntimeError("Model did not call the extraction tool")
