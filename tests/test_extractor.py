from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from intelextract.extractor import extract, ExtractionTruncatedError


def _make_tool_use_response(tool_input: dict):
    tool_use_block = MagicMock()
    tool_use_block.type = "tool_use"
    tool_use_block.input = tool_input

    response = MagicMock()
    response.content = [tool_use_block]
    return response


def _valid_tool_input():
    return {
        "iocs": {
            "hashes": {"md5": [], "sha1": [], "sha256": []},
            "ips": ["203.0.113.45"],
            "domains": [],
            "urls": [],
            "filenames": [],
            },
        "attack_techniques": [{"id": "T1059", "name": "PowerShell"}],
        "threat_actors": ["APT41"],
        "malware_families": ["Cobalt Strike"],
        "affected_sectors": [],
        "affected_regions": [],
        }


@patch("intelextract.extractor.Anthropic")
def test_extract_returns_content_and_usage(mock_anthropic):
    response = _make_tool_use_response(_valid_tool_input())
    response.stop_reason = "tool_use"
    response.usage = MagicMock(input_tokens=500, output_tokens=200)
    mock_anthropic.return_value.messages.create.return_value = response

    content, usage = extract("some threat report text")

    assert content.threat_actors == ["APT41"]
    assert content.malware_families == ["Cobalt Strike"]
    assert content.iocs.ips == ["203.0.113.45"]
    assert content.attack_techniques[0].id == "T1059"
    assert usage.input_tokens == 500
    assert usage.output_tokens == 200


@patch("intelextract.extractor.Anthropic")
def test_extract_raises_when_no_tool_use_block(mock_anthropic):

    text_block = MagicMock()
    text_block.type = "text"

    response = MagicMock()
    response.content = [text_block]
    response.stop_reason = "tool_use"
    response.usage = MagicMock(input_tokens=0, output_tokens=0)

    mock_client = MagicMock()
    mock_client.messages.create.return_value = response
    mock_anthropic.return_value = mock_client

    with pytest.raises(RuntimeError, match="No tool_use block"):
        extract("some text")


@patch("intelextract.extractor.Anthropic")
def test_extract_raises_validation_error_on_malformed_tool_input(mock_anthropic):

    malformed_input = {
        "iocs": {
            "hashes": {"md5": [], "sha1": [], "sha256": []},
            "ips": [],
            "domains": [],
            "urls": [],
            "filenames": [],
            },
        }

    mock_client = MagicMock()
    mock_client.messages.create.return_value = _make_tool_use_response(malformed_input)
    mock_anthropic.return_value = mock_client

    with pytest.raises(ValidationError):
        extract("some text")


@patch("intelextract.extractor.Anthropic")
def test_extract_raises_on_max_tokens_stop_reason(mock_anthropic):
    response = MagicMock()
    response.stop_reason = "max_tokens"
    mock_anthropic.return_value.messages.create.return_value = response

    with pytest.raises(ExtractionTruncatedError):
        extract("some text")


@patch("intelextract.extractor.Anthropic")
def test_extract_sends_system_prompt_and_report_delimiters(mock_anthropic):
    response = _make_tool_use_response(_valid_tool_input())
    response.stop_reason = "tool_use"
    response.usage = MagicMock(input_tokens=500, output_tokens=200)
    mock_anthropic.return_value.messages.create.return_value = response

    extract("malicious report content here")

    call_kwargs = mock_anthropic.return_value.messages.create.call_args.kwargs
    assert "system" in call_kwargs
    assert "<report>" in call_kwargs["messages"][0]["content"]
    assert "</report>" in call_kwargs["messages"][0]["content"]
    assert "malicious report content here" in call_kwargs["messages"][0]["content"]


@patch("intelextract.extractor.Anthropic")
def test_extract_passes_api_timeout(mock_anthropic):
    response = _make_tool_use_response(_valid_tool_input())
    response.stop_reason = "tool_use"
    response.usage = MagicMock(input_tokens=500, output_tokens=200)
    mock_anthropic.return_value.messages.create.return_value = response

    extract("some text")

    call_kwargs = mock_anthropic.return_value.messages.create.call_args.kwargs
    assert call_kwargs["timeout"] == 120
