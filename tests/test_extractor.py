from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from intelextract.extractor import extract


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
def test_extract_returns_extraction_content(mock_anthropic):

    mock_client = MagicMock()
    mock_client.messages.create.return_value = _make_tool_use_response(_valid_tool_input())
    mock_anthropic.return_value = mock_client

    result = extract("some threat report text")

    assert result.threat_actors == ["APT41"]
    assert result.malware_families == ["Cobalt Strike"]
    assert result.iocs.ips == ["203.0.113.45"]
    assert result.attack_techniques[0].id == "T1059"


@patch("intelextract.extractor.Anthropic")
def test_extract_raises_when_no_tool_use_block(mock_anthropic):

    text_block = MagicMock()
    text_block.type = "text"

    response = MagicMock()
    response.content = [text_block]

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
