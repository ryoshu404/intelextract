from unittest.mock import MagicMock, patch

import pytest

from intelextract.fetcher import fetch_url


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_returns_text_and_final_url(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.text = "<html><body>Threat report content</body></html>"
    response.url = "https://example.com/report"
    mock_httpx.get.return_value = response
    mock_trafilatura.extract.return_value = "Threat report content"

    text, final_url = fetch_url("https://example.com/report", user_agent="test-agent")

    assert text == "Threat report content"
    assert final_url == "https://example.com/report"
    response.raise_for_status.assert_called_once()


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_raises_on_none_extraction(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.text = "<html></html>"
    mock_httpx.get.return_value = response
    mock_trafilatura.extract.return_value = None

    with pytest.raises(ValueError, match="No content extracted"):
        fetch_url("https://example.com/empty", user_agent="test-agent")


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_raises_on_empty_extraction(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.text = "<html></html>"
    mock_httpx.get.return_value = response
    mock_trafilatura.extract.return_value = ""

    with pytest.raises(ValueError, match="No content extracted"):
        fetch_url("https://example.com/empty", user_agent="test-agent")


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_sends_user_agent_and_follows_redirects(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.text = "<html>x</html>"
    response.url = "https://example.com"
    mock_httpx.get.return_value = response
    mock_trafilatura.extract.return_value = "x"

    fetch_url("https://example.com", user_agent="test-agent/1.0")

    call_kwargs = mock_httpx.get.call_args.kwargs
    assert call_kwargs["headers"]["User-Agent"] == "test-agent/1.0"
    assert call_kwargs["follow_redirects"] is True
