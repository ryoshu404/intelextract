from unittest.mock import MagicMock, patch

import pytest

from intelextract.fetcher import fetch_url


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_returns_text_final_url_and_title(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.text = "<html>...</html>"
    response.url = "https://example.com/report"
    response.headers = {}
    mock_httpx.get.return_value = response
    metadata = MagicMock()
    metadata.title = "Sample Threat Report"
    mock_trafilatura.extract_metadata.return_value = metadata
    mock_trafilatura.extract.return_value = "Threat report content"

    text, final_url, title = fetch_url("https://example.com/report", user_agent="test-agent")

    assert text == "Threat report content"
    assert final_url == "https://example.com/report"
    assert title == "Sample Threat Report"
    response.raise_for_status.assert_called_once()


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_title_none_when_no_metadata(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.text = "<html>...</html>"
    response.url = "https://example.com"
    response.headers = {}
    mock_httpx.get.return_value = response
    mock_trafilatura.extract_metadata.return_value = None
    mock_trafilatura.extract.return_value = "text"

    _, _, title = fetch_url("https://example.com", user_agent="test-agent")

    assert title is None


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_raises_on_none_extraction(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.text = "<html></html>"
    response.headers = {}
    mock_httpx.get.return_value = response
    mock_trafilatura.extract.return_value = None

    with pytest.raises(ValueError, match="No content extracted"):
        fetch_url("https://example.com/empty", user_agent="test-agent")


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_raises_on_empty_extraction(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.text = "<html></html>"
    response.headers = {}
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
    response.headers = {}
    mock_httpx.get.return_value = response
    mock_trafilatura.extract.return_value = "x"

    fetch_url("https://example.com", user_agent="test-agent/1.0")

    call_kwargs = mock_httpx.get.call_args.kwargs
    assert call_kwargs["headers"]["User-Agent"] == "test-agent/1.0"
    assert call_kwargs["follow_redirects"] is True


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_raises_on_oversized_content(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.headers = {'content-length': str(20 * 1024 * 1024)}  # 20 MB
    mock_httpx.get.return_value = response

    with pytest.raises(ValueError, match="Content too large"):
        fetch_url("https://example.com", user_agent="test-agent")


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_raises_on_non_html_content_type(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.headers = {'content-type': 'application/pdf'}
    mock_httpx.get.return_value = response

    with pytest.raises(ValueError, match="Unsupported content-type"):
        fetch_url("https://example.com/doc.pdf", user_agent="test-agent")
