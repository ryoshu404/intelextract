from unittest.mock import MagicMock, patch

import pytest

from intelextract.fetcher import fetch_url


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_returns_extracted_text(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.text = "<html><body>Threat report content</body></html>"
    mock_httpx.get.return_value = response
    mock_trafilatura.extract.return_value = "Threat report content"

    result = fetch_url("https://example.com/report")

    assert result == "Threat report content"
    response.raise_for_status.assert_called_once()


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_raises_on_none_extraction(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.text = "<html></html>"
    mock_httpx.get.return_value = response
    mock_trafilatura.extract.return_value = None

    with pytest.raises(ValueError, match="No content extracted"):
        fetch_url("https://example.com/empty")


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_raises_on_empty_extraction(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.text = "<html></html>"
    mock_httpx.get.return_value = response
    mock_trafilatura.extract.return_value = ""

    with pytest.raises(ValueError, match="No content extracted"):
        fetch_url("https://example.com/empty")


@patch("intelextract.fetcher.trafilatura")
@patch("intelextract.fetcher.httpx")
def test_fetch_url_sets_user_agent_and_follows_redirects(mock_httpx, mock_trafilatura):

    response = MagicMock()
    response.text = "<html>x</html>"
    mock_httpx.get.return_value = response
    mock_trafilatura.extract.return_value = "x"

    fetch_url("https://example.com")

    call_kwargs = mock_httpx.get.call_args.kwargs
    assert call_kwargs["headers"]["User-Agent"] == "intelextract"
    assert call_kwargs["follow_redirects"] is True
