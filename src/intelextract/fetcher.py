"""URL fetching and HTML-to-text extraction."""

from __future__ import annotations


import httpx
import trafilatura


USER_AGENT = "intelextract"

def fetch_url(url: str, timeout: float = 30.0) -> str:
    response = httpx.get(
        url,
        timeout = timeout,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        )
    response.raise_for_status()
    text = trafilatura.extract(response.text)
    if not text:
        raise ValueError(f"Failed to extract text from {url}")
    return text
