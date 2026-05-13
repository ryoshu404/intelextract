"""URL fetching and HTML-to-text extraction."""

from __future__ import annotations

import httpx
import trafilatura


def fetch_url(url: str, user_agent: str, timeout: float = 30.0) -> tuple[str, str]:
    response = httpx.get(
        url,
        headers={"User-Agent": user_agent},
        follow_redirects=True,
        timeout=timeout,
    )
    response.raise_for_status()

    text = trafilatura.extract(response.text)
    if not text:
        raise ValueError(f"No content extracted from {url}")

    return text, str(response.url)
