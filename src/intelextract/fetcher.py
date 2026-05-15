"""URL fetching and HTML-to-text extraction."""

from __future__ import annotations

import httpx
import trafilatura


MAX_CONTENT_BYTES = 5 * 1024 * 1024


def fetch_url(url: str, user_agent: str, timeout: float = 30.0) -> tuple[str, str, str | None]:
    response = httpx.get(
        url,
        headers={'User-Agent': user_agent},
        follow_redirects=True,
        timeout=timeout,
    )
    response.raise_for_status()

    content_length = response.headers.get('content-length')
    if content_length and int(content_length) > MAX_CONTENT_BYTES:
        raise ValueError(
            f'Content too large: {content_length} bytes (limit {MAX_CONTENT_BYTES})'
        )

    content_type = response.headers.get('content-type')
    if content_type and not content_type.startswith('text/html'):
        raise ValueError(f'Unsupported content-type: {content_type}')

    metadata = trafilatura.extract_metadata(response.text)
    title = metadata.title if metadata else None

    text = trafilatura.extract(response.text)
    if not text:
        raise ValueError(f'No content extracted from {url}')

    return text, str(response.url), title
