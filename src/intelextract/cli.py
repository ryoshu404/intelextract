"""Command-line entry point for intelextract."""

from __future__ import annotations

import argparse
import time
import importlib.metadata
from datetime import datetime, timezone


from .extractor import MODEL, extract
from .fetcher import fetch_url
from .models import Extraction, ExtractionMetadata, Source


try:
    VERSION = importlib.metadata.version('intelextract')
except importlib.metadata.PackageNotFoundError:
    VERSION = 'unknown'


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="intelextract",
        description="intelextract - extract structured TI from threat reports via Anthropic API.",
        epilog="https://github.com/ryoshu404/intelextract",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--url", help="URL of threat research to fetch and extract from")
    input_group.add_argument("--text", help="Pasted text to extract from directly")
    parser.add_argument("-v", "--version", action="version", version=f"intelextract {VERSION}")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.url:
        text = fetch_url(args.url)
        source_url = args.url
    else:
        text = args.text
        source_url = None
    fetched_at = datetime.now(timezone.utc)
    start = time.perf_counter()
    content, usage = extract(text)
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    extraction = Extraction(
        source=Source(url=source_url, title=None, fetched_at=fetched_at),
        extraction=content,
        extraction_metadata=ExtractionMetadata(
            model=MODEL,
            extraction_time_ms=elapsed_ms,
            usage=usage,
            ),
            )

    print(extraction.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
