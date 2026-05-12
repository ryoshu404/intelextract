"""Command-line entry point for intelextract."""

from __future__ import annotations


import argparse
import importlib.metadata

from intelextract.extractor import extract
from intelextract.fetcher import fetch_url


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
    input_to_pass = args.text
    if args.url:
        input_to_pass = fetch_url(args.url)
    extraction = extract(input_to_pass)
    print(extraction.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
