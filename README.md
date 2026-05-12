# intelextract

intelextract is a Python CLI that extracts structured threat intelligence from threat-research text and produces deterministic JSON output suitable for downstream automation. The goal of intelextract is to provide a simple bridge between unstructured threat reporting and structured detection, correlation, and analyst workflows.

The tool consumes either a URL or raw text, sends the content to the Anthropic API with a forced tool-use contract, and returns a Pydantic-validated extraction. The schema captures threat actors, malware families, ATT&CK techniques, indicators of compromise, affected sectors, and affected regions.

---

# Features

intelextract implements the following capabilities:

- URL fetching via httpx with trafilatura content extraction
- Raw text input mode
- Anthropic API integration with forced tool use for structured output
- Pydantic schema as the single source of truth for both the tool's `input_schema` and response validation
- ATT&CK technique extraction (id + name)
- Nested IOC structure (hashes, IPs, domains, URLs, filenames)
- First-occurrence-wins deduplication on string fields and technique IDs
- Explicit `ValidationError` on malformed model output (no silent fallback)
- Source provenance and extraction metadata in the output envelope

---

# What It Doesn't Do

intelextract is intentionally narrow in v1:

- No multi-document correlation. Each invocation processes one document.
- No source-text presence validation. Extracted entities are not verified against the source text. (v1.1 scope.)
- No prompt-injection defenses beyond the structured tool contract. (v1.1 scope.)
- No IOC format validation. Hash lengths, IP formats, and domain patterns are accepted as the model emits them. (v1.1 scope.)
- No streaming. Single API call per invocation; full response or explicit failure.
- No persistent state. No cache, no database, no retry layer beyond what the SDK provides.

---

# Architecture

```
URL or text
↓
Fetcher (URL mode only)
↓
Extractor
↓
Anthropic API (forced tool_choice)
↓
Pydantic validation
↓
Extraction envelope (source + content + metadata)
↓
JSON to stdout
```

Each component is responsible for a single concern:

| Component | Responsibility |
|-----------|----------------|
| fetcher | Retrieves URL content via httpx; extracts main article text via trafilatura |
| extractor | Constructs API request, forces tool use, parses tool_use response, validates via Pydantic |
| models | Defines the extraction schema; generates the Anthropic tool's input_schema from the same Pydantic model |
| cli | Argument parsing, mode selection (URL vs text), wraps extraction with source and metadata envelope |

---

# Design Decisions

## Pydantic Schema as Single Source of Truth

The same Pydantic model that validates the API response also generates the Anthropic tool's `input_schema` via `model_json_schema()`. There is no separate schema definition — the API contract and the validation logic are the same object.

Benefits:

- Drift between API contract and validation is impossible by construction
- Schema changes propagate atomically — adding a field updates both the LLM's instructions and the parser
- One place to read and reason about output shape

## Forced Tool Use

The API call sets `tool_choice` to require the model to emit a `record_extraction` tool_use block. This eliminates the "did the model decide to use the tool?" branch — every successful call yields structured output, every malformed output raises explicitly.

## ValidationError as Explicit Failure Mode

When the model emits content that doesn't conform to the schema, Pydantic raises `ValidationError`. This is desired behavior. Downstream automation can rely on either valid structured output or an explicit exception — never silently malformed data.

## Single Call, No Streaming

Each invocation makes one API call and returns one result. No streaming, no multi-turn refinement, no fallback prompt strategies. Predictable latency, auditable cost per invocation, simple error surface.

## Two-Level Model Architecture

The schema is split into `ExtractionContent` (what the model populates) and `Extraction` (the outer envelope with source and metadata, which code populates). The tool's `input_schema` is generated from `ExtractionContent` only, so the model is exposed exclusively to fields it's responsible for emitting.

## AttackTechnique Deduplication by ID

When duplicate technique entries share an ID (e.g., `T1059.001` emitted twice with slightly different names), the first occurrence wins and subsequent duplicates are dropped. ATT&CK IDs are the canonical identifier; cosmetic name variants are noise.

## Prompt Strategy — Don't Invent, Don't Refuse

Initial prompt framing was "leave fields empty if not specifically named." This caused over-conservative extraction during corpus testing — the model dropped legitimate entities when uncertain. Final framing inverts the constraint: "do not invent generic placeholder values; when specific values appear in the text, extract them." This recovered legitimate extractions while preserving placeholder and qualifier suppression.

## httpx and trafilatura for Fetching

httpx for HTTP — explicit timeout handling, redirect support, and a sync API that keeps the call site readable. trafilatura for content extraction — handles common article-extraction edge cases without site-specific scraping. When trafilatura returns nothing, the fetcher raises `ValueError` rather than passing boilerplate or empty content to the model.

---

# Repository Structure

```
intelextract/
├── src/
│   └── intelextract/
│       ├── cli.py
│       ├── extractor.py
│       ├── fetcher.py
│       └── models.py
├── tests/
│   ├── test_models.py
│   ├── test_extractor.py
│   └── test_fetcher.py
├── README.md
└── pyproject.toml
```

---

# Installation

Requires Python 3.12+ and an Anthropic API key.

Clone the repository:
```bash
git clone https://github.com/ryoshu404/intelextract.git
cd intelextract
```

Create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate
```

Install the project in editable mode:
```bash
pip install -e .
```

Set your Anthropic API key:
```bash
export ANTHROPIC_API_KEY="..."
```

Verify the installation:
```bash
intelextract --version
```

---

# Usage

Extract from a URL:
```bash
intelextract --url https://example.com/threat-report
```

Extract from raw text:
```bash
intelextract --text "threat report content here..."
```

View available options:
```bash
intelextract --help
```

---

# Output Schema

Example output:

```json
{
  "source": {
    "url": "https://example.com/threat-report",
    "title": null,
    "fetched_at": "2026-05-12T15:30:00.000000+00:00"
  },
  "extraction": {
    "iocs": {
      "hashes": {
        "md5": [],
        "sha1": [],
        "sha256": ["..."]
      },
      "ips": ["..."],
      "domains": ["..."],
      "urls": ["..."],
      "filenames": ["..."]
    },
    "attack_techniques": [
      {"id": "T1059.001", "name": "PowerShell"},
      {"id": "T1003.001", "name": "LSASS Memory"}
    ],
    "threat_actors": ["FIN7"],
    "malware_families": ["Carbanak"],
    "affected_sectors": ["Financial Services"],
    "affected_regions": ["United States"]
  },
  "extraction_metadata": {
    "model": "claude-sonnet-4-6",
    "extraction_time_ms": 4231
  }
}
```

---

# Known Limitations

**No source-text presence validation.** Entities returned by the model are not currently verified against the source document. The forced tool_choice contract constrains shape, not content. Scoped for v1.1.

**No IOC format validation.** Hash lengths, IP formats, and domain patterns are accepted as the model emits them. Observed failure mode during corpus testing: a TLS certificate SHA-1 fingerprint formatted with colon separators was classified as a SHA-1 hash. Scoped for v1.1.

**Internal and infrastructure IPs extracted as IOCs.** RFC1918 ranges, AWS metadata IPs (169.254.169.254), and well-known public DNS resolvers (1.1.1.1, 8.8.8.8) appear in IOC output when present in the source. A `--strict-ioc` flag to filter these is v1.2 scope.

**Tools-vs-malware ambiguity.** Penetration testing tools used by attackers (Mimikatz, Impacket, PsExec, Crackmapexec) appear in `malware_families`. A schema split separating `tools_used` from `malware_families` is v1.2 scope.

**Output bounded by max_tokens.** Long reports may exceed the model's response token budget. The current implementation does not check `stop_reason` and may parse truncated responses. Scoped for v1.1.

---

# What's Planned (v1.1)

Operational hardening based on observed v1 failure modes:

- **Token handling.** Check `stop_reason` and raise `ExtractionTruncatedError` on truncation. Capture `usage` telemetry (input and output tokens) in extraction metadata.
- **IOC format validation.** Regex validation per IOC subfield (hash length, IPv4/IPv6 via the `ipaddress` module, domain format). Malformed values dropped with warnings appended to extraction metadata.
- **URL provenance.** Log final URL after redirects in the source envelope. Configurable User-Agent.
- **Prompt-injection defenses.** Explicit system prompt framing report content as data not instructions. Content delimiters in user messages.

Source-presence validation, URL reputation checks, and the `--strict-ioc` flag are documented as v1.2 candidates.

---

# Tech Stack

- Python 3.12+
- [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python)
- [Pydantic](https://docs.pydantic.dev/) v2 for schema and validation
- [httpx](https://www.python-httpx.org/) for HTTP
- [trafilatura](https://trafilatura.readthedocs.io/) for HTML content extraction
- pytest for testing

---

# Related Projects

Part of a larger security tooling portfolio.

### [pydetect](https://github.com/ryoshu404/pydetect) (v1.0)
Sigma detection rule library with a pytest harness and per-rule decision documentation. Rules validated against real captured attack telemetry from OTRF Security Datasets.

### [statica](https://github.com/ryoshu404/statica) (v1.0)
Modular static analysis pipeline written in Python. Extracts file hashes, printable strings, and common indicators of compromise from arbitrary files.

### [macollect](https://github.com/ryoshu404/macollect) (v1.0)
Modular macOS forensic artifact collector written in Python. Eight independent collection modules producing structured JSON for incident response and threat-hunting workflows.

---

# Author

R. Santos
GitHub: https://github.com/ryoshu404

---

# License

MIT
