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
- Explicit failure modes: `ValidationError` on malformed output, `ExtractionTruncatedError` on token-limit truncation, `RuntimeError` on missing tool_use block
- Token usage telemetry (input and output tokens) in the output envelope
- URL provenance — captures `final_url` after redirects alongside the requested URL
- Configurable User-Agent via `--user-agent`
- Prompt-injection defenses via explicit system prompt and `<report>...</report>` content delimiters
- Source provenance and extraction metadata in the output envelope

---

# What It Doesn't Do

intelextract is intentionally narrow:

- No multi-document correlation. Each invocation processes one document.
- No source-text presence validation. Extracted entities are not verified against the source text. (v1.2 scope.)
- No IOC format validation. Hash lengths, IP formats, and domain patterns are accepted as the model emits them. (v1.2 scope.)
- No URL reputation checking. The fetcher trusts the operator-supplied URL. (v1.2 scope.)
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
Anthropic API (system prompt + forced tool_choice)
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
| fetcher | Retrieves URL content via httpx; extracts main article text via trafilatura; returns text and final URL after redirects |
| extractor | Constructs API request with system prompt and report delimiters, forces tool use, parses tool_use response, validates via Pydantic, surfaces token usage |
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

## Explicit Failure Modes

The extractor and fetcher surface every failure as a typed exception:

- `pydantic.ValidationError` — model emitted content that doesn't conform to the schema
- `ExtractionTruncatedError` — `stop_reason == "max_tokens"`, response was truncated
- `RuntimeError` — response contained no `tool_use` block (unexpected API behavior)
- `ValueError` — trafilatura extracted no content from the fetched URL

None of these are silent fallbacks. Downstream automation can rely on either valid structured output or an explicit exception by type. Each failure mode maps to a different remediation: truncation is retryable with shorter input, validation errors indicate API-contract drift or LLM emitting non-conforming output, no-tool-use-block is genuinely unexpected API behavior, and empty content is an input-quality problem.

## Single Call, No Streaming

Each invocation makes one API call and returns one result. No streaming, no multi-turn refinement, no fallback prompt strategies. Predictable latency, auditable cost per invocation, simple error surface.

## Two-Level Model Architecture

The schema is split into `ExtractionContent` (what the model populates) and `Extraction` (the outer envelope with source and metadata, which code populates). The tool's `input_schema` is generated from `ExtractionContent` only, so the model is exposed exclusively to fields it's responsible for emitting.

## AttackTechnique Deduplication by ID

When duplicate technique entries share an ID (e.g., `T1059.001` emitted twice with slightly different names), the first occurrence wins and subsequent duplicates are dropped. ATT&CK IDs are the canonical identifier; cosmetic name variants are noise.

## Prompt Strategy — Don't Invent, Don't Refuse

Initial prompt framing was "leave fields empty if not specifically named." This caused over-conservative extraction during corpus testing — the model dropped legitimate entities when uncertain. Final framing inverts the constraint: "do not invent generic placeholder values; when specific values appear in the text, extract them." This recovered legitimate extractions while preserving placeholder and qualifier suppression.

## Prompt-Injection Defenses

The Anthropic API call passes an explicit `system` parameter framing user-message content as data not instructions. The report text in the user message is wrapped in `<report>...</report>` delimiters. The system prompt explicitly names common injection patterns — instructions, system messages, role declarations, directives addressed to the model — rather than relying on a generic "treat as data" framing.

The defense relies on the API's privilege gradient: the `system` parameter is treated by the model as more authoritative than instructions appearing in user-message content. Putting the defensive framing in the system prompt and the report content (potentially adversarial) in the user message means an attacker controlling the report content can't reach up and override the framing.

This is one of three layers: (1) forced `tool_choice` constrains output shape; (2) system prompt and delimiters constrain interpretation; (3) Pydantic schema validation constrains structure. Source-presence validation — verifying that extracted entities actually appear in the source text — is a fourth layer scoped for v1.2.

## URL Provenance

The `Source` envelope captures both `url` (the URL requested) and `final_url` (the URL httpx resolved to after redirects). For threat intelligence, the URL the content actually came from matters more than the URL requested — redirects can canonicalize tracking parameters, change geographic routing, or in adversarial cases serve content from a different destination. Surfacing both makes redirect chains visible without requiring the consumer to re-fetch.

The User-Agent header is configurable via `--user-agent`. The default follows the Googlebot convention — `intelextract/<version> (+https://github.com/ryoshu404/intelextract)` — so sysadmins seeing this UA in logs can identify the source without guessing.

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

Extract with a custom User-Agent (e.g., for operator identification when coordinating with site owners):
```bash
intelextract --url https://example.com/threat-report --user-agent "MyOrg-IR-Bot/1.0 (contact@myorg.example)"
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
    "final_url": "https://example.com/threat-report",
    "title": null,
    "fetched_at": "2026-05-13T15:30:00.000000+00:00"
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
    "extraction_time_ms": 4231,
    "usage": {
      "input_tokens": 7800,
      "output_tokens": 1100
    }
  }
}
```

---

# Known Limitations

**No source-text presence validation.** Entities returned by the model are not verified against the source document. The system prompt and forced tool_choice constrain shape and discourage invention, but don't guarantee extracted entities are actually present in the source. Scoped for v1.2.

**No IOC format validation.** Hash lengths, IP formats, and domain patterns are accepted as the model emits them. Observed failure mode during corpus testing: a TLS certificate SHA-1 fingerprint formatted with colon separators was classified as a SHA-1 hash. Scoped for v1.2.

**Internal and infrastructure IPs extracted as IOCs.** RFC1918 ranges, AWS metadata IPs (169.254.169.254), and well-known public DNS resolvers (1.1.1.1, 8.8.8.8) appear in IOC output when present in the source. A `--strict-ioc` flag to filter these is v1.2 scope.

**Tools-vs-malware ambiguity.** Penetration testing tools used by attackers (Mimikatz, Impacket, PsExec, Crackmapexec) appear in `malware_families`. A schema split separating `tools_used` from `malware_families` is v1.2 scope.

**Output bounded by `max_tokens=4096`.** Long reports producing many entities may hit the response token budget and raise `ExtractionTruncatedError`. A configurable `--max-tokens` flag is a v1.2 candidate.

**No URL reputation checking.** The fetcher trusts the operator-supplied URL. `final_url` is captured for provenance, but no automatic reputation check is performed against threat-intel sources. Scoped for v1.2.

---

# What's Shipped (v1.1)

Operational hardening across three dimensions:

- **Token handling.** `stop_reason` checked; `ExtractionTruncatedError` raised on truncation; `usage` telemetry (input and output tokens) captured in extraction metadata.
- **URL provenance.** `final_url` captured after redirects in the source envelope; configurable `--user-agent` flag with default identifying the tool, version, and repository.
- **Prompt-injection defenses.** Explicit system prompt framing report content as data not instructions; report text wrapped in `<report>...</report>` content delimiters in user messages.

# What's Planned (v1.2)

- **Source-presence validation.** Verify extracted entities appear in source text. Open design questions on normalization (defanging, case sensitivity, partial matching, paraphrase tolerance) — to be anchored by corpus testing rather than chosen arbitrarily.
- **IOC format validation.** Regex per IOC subfield (hash lengths, IPv4/IPv6 via the `ipaddress` module, domain format). Malformed values dropped with warnings appended to extraction metadata.
- **URL reputation check.** Optional flag-gated provider integration (URLhaus or similar). Provider choice and failure-mode behavior to be designed deliberately.
- **`--strict-ioc` flag.** Filter internal and infrastructure IPs (RFC1918, AWS metadata, public DNS resolvers).
- **`tools_used` vs `malware_families` schema split.** Separate penetration-testing tooling from malware families.
- **`--max-tokens` flag.** Allow operator override of the default 4096 output token budget.

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
