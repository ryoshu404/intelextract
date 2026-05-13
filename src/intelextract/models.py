"""Pydantic models defining the extraction schema."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, field_validator


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    """Dedupe a string list while preserving first-occurrence order."""
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


class Hashes(BaseModel):
    md5: list[str]
    sha1: list[str]
    sha256: list[str]


class IOCs(BaseModel):
    hashes: Hashes
    ips: list[str]
    domains: list[str]
    urls: list[str]
    filenames: list[str]


class AttackTechnique(BaseModel):
    id: str
    name: str


class ExtractionContent(BaseModel):
    """Structured threat intelligence populated by the LLM tool call."""
    iocs: IOCs
    attack_techniques: list[AttackTechnique]
    threat_actors: list[str]
    malware_families: list[str]
    affected_sectors: list[str]
    affected_regions: list[str]

    @field_validator('threat_actors', 'malware_families', 'affected_sectors', 'affected_regions', mode='after')
    @classmethod
    def _dedupe_strings(cls, v: list[str]) -> list[str]:
        return _dedupe_preserve_order(v)

    @field_validator('attack_techniques', mode='after')
    @classmethod
    def _dedupe_techniques(cls, v: list[AttackTechnique]) -> list[AttackTechnique]:
        seen = set()
        result = []
        for technique in v:
            if technique.id not in seen:
                seen.add(technique.id)
                result.append(technique)
        return result


class Source(BaseModel):
    url: str | None
    final_url: str | None = None
    title: str | None
    fetched_at: datetime


class Usage(BaseModel):
    input_tokens: int
    output_tokens: int


class ExtractionMetadata(BaseModel):
    model: str
    extraction_time_ms: int
    usage: Usage


class Extraction(BaseModel):
    source: Source
    extraction: ExtractionContent
    extraction_metadata: ExtractionMetadata
