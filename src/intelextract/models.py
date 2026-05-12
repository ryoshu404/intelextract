"""Pydantic models defining the extraction schema."""

from __future__ import annotations

from pydantic import BaseModel, Field

class Extraction(BaseModel):
    iocs: list[str]
    threat_actors: list[str]
    malware_families: list[str]
