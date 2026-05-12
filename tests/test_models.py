from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from intelextract.models import (
    AttackTechnique,
    Extraction,
    ExtractionContent,
    ExtractionMetadata,
    Hashes,
    IOCs,
    Source,
    )


def _empty_iocs():
    return IOCs(
        hashes=Hashes(md5=[], sha1=[], sha256=[]),
        ips=[],
        domains=[],
        urls=[],
        filenames=[],
        )


def test_extraction_content_constructs_from_valid_input():

    content = ExtractionContent(
        iocs=_empty_iocs(),
        attack_techniques=[AttackTechnique(id="T1059", name="Command and Scripting Interpreter")],
        threat_actors=["APT41"],
        malware_families=["Cobalt Strike"],
        affected_sectors=[],
        affected_regions=[],
        )

    assert content.threat_actors == ["APT41"]
    assert content.malware_families == ["Cobalt Strike"]
    assert content.attack_techniques[0].id == "T1059"


def test_extraction_content_missing_field_raises():

    with pytest.raises(ValidationError):
        ExtractionContent(
            iocs=_empty_iocs(),
            attack_techniques=[],
            threat_actors=["APT41"],
            )


def test_dedupes_threat_actors_preserving_order():

    content = ExtractionContent(
        iocs=_empty_iocs(),
        attack_techniques=[],
        threat_actors=["APT41", "APT28", "APT41"],
        malware_families=[],
        affected_sectors=[],
        affected_regions=[],
        )

    assert content.threat_actors == ["APT41", "APT28"]


def test_dedupes_malware_families_preserving_order():

    content = ExtractionContent(
        iocs=_empty_iocs(),
        attack_techniques=[],
        threat_actors=[],
        malware_families=["Cobalt Strike", "Emotet", "Cobalt Strike", "TrickBot"],
        affected_sectors=[],
        affected_regions=[],
        )

    assert content.malware_families == ["Cobalt Strike", "Emotet", "TrickBot"]


def test_dedupes_attack_techniques_by_id_first_occurrence_wins():

    content = ExtractionContent(
        iocs=_empty_iocs(),
        attack_techniques=[
            AttackTechnique(id="T1059", name="Command and Scripting Interpreter"),
            AttackTechnique(id="T1059", name="PowerShell"),
            AttackTechnique(id="T1003", name="OS Credential Dumping"),
            ],
        threat_actors=[],
        malware_families=[],
        affected_sectors=[],
        affected_regions=[],
        )

    assert len(content.attack_techniques) == 2
    assert content.attack_techniques[0].name == "Command and Scripting Interpreter"
    assert content.attack_techniques[1].id == "T1003"


def test_extraction_wrapper_constructs():

    extraction = Extraction(
        source=Source(url="https://example.com", title=None, fetched_at=datetime.now(timezone.utc)),
        extraction=ExtractionContent(
            iocs=_empty_iocs(),
            attack_techniques=[],
            threat_actors=[],
            malware_families=[],
            affected_sectors=[],
            affected_regions=[],
            ),
        extraction_metadata=ExtractionMetadata(model="claude-sonnet-4-6", extraction_time_ms=1234),
        )

    assert extraction.source.url == "https://example.com"
    assert extraction.extraction_metadata.extraction_time_ms == 1234
