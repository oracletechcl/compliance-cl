from __future__ import annotations

import pytest

from oracle_collector.mapper import apply_mapping
from oracle_collector.models import EvidenceRecord


def make_record(**overrides: object) -> EvidenceRecord:
    values = {
        "id": "ev-1",
        "layer": "storage",
        "resource": "bucket:exports",
        "attribute": "public_access",
        "value": {"visibility": "public"},
        "signal": "misconfigured",
        "source": {"collector": "oci.object_storage", "ref": "raw/oci/object_storage/test.json"},
    }
    values.update(overrides)
    return EvidenceRecord(**values)


def test_evidence_record_serializes_only_technical_signal() -> None:
    record = make_record()
    payload = record.to_dict()
    assert payload["signal"] == "misconfigured"
    assert "status" not in payload


def test_evidence_record_derives_a_nonempty_oci_component() -> None:
    component = make_record().to_dict()["component"]

    assert component["id"].startswith("cmp-")
    assert component["name"] == "OCI Object Storage — bucket:exports — Acceso público"
    assert component["type"] == "storage"
    assert component["provider"] == "OCI"
    assert component["service"] == "OCI Object Storage"
    assert component["resource_id"] == "bucket:exports"
    assert component["identifier_type"] == "Identificador OCI"


def test_evidence_record_derives_a_nonempty_onprem_component() -> None:
    component = make_record(
        layer="database",
        resource="coreprod",
        source={"collector": "dbsat", "product": "Oracle Database"},
    ).to_dict()["component"]

    assert "coreprod" in component["name"]
    assert component["provider"] == "On-Premises"
    assert component["service"] == "Oracle Database"
    assert component["resource_id"] == "coreprod"
    assert component["identifier_type"] == "Alias de destino"


def test_opaque_resource_identifier_is_replaced_with_a_human_component_label() -> None:
    component = make_record(
        layer="monitoring",
        resource="c63aa62b-b483-415f-b42f-32282a38442a",
        attribute="audit_event",
        source={"collector": "oci.audit"},
    ).to_dict()["component"]

    assert component["name"] == "OCI Audit — Evento de auditoría"
    assert component["aspect"] == "Evento de auditoría"
    assert "c63aa62b" not in component["name"]


def test_redacted_ocid_is_not_exposed_as_a_component_name() -> None:
    component = make_record(
        resource="ocid1.fnapp.sha256:abc123",
        attribute="tls_configuration",
        source={"collector": "oci.functions"},
    ).to_dict()["component"]

    assert component["name"] == "OCI Functions — Configuración TLS"
    assert "ocid1" not in component["name"].lower()


def test_prefixed_uuid_is_not_exposed_as_a_component_name() -> None:
    component = make_record(
        layer="storage",
        resource="csi-0d514092-b314-4bad-af7a-5909aa36a7a9",
        attribute="volume_encryption",
        source={"collector": "oci.block_storage"},
    ).to_dict()["component"]

    assert component["name"] == "OCI Block Storage — Cifrado de volumen"
    assert "0d514092" not in component["name"]


@pytest.mark.parametrize(
    ("collector", "product", "expected_provider"),
    [
        ("oci.networking", "", "OCI"),
        ("dbsat", "Oracle Database", "On-Premises"),
        ("direct_sql", "Oracle Database", "On-Premises"),
        ("middleware", "weblogic", "On-Premises"),
    ],
)
def test_component_mapping_covers_cloud_onprem_and_hybrid_collectors(
    collector: str, product: str, expected_provider: str
) -> None:
    component = make_record(
        resource=f"{collector}-component",
        source={"collector": collector, "product": product},
    ).to_dict()["component"]

    assert component["name"]
    assert component["service"]
    assert component["provider"] == expected_provider


def test_invalid_signal_is_rejected() -> None:
    with pytest.raises(ValueError, match="signal"):
        make_record(signal="fail")


def test_mapper_attaches_controls_and_remediation_without_verdict() -> None:
    record = make_record(control_ids=[], remediation_candidates=[])
    mapped = apply_mapping(record)
    assert {"sec-rest", "inc-brechas"}.issubset(set(mapped.control_ids))
    assert any(item["deployment"] == "oci" for item in mapped.remediation_candidates)
    assert "status" not in mapped.to_dict()
