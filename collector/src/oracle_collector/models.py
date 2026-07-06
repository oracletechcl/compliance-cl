from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, ClassVar


ALLOWED_SIGNALS = frozenset({"present", "absent", "unknown", "misconfigured"})
_OPAQUE_RESOURCE = re.compile(r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|ocid1\.[a-z0-9._-]+)$", re.IGNORECASE)
_ATTRIBUTE_LABELS = {
    "audit_event": "Evento de auditoría",
    "audit_configuration": "Configuración de auditoría",
    "public_access": "Acceso público",
    "mfa_state": "Estado de MFA",
    "tls_configuration": "Configuración TLS",
    "backup_configuration": "Configuración de respaldo",
    "tde_encryption": "Cifrado TDE",
    "volume_encryption": "Cifrado de volumen",
}
_OCI_SERVICE_NAMES = {
    "api_gateway": "OCI API Gateway",
    "block_storage": "OCI Block Storage",
    "logging_analytics": "OCI Logging Analytics",
    "object_storage": "OCI Object Storage",
    "oke": "Oracle Kubernetes Engine",
    "mysql": "MySQL HeatWave",
}
_ONPREM_PRODUCT_NAMES = {
    "weblogic": "Oracle WebLogic Server",
    "ohs": "Oracle HTTP Server",
    "oam": "Oracle Access Manager",
    "oaa": "Oracle Advanced Authentication",
    "oag": "Oracle API Gateway",
    "webgate": "Oracle WebGate",
    "avdf": "Oracle Audit Vault and Database Firewall",
}


def _is_opaque_resource(value: str) -> bool:
    normalized = value.strip().lower()
    return bool(
        _OPAQUE_RESOURCE.search(normalized)
        or normalized.startswith("ocid1.")
        or normalized.startswith("[ocid")
        or "sha256:" in normalized
        or normalized in {"unknown", "n/a"}
    )


def _attribute_label(attribute: str) -> str:
    normalized = attribute.split(":")[-1]
    return _ATTRIBUTE_LABELS.get(normalized, normalized.replace("_", " ").replace("-", " ").capitalize())


def _component_name(service: str, resource: str, attribute: str) -> str:
    aspect = _attribute_label(attribute)
    if _is_opaque_resource(resource):
        return f"{service} — {aspect}"
    return f"{service} — {resource} — {aspect}"


def _component_service(collector: str, product: str) -> str:
    if product:
        return _ONPREM_PRODUCT_NAMES.get(product.strip().lower(), product)
    if collector.startswith("oci."):
        service = collector.removeprefix("oci.")
        return _OCI_SERVICE_NAMES.get(service, "OCI " + service.replace("_", " ").title())
    return {
        "dbsat": "Oracle Database Security Assessment Tool (DBSAT)",
        "direct_sql": "Oracle Database (SQL directo)",
        "middleware": "Oracle Middleware",
    }.get(collector, collector)


def _identifier_type(resource: str, provider: str) -> str:
    if resource.strip().lower().startswith("ocid1."):
        return "OCID"
    if provider == "OCI":
        return "Identificador OCI"
    if provider == "On-Premises":
        return "Alias de destino"
    return "Identificador técnico"


@dataclass
class EvidenceRecord:
    id: str
    layer: str
    resource: str
    attribute: str
    value: Any
    signal: str
    control_ids: list[str] = field(default_factory=list)
    law_refs: list[str] = field(default_factory=list)
    remediation_candidates: list[dict[str, Any]] = field(default_factory=list)
    source: dict[str, Any] = field(default_factory=dict)
    component: dict[str, str] = field(default_factory=dict)
    confidence: str | None = None

    allowed_signals: ClassVar[frozenset[str]] = ALLOWED_SIGNALS

    def __post_init__(self) -> None:
        if self.signal not in self.allowed_signals:
            raise ValueError(f"invalid technical signal: {self.signal!r}")
        if not self.id or not self.layer or not self.resource or not self.attribute:
            raise ValueError("evidence id, layer, resource, and attribute are required")
        collector = str(self.source.get("collector") or "collector")
        provider = "OCI" if collector.startswith("oci.") else "On-Premises" if collector in {"dbsat", "direct_sql", "middleware"} or collector.startswith("onprem") else "Other"
        service = _component_service(collector, str(self.source.get("product") or ""))
        aspect = _attribute_label(str(self.attribute))
        default_component = {
            "id": "cmp-" + hashlib.sha256(f"{collector}|{self.layer}|{self.resource}".encode("utf-8")).hexdigest()[:16],
            "name": _component_name(service, str(self.resource), str(self.attribute)),
            "type": str(self.layer),
            "provider": provider,
            "service": service,
            "aspect": aspect,
            "resource_id": str(self.resource),
            "identifier_type": _identifier_type(str(self.resource), provider),
        }
        supplied = self.component if isinstance(self.component, dict) else {}
        self.component = {
            key: str(supplied.get(key) or value)
            for key, value in default_component.items()
        }

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "layer": self.layer,
            "resource": self.resource,
            "attribute": self.attribute,
            "value": self.value,
            "signal": self.signal,
            "control_ids": list(self.control_ids),
            "law_refs": list(self.law_refs),
            "remediation_candidates": list(self.remediation_candidates),
            "source": dict(self.source),
            "component": dict(self.component),
        }
        if self.confidence is not None:
            payload["confidence"] = self.confidence
        return payload


@dataclass
class CollectorResult:
    evidence: list[EvidenceRecord] = field(default_factory=list)
    inventory: list[dict[str, Any]] = field(default_factory=list)
    raw_files: dict[str, Any] = field(default_factory=dict)
    services_scanned: list[str] = field(default_factory=list)
    services_skipped: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    environment: dict[str, Any] = field(default_factory=dict)
    resilience_tier_observed: dict[str, Any] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        if any(bool(error.get("fatal")) for error in self.errors):
            return 1
        if self.errors or self.services_skipped:
            return 2
        return 0

    def merge(self, other: "CollectorResult") -> None:
        self.evidence.extend(other.evidence)
        self.inventory.extend(other.inventory)
        self.raw_files.update(other.raw_files)
        self.services_scanned.extend(x for x in other.services_scanned if x not in self.services_scanned)
        self.services_skipped.extend(other.services_skipped)
        self.warnings.extend(other.warnings)
        self.errors.extend(other.errors)
        self.environment.update(other.environment)
        self.resilience_tier_observed.update(other.resilience_tier_observed)
