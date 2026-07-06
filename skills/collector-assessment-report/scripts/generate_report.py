#!/usr/bin/env python3
"""Build a conservative, self-contained report from collector evidence.

The script intentionally creates only a draft assessment unless a reviewed
assessment overlay is supplied. It uses Python's standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import stat
import sys
import tarfile
import tempfile
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


STATUSES = ("pass", "partial", "fail")
ACCEPTED_INPUT_STATUSES = (*STATUSES, "unknown")
DISCLAIMER = "Evaluación técnica informativa únicamente; no constituye asesoría legal ni una certificación de cumplimiento."
PRICE_LIST = "https://www.oracle.com/cloud/price-list/"
DEFAULT_MAX_ARCHIVE_MEMBERS = 10_000
DEFAULT_MAX_ARCHIVE_UNCOMPRESSED_BYTES = 1_073_741_824

OCI_ID_RE = re.compile(r"\bocid1\.[A-Za-z0-9_.:-]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)

PRODUCT_NAMES = {
    "api_gateway": "OCI API Gateway",
    "block_storage": "OCI Block Volume",
    "cloud_guard": "OCI Cloud Guard",
    "compute": "OCI Compute",
    "container_instances": "OCI Container Instances",
    "database": "Oracle Database on OCI",
    "functions": "OCI Functions",
    "load_balancer": "OCI Load Balancer",
    "logging": "OCI Logging",
    "logging_analytics": "OCI Logging Analytics",
    "monitoring": "OCI Monitoring",
    "mysql": "MySQL HeatWave on OCI",
    "networking": "OCI Networking",
    "notifications": "OCI Notifications",
    "object_storage": "OCI Object Storage",
    "oke": "Oracle Kubernetes Engine",
    "security_zones": "OCI Security Zones",
    "threat_intelligence": "OCI Threat Intelligence",
    "vault": "OCI Vault",
    "waf": "OCI Web Application Firewall",
}

ONPREM_PRODUCT_NAMES = {
    "database": "Oracle Database",
    "oracle database": "Oracle Database",
    "weblogic": "Oracle WebLogic Server",
    "oam": "Oracle Access Manager",
    "oaa": "Oracle Advanced Authentication",
    "oag": "Oracle API Gateway (on-premises)",
    "webgate": "Oracle WebGate",
}

REMEDIATIONS = {
    "sec-logs": "Defina los eventos de auditoría obligatorios, habilite logs de servicio y aplicación, configure retención, restrinja el acceso y pruebe su recuperación.",
    "sec-monitoring": "Defina señales accionables, alarmas, responsables y rutas de escalamiento; pruebe periódicamente la entrega de notificaciones.",
    "inc-brechas": "Documente recepción y triaje de incidentes, decisiones de notificación legal, preservación de evidencia, ejercicios y un registro de brechas.",
    "sec-secrets": "Inventaríe los secretos, muévalos a almacenamiento administrado, rótelos, restrinja políticas y monitoree el acceso.",
    "sec-backups": "Defina objetivos de recuperación, calendarios y retención de respaldos, aísle copias cuando corresponda y pruebe restauraciones.",
    "sec-tls": "Exija versiones TLS compatibles y certificados administrados en cada endpoint público e interno; pruebe la renovación.",
    "sec-rest": "Verifique cifrado en reposo y propiedad de claves para cada almacén; documente rotación y segregación de funciones.",
    "sec-mfa": "Exija MFA para identidades privilegiadas y de fuerza laboral, elimine cuentas compartidas y pruebe procedimientos de recuperación.",
    "sec-tenant": "Exija límites por tenant en IAM, red, almacenamiento, base de datos y autorización de aplicación; agregue pruebas de aislamiento.",
    "data-derechos": "Implemente recepción autenticada de solicitudes, verificación de identidad, seguimiento de plazos, exportación, corrección, eliminación y apelaciones.",
    "data-minimizacion": "Asocie cada dato con una finalidad y regla de retención; detenga la recolección y elimine datos sin necesidad justificada.",
    "data-info": "Publique un aviso de privacidad completo vinculado al tratamiento real, destinatarios, retención, transferencias, derechos y canales de contacto.",
    "data-eipd": "Realice y apruebe una evaluación de impacto antes de tratamientos de alto riesgo; haga seguimiento de riesgos residuales y disparadores de revisión.",
    "gov-registro": "Mantenga un inventario con responsable de tratamientos, actividades y riesgos que incluya sistemas, datos, fines, destinatarios, retención y controles.",
    "gov-politicas": "Apruebe, publique, capacite y revise periódicamente las políticas requeridas de gobierno y privacidad.",
}

# Concrete, ordered, Spanish step-by-step instructions per control. These back
# the "Acción de mitigación" detail alongside the explanatory REMEDIATIONS
# text above. A reviewed assessment overlay may supply its own
# `remediation_steps` per control; this dict is only the deterministic
# draft's default. Controls without a specific entry fall back to
# GENERIC_REMEDIATION_STEPS.
REMEDIATION_STEPS = {
    "sec-logs": [
        "Defina los eventos de auditoría obligatorios para infraestructura y aplicación.",
        "Habilite los logs de servicio y de aplicación necesarios.",
        "Configure la retención y restrinja el acceso a los registros.",
        "Proteja las exportaciones de logs contra manipulación o eliminación no autorizada.",
        "Pruebe periódicamente la búsqueda, las alertas y la recuperación de los registros.",
    ],
    "sec-monitoring": [
        "Defina señales accionables, alarmas, responsables y rutas de escalamiento por carga de trabajo.",
        "Configure las alarmas y sus destinos de notificación.",
        "Afine las detecciones según el perfil de cada carga de trabajo.",
        "Pruebe periódicamente la entrega de notificaciones de extremo a extremo.",
    ],
    "inc-brechas": [
        "Documente la recepción y el triaje de incidentes.",
        "Defina el proceso de decisión de notificación legal al regulador y a los titulares.",
        "Documente el procedimiento de preservación de evidencia durante la investigación.",
        "Ejecute ejercicios periódicos de simulación de incidentes.",
        "Mantenga un registro de brechas actualizado con las decisiones tomadas.",
    ],
    "sec-secrets": [
        "Inventaríe los secretos existentes sin exponer sus valores.",
        "Muévalos a un almacenamiento administrado (OCI Vault Secrets).",
        "Rote los secretos según una política definida.",
        "Restrinja las políticas de acceso a los secretos con mínimo privilegio.",
        "Monitoree el acceso a los secretos y genere alertas ante uso anómalo.",
    ],
    "sec-backups": [
        "Defina los objetivos de recuperación (RPO/RTO) por tipo de dato.",
        "Establezca calendarios y plazos de retención de respaldos.",
        "Aísle las copias de respaldo del entorno productivo cuando corresponda.",
        "Pruebe periódicamente la restauración documentada de los respaldos.",
    ],
    "sec-tls": [
        "Exija versiones de TLS compatibles y vigentes en cada endpoint público e interno.",
        "Use certificados administrados en todos los puntos de entrada.",
        "Verifique que el tráfico HTTP se redirija o deshabilite en favor de HTTPS.",
        "Pruebe periódicamente el proceso de renovación de certificados.",
    ],
    "sec-rest": [
        "Verifique el cifrado en reposo de cada base de datos, volumen y almacén de objetos.",
        "Documente la propiedad y administración de las claves de cifrado.",
        "Defina y documente la rotación de claves.",
        "Verifique la segregación de funciones sobre la gestión de claves y secretos.",
    ],
    "sec-mfa": [
        "Exija MFA para todas las identidades privilegiadas y de fuerza laboral.",
        "Elimine las cuentas compartidas y de acceso genérico.",
        "Proteja y pruebe los procedimientos de recuperación de cuenta.",
    ],
    "sec-tenant": [
        "Exija límites por tenant en IAM, red, almacenamiento y base de datos.",
        "Aplique autorización de aplicación por tenant en cada consulta.",
        "Agregue pruebas automatizadas negativas de aislamiento entre tenants.",
    ],
    "data-derechos": [
        "Implemente la recepción autenticada de solicitudes de derechos.",
        "Defina la verificación de identidad del titular, proporcional al riesgo.",
        "Haga seguimiento de los plazos legales de respuesta.",
        "Implemente exportación, corrección y eliminación de datos personales.",
        "Habilite un mecanismo de apelación para el titular.",
    ],
    "data-minimizacion": [
        "Asocie cada dato recolectado con una finalidad específica.",
        "Defina la regla de retención aplicable a cada dato.",
        "Detenga la recolección de datos sin necesidad justificada.",
        "Elimine los datos que ya no tengan una finalidad vigente.",
    ],
    "data-info": [
        "Redacte un aviso de privacidad vinculado al tratamiento real.",
        "Incluya destinatarios, retención, transferencias y derechos del titular.",
        "Publique los canales de contacto del responsable del tratamiento.",
        "Enlace el aviso en cada punto de recolección de datos.",
    ],
    "data-eipd": [
        "Identifique los tratamientos de alto riesgo que requieren una evaluación de impacto.",
        "Realice la evaluación de impacto antes de iniciar el tratamiento.",
        "Obtenga la aprobación formal de la evaluación.",
        "Documente el seguimiento de riesgos residuales y sus disparadores de revisión.",
    ],
    "gov-registro": [
        "Cree un inventario de tratamientos con responsable asignado.",
        "Documente sistemas, datos, fines, destinatarios y retención de cada tratamiento.",
        "Incluya los riesgos identificados y los controles aplicados.",
        "Mantenga el inventario actualizado con revisiones periódicas.",
    ],
    "gov-politicas": [
        "Redacte las políticas de gobierno y privacidad requeridas.",
        "Apruebe formalmente cada política con el responsable correspondiente.",
        "Publique las políticas y capacite al personal involucrado.",
        "Revise periódicamente las políticas y actualícelas cuando corresponda.",
    ],
    "ctrl-interno": [
        "Defina las reglas de autorización y segregación de funciones.",
        "Aplique esas reglas en los procesos y sistemas relevantes.",
        "Implemente un mecanismo de auditoría sobre las autorizaciones.",
        "Haga seguimiento de los hallazgos y su cierre.",
    ],
}

GENERIC_REMEDIATION_STEPS = [
    "Asigne un responsable formal del control.",
    "Reúna o genere la evidencia faltante para acreditar el cumplimiento.",
    "Defina criterios de aceptación claros y verificables.",
    "Implemente el control y verifique su efectividad de forma periódica.",
]


def die(message: str) -> "NoReturn":
    raise SystemExit(f"error: {message}")


def archive_limit(environment_name: str, default: int) -> int:
    raw = os.environ.get(environment_name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        die(f"{environment_name} must be a positive integer")
    if value <= 0:
        die(f"{environment_name} must be a positive integer")
    return value


def digest_marker(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"[{kind}:sha256:{digest}]"


def sanitize_display_text(value: str) -> str:
    """Redact identifiers and credential material before anything is emitted."""

    value = PRIVATE_KEY_RE.sub("[private-key:redacted]", value)
    value = BEARER_RE.sub(lambda match: digest_marker("bearer", match.group(0)), value)
    value = EMAIL_RE.sub(lambda match: digest_marker("email", match.group(0).lower()), value)
    value = OCI_ID_RE.sub(lambda match: digest_marker("oci-id", match.group(0)), value)
    return value


def sanitize_for_display(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_display_text(value)
    if isinstance(value, list):
        return [sanitize_for_display(item) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_for_display(item) for key, item in value.items()}
    return value


def archive_stem(path: Path) -> str:
    lower = path.name.lower()
    for suffix in (".tar.gz", ".tgz", ".tar", ".zip"):
        if lower.endswith(suffix):
            return path.name[: -len(suffix)]
    return path.stem


def safe_member_path(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    member = PurePosixPath(normalized)
    if member.is_absolute() or not member.parts or ".." in member.parts:
        die(f"unsafe archive member: {name!r}")
    if re.match(r"^[A-Za-z]:", normalized):
        die(f"unsafe archive member: {name!r}")
    return member


def copy_archive_member(source: Any, destination: Any, remaining_bytes: int) -> int:
    copied = 0
    while True:
        chunk = source.read(min(1024 * 1024, remaining_bytes - copied + 1))
        if not chunk:
            return copied
        copied += len(chunk)
        if copied > remaining_bytes:
            die("archive exceeded the uncompressed byte safety limit during extraction")
        destination.write(chunk)


def extract_archive(archive: Path, destination: Path) -> None:
    max_members = archive_limit("COLLECTOR_REPORT_MAX_ARCHIVE_MEMBERS", DEFAULT_MAX_ARCHIVE_MEMBERS)
    max_bytes = archive_limit(
        "COLLECTOR_REPORT_MAX_ARCHIVE_UNCOMPRESSED_BYTES", DEFAULT_MAX_ARCHIVE_UNCOMPRESSED_BYTES
    )
    lower = archive.name.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive) as source:
            members = source.infolist()
            if len(members) > max_members:
                die(f"archive exceeds the {max_members} member safety limit")
            if sum(info.file_size for info in members) > max_bytes:
                die(f"archive exceeds the {max_bytes} byte uncompressed safety limit")
            extracted_bytes = 0
            for info in members:
                member = safe_member_path(info.filename)
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    die(f"archive links are not allowed: {info.filename!r}")
                target = destination.joinpath(*member.parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(info) as src, target.open("wb") as dst:
                    extracted_bytes += copy_archive_member(src, dst, max_bytes - extracted_bytes)
        return
    if lower.endswith((".tar", ".tar.gz", ".tgz")):
        with tarfile.open(archive, "r:*") as source:
            members = source.getmembers()
            if len(members) > max_members:
                die(f"archive exceeds the {max_members} member safety limit")
            if sum(info.size for info in members if info.isfile()) > max_bytes:
                die(f"archive exceeds the {max_bytes} byte uncompressed safety limit")
            extracted_bytes = 0
            for info in members:
                member = safe_member_path(info.name)
                if info.isdir():
                    destination.joinpath(*member.parts).mkdir(parents=True, exist_ok=True)
                    continue
                if not info.isfile():
                    die(f"archive links and special files are not allowed: {info.name!r}")
                target = destination.joinpath(*member.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                src = source.extractfile(info)
                if src is None:
                    die(f"could not read archive member: {info.name!r}")
                with src, target.open("wb") as dst:
                    extracted_bytes += copy_archive_member(src, dst, max_bytes - extracted_bytes)
        return
    die("collector input must be a directory or .zip/.tar/.tar.gz/.tgz archive")


def find_bundle(root: Path) -> Path:
    candidates = sorted(p for p in root.rglob("evidence-bundle.json") if p.is_file())
    if len(candidates) != 1:
        die(f"expected exactly one evidence-bundle.json, found {len(candidates)}")
    return candidates[0]


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"cannot read valid JSON from {path}: {exc}")
    if not isinstance(value, dict):
        die(f"expected a JSON object in {path}")
    return value


def validate_bundle(bundle: dict[str, Any]) -> None:
    for key in ("inventory", "evidence"):
        if not isinstance(bundle.get(key), list):
            die(f"evidence bundle field {key!r} must be an array")
    for index, evidence in enumerate(bundle["evidence"]):
        if not isinstance(evidence, dict):
            die(f"evidence[{index}] must be an object")
        if not isinstance(evidence.get("control_ids", []), list):
            die(f"evidence[{index}].control_ids must be an array")


def validate_repo(repo: Path) -> None:
    missing = [name for name in ("packs", "references", "sources") if not (repo / name).is_dir()]
    if missing:
        die(f"repository root is missing required directories: {', '.join(missing)}")
    if not (repo / "references" / "controls.md").is_file():
        die("repository root is missing references/controls.md")


def expected_requirement(control_id: str, name: str, evidence_expected: str) -> str:
    """Describe the observable result required without exposing repository internals."""
    if control_id.startswith("sec-"):
        detail = "La configuración técnica debe aplicarse en todo el alcance, con responsable, registros verificables y revisión de efectividad."
    elif control_id.startswith("data-"):
        detail = "Deben existir proceso, decisión documentada e implementación verificable para los datos y tratamientos dentro del alcance."
    elif control_id.startswith("gov-") or control_id == "ctrl-interno":
        detail = "Deben existir responsable identificado, procedimiento aprobado, evidencia de ejecución y revisión periódica."
    elif control_id.startswith("inc-"):
        detail = "Deben existir responsables, procedimiento operativo, registro de casos o ejercicios y evidencia de notificación cuando aplique."
    else:
        detail = "Debe existir una implementación verificable, responsable y evidencia de operación para el alcance evaluado."
    return f"Se espera que «{name}» esté definido, implementado y operativo. {detail} La evidencia mínima debe incluir: {evidence_expected}."


def expected_component(control_id: str) -> dict[str, str]:
    targets = {
        "sec-tls": ("Endpoints, gateways y balanceadores", "network", "Cifrado en tránsito"),
        "sec-rest": ("Bases de datos y almacenamiento con datos sensibles", "storage", "Cifrado en reposo"),
        "sec-passwords": ("Mecanismo de autenticación de la aplicación", "iam", "Gestión de contraseñas"),
        "sec-mfa": ("Identidades y accesos administrativos", "iam", "Gestión de identidades"),
        "sec-logs": ("Plataforma de registros de auditoría", "monitoring", "Registro y auditoría"),
        "sec-monitoring": ("Plataforma de monitoreo y alertas", "monitoring", "Monitoreo operativo"),
        "sec-tenant": ("Límites de tenant en aplicación, IAM y datos", "iam", "Aislamiento multi-tenant"),
        "sec-secrets": ("Gestión de secretos y claves", "iam", "Secretos y llaves"),
        "sec-backups": ("Servicios de respaldo y recuperación", "database", "Respaldo y recuperación"),
        "inc-brechas": ("Proceso de respuesta a incidentes", "monitoring", "Gestión de incidentes"),
        "ctrl-interno": ("Proceso de autorizaciones y segregación", "governance", "Control interno"),
    }
    if control_id.startswith("data-"):
        target = ("Flujos de tratamiento de datos y aplicación", "application", "Gobierno de datos")
    elif control_id.startswith("gov-"):
        target = ("Proceso de gobierno, responsables y evidencias", "governance", "Gobierno organizacional")
    elif control_id.startswith("trans-"):
        target = ("Integraciones, terceros y transferencias", "application", "Gestión de terceros")
    else:
        target = targets.get(control_id, ("Componente del alcance evaluado", "application", "Control aplicable"))
    name, component_type, service = target
    return {
        "id": f"target-{control_id}",
        "name": f"Componente objetivo: {name}",
        "type": component_type,
        "provider": "Multiplataforma",
        "service": service,
        "aspect": "Control esperado",
        "resource_id": "No aplica — componente esperado de proceso o alcance",
        "identifier_type": "No aplica",
        "origin": "expected",
    }


def display_component_service(collector: str, product: str) -> str:
    if product:
        return {
            "weblogic": "Oracle WebLogic Server",
            "ohs": "Oracle HTTP Server",
            "oam": "Oracle Access Manager",
            "oaa": "Oracle Advanced Authentication",
            "oag": "Oracle API Gateway",
            "webgate": "Oracle WebGate",
            "avdf": "Oracle Audit Vault and Database Firewall",
        }.get(product.strip().lower(), product)
    if collector.startswith("oci."):
        service = collector.removeprefix("oci.")
        return {
            "api_gateway": "OCI API Gateway",
            "block_storage": "OCI Block Storage",
            "logging_analytics": "OCI Logging Analytics",
            "object_storage": "OCI Object Storage",
            "oke": "Oracle Kubernetes Engine",
            "mysql": "MySQL HeatWave",
        }.get(service, "OCI " + service.replace("_", " ").title())
    return {
        "dbsat": "Oracle Database Security Assessment Tool (DBSAT)",
        "direct_sql": "Oracle Database (SQL directo)",
        "middleware": "Oracle Middleware",
    }.get(collector, collector)


def display_component_aspect(attribute: str) -> str:
    labels = {
        "audit_event": "Evento de auditoría",
        "audit_configuration": "Configuración de auditoría",
        "public_access": "Acceso público",
        "mfa_state": "Estado de MFA",
        "tls_configuration": "Configuración TLS",
        "backup_configuration": "Configuración de respaldo",
        "tde_encryption": "Cifrado TDE",
        "volume_encryption": "Cifrado de volumen",
    }
    normalized = attribute.split(":")[-1]
    return labels.get(normalized, normalized.replace("_", " ").replace("-", " ").capitalize())


def opaque_component_value(value: str) -> bool:
    normalized = value.strip().lower()
    return bool(
        re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", normalized)
        or normalized.startswith("ocid1.")
        or normalized.startswith("[ocid")
        or "sha256:" in normalized
    )


def display_component_name(service: str, resource: str, attribute: str) -> str:
    opaque = opaque_component_value(resource)
    aspect = display_component_aspect(attribute)
    return f"{service} — {aspect}" if opaque or resource.lower() in {"unknown", "n/a"} else f"{service} — {resource} — {aspect}"


def display_identifier_type(resource: str, provider: str) -> str:
    if resource.strip().lower().startswith("ocid1."):
        return "OCID"
    if provider == "OCI":
        return "Identificador OCI"
    if provider == "On-Premises":
        return "Alias de destino"
    return "Identificador técnico"


def component_from_evidence(evidence: dict[str, Any]) -> dict[str, str]:
    source = evidence.get("source") if isinstance(evidence.get("source"), dict) else {}
    supplied = evidence.get("component") if isinstance(evidence.get("component"), dict) else {}
    collector = str(source.get("collector") or "collector")
    product = str(source.get("product") or "")
    resource = str(evidence.get("resource") or source.get("product") or collector)
    service = display_component_service(collector, product)
    aspect = display_component_aspect(str(evidence.get("attribute") or "configuración evaluada"))
    provider = str(supplied.get("provider") or provider_for_collector(collector))
    supplied_name = str(supplied.get("name") or "")
    supplied_service = str(supplied.get("service") or "")
    name = supplied_name if supplied_name and not opaque_component_value(supplied_name) else display_component_name(service, resource, str(evidence.get("attribute") or "configuración evaluada"))
    return {
        "id": str(supplied.get("id") or f"component-{evidence.get('id') or collector}"),
        "name": name,
        "type": str(supplied.get("type") or evidence.get("layer") or "application"),
        "provider": provider,
        "service": display_component_service(collector, product) if not supplied_service or opaque_component_value(supplied_service) else supplied_service,
        "aspect": str(supplied.get("aspect") or aspect),
        "resource_id": str(supplied.get("resource_id") or resource),
        "identifier_type": str(supplied.get("identifier_type") or display_identifier_type(resource, provider)),
        "origin": "observed",
    }


def parse_controls(repo: Path) -> dict[str, dict[str, Any]]:
    controls: dict[str, dict[str, Any]] = {}
    for line in (repo / "references" / "controls.md").read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 2:
            match = re.fullmatch(r"`([a-z][a-z0-9-]+)`", cells[0])
            if match:
                control_id = match.group(1)
                full_catalog_row = len(cells) >= 6
                evidence_expected = cells[5] if full_catalog_row else "evidencia verificable del responsable y de la implementación"
                controls[control_id] = {
                    "id": control_id,
                    "name": cells[1],
                    "frameworks": [],
                    "expected_reference": {
                        "requirement": expected_requirement(control_id, cells[1], evidence_expected),
                        "legal_21719": cells[2] if full_catalog_row else "No definido en el catálogo",
                        "legal_21595": cells[3] if full_catalog_row else "No definido en el catálogo",
                        "crosswalk": cells[4] if full_catalog_row else "No definido en el catálogo",
                        "evidence_expected": evidence_expected,
                    },
                }
    if not controls:
        die("no controls were parsed from references/controls.md")

    for pack_file in sorted((repo / "packs").glob("*/pack.md")):
        framework = pack_file.parent.name
        ids = set(re.findall(r"`([a-z][a-z0-9-]+)`", pack_file.read_text(encoding="utf-8")))
        for control_id in sorted(ids & controls.keys()):
            controls[control_id]["frameworks"].append(framework)
    return controls


def corpus_manifest(repo: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for area in ("packs", "references", "sources"):
        result[area] = [str(path.relative_to(repo)) for path in sorted((repo / area).rglob("*")) if path.is_file()]
    return result


def product_for(control_id: str, as_of: str) -> dict[str, Any]:
    if control_id in {"sec-logs", "sec-monitoring", "inc-brechas"}:
        name = "OCI Audit, Logging, Monitoring, Events, and Notifications"
        why = "Centraliza telemetría, alertas, enrutamiento y los insumos para investigar eventos de seguridad."
        enablement = "Habilite los logs de servicio y aplicación necesarios, alarmas, reglas de eventos, tópicos, retención y rutas de escalamiento probadas."
        basis = "Ingesta y retención mensual de logs, consultas, métricas, eventos y destinos de notificación"
    elif control_id in {"sec-secrets", "sec-rest", "data-pseudonym"}:
        name = "OCI Vault and Key Management"
        why = "Gestiona claves de cifrado y secretos con operaciones controladas por IAM y trazabilidad de auditoría."
        enablement = "Cree políticas para bóvedas, claves y secretos; migre y rote valores; y alerte sobre operaciones privilegiadas."
        basis = "Modo de protección de bóveda, versiones de claves y secretos, y operaciones criptográficas"
    elif control_id in {"sec-mfa", "sec-tenant", "sec-passwords"}:
        name = "OCI IAM Identity Domains"
        why = "Soporta ciclo de vida de identidades, MFA, federación y acceso administrativo basado en políticas."
        enablement = "Seleccione la edición del dominio de identidad, fuerce MFA y reglas de ciclo de vida, y revise las políticas de mínimo privilegio."
        basis = "Edición del dominio de identidad, usuarios activos y capacidades de identidad empresarial"
    elif control_id in {"sec-tls"}:
        name = "OCI Certificates, Load Balancer, WAF, and API Gateway"
        why = "Proporciona ciclo de vida administrado de certificados y exigencia de TLS en los puntos de entrada compatibles."
        enablement = "Emita o importe certificados, asígnelos a cada listener o gateway, aplique la política TLS y pruebe la renovación."
        basis = "Operaciones de certificados, forma y ancho de banda del balanceador, solicitudes del gateway y uso de WAF"
    elif control_id in {"sec-backups"}:
        name = "OCI Backup services and Full Stack Disaster Recovery"
        why = "Soporta protección administrada, retención, orquestación de recuperación y patrones entre regiones."
        enablement = "Defina políticas a partir de objetivos de recuperación, proteja cada almacén, aísle copias y ejecute ejercicios de restauración."
        basis = "Capacidad protegida, almacenamiento de respaldo, operaciones, retención y región de destino"
    elif control_id.startswith("data-"):
        name = "Oracle Data Safe y OCI Data Catalog (capacidades candidatas)"
        why = "Puede apoyar la evaluación de seguridad de bases de datos, el descubrimiento de datos sensibles, enmascaramiento, auditoría y catalogación."
        enablement = "Confirme los almacenes aplicables, registre los destinos compatibles, clasifique los datos e integre hallazgos en los flujos de gobierno."
        basis = "Cobertura de bases de datos o servicios, uso de catálogo, región y capacidades seleccionadas"
    elif control_id.startswith("gov-") or control_id == "ctrl-interno":
        name = "Oracle Fusion Cloud Risk Management (opcional; el proceso documentado sigue siendo obligatorio)"
        why = "Puede apoyar flujos de riesgo, control de acceso y gobierno, pero no reemplaza políticas, responsables ni evidencia verificable."
        enablement = "Defina primero los responsables y el proceso; después evalúe la suscripción, los flujos, integraciones y retención de evidencia."
        basis = "Suscripción, módulos, usuarios, implementación y alcance de integración"
    else:
        name = "Cambio de proceso o aplicación; ningún producto OCI único cierra este control"
        why = "El control depende principalmente del gobierno documentado o del comportamiento de la carga de trabajo."
        enablement = "Asigne un responsable, defina criterios de aceptación, implemente el cambio de proceso o aplicación y recolecte evidencia operativa."
        basis = "Esfuerzo de implementación, apoyo legal y de procesos, ingeniería, capacitación y operación continua"
    return {
        "name": name,
        "why": why,
        "enablement": enablement,
        "cost": {
            "estimate": "Quote required",
            "currency": "USD",
            "as_of": as_of,
            "pricing_basis": basis,
            "assumptions": ["No workload sizing or negotiated discount was supplied", "Use the target region and current Oracle rate card"],
            "source": PRICE_LIST,
        },
    }


def default_status(signals: list[str]) -> str:
    normalized = {str(signal).strip().lower() for signal in signals}
    if normalized & {"fail", "failed", "noncompliant", "absent", "disabled", "misconfigured", "unknown"}:
        return "fail"
    if normalized & {"pass", "passed", "compliant"}:
        return "pass"
    if normalized & {"partial", "present", "enabled"}:
        return "partial"
    return "fail"


def compliance_percent(status: str) -> int:
    """Conservative score used consistently by cards and the risk matrix."""
    return {"pass": 100, "partial": 50, "fail": 0}.get(status, 0)


def default_rationale(status: str, evidence_count: int) -> str:
    if status == "partial":
        return f"{evidence_count} registro(s) del colector indican recursos o capacidades relacionadas, pero no acreditan el cumplimiento completo del control."
    if status == "pass":
        return f"{evidence_count} registro(s) del colector presentan una señal explícita de cumplimiento; confirme el alcance y la efectividad operativa."
    if status == "fail":
        if evidence_count == 0:
            return "No se proporcionó la evidencia requerida; bajo la política de evaluación, este control se considera no conforme."
        return f"{evidence_count} registro(s) del colector presentan una señal explícita negativa que contradice el control."
    return "No se proporcionó la evidencia requerida; bajo la política de evaluación, este control se considera no conforme."


def collector_error_summary(errors: Any) -> list[dict[str, str]]:
    if isinstance(errors, list):
        rows = errors
    elif isinstance(errors, dict):
        rows = [{"area": str(key), "detail": value} for key, value in errors.items()]
    else:
        return []
    result = []
    for row in rows:
        if isinstance(row, dict):
            area = row.get("service") or row.get("collector") or row.get("area") or "collector"
            category = row.get("type") or row.get("category") or row.get("status") or "coverage error"
            result.append({"area": str(area), "category": str(category)})
        else:
            result.append({"area": "collector", "category": type(row).__name__})
    return result


def collector_limitations(bundle: dict[str, Any]) -> list[dict[str, str]]:
    result = collector_error_summary(bundle.get("errors"))
    coverage = bundle.get("coverage") if isinstance(bundle.get("coverage"), dict) else {}
    for warning in coverage.get("warnings", []):
        result.append({"area": "coverage", "category": str(warning)})
    for skipped in coverage.get("services_skipped", []):
        if isinstance(skipped, dict):
            service = str(skipped.get("service") or "collector")
            reason = str(skipped.get("reason") or "service skipped")
            result.append({"area": service, "category": reason})
    return result


def provider_for_collector(collector: str) -> str:
    normalized = collector.strip().lower()
    if normalized.startswith("oci.") or normalized == "oci":
        return "OCI"
    if normalized in {"dbsat", "direct_sql", "middleware"} or normalized.startswith("onprem"):
        return "On-Premises"
    return "Other"


def display_onprem_product(product: str, collector: str) -> str:
    normalized = product.strip().lower()
    if normalized in ONPREM_PRODUCT_NAMES:
        return ONPREM_PRODUCT_NAMES[normalized]
    if product.strip():
        return product.strip().replace("_", " ").title()
    if collector == "middleware":
        return "Oracle Middleware"
    if collector in {"dbsat", "direct_sql"}:
        return "Oracle Database"
    return collector.replace("_", " ").title()


def validate_evidence_ref(ref: str, ids: set[str], bundle_root: Path, repo: Path) -> None:
    if ref in ids:
        return
    normalized = PurePosixPath(ref)
    if normalized.is_absolute() or ".." in normalized.parts:
        die(f"assessment contains unsafe evidence reference: {sanitize_display_text(ref)!r}")
    if normalized.parts and normalized.parts[0] == "raw" and bundle_root.joinpath(*normalized.parts).is_file():
        return
    if normalized.parts and normalized.parts[0] in {"packs", "references", "sources"} and repo.joinpath(*normalized.parts).is_file():
        return
    die(f"assessment evidence reference does not exist: {sanitize_display_text(ref)!r}")


def apply_overlay(
    data: dict[str, Any], overlay: dict[str, Any], evidence_ids: set[str], bundle_root: Path, repo: Path
) -> None:
    if overlay.get("schema") != 1:
        die("assessment schema must equal 1")
    if "assessed_product" in overlay:
        data["assessed_product"] = str(overlay["assessed_product"]).strip() or data["assessed_product"]
    if "scope_notes" in overlay:
        data["scope_notes"] = str(overlay["scope_notes"])
    raw_updates = overlay.get("controls", {})
    if not isinstance(raw_updates, dict):
        die("assessment controls must be an object keyed by control ID")
    # Accept the companion analysis format produced by the collector workflow:
    # {"controls": {"summary": {...}, "items": {"control-id":
    # {"status": ..., "finding": ...}}}}.  The summary is informational;
    # individual items are translated into this reporter's reviewed-overlay
    # contract.  This keeps assessment input portable without weakening the
    # stricter validation below.
    if "items" in raw_updates:
        legacy_items = raw_updates["items"]
        if not isinstance(legacy_items, dict):
            die("assessment controls.items must be an object keyed by control ID")
        updates = {}
        for control_id, legacy_update in legacy_items.items():
            if not isinstance(legacy_update, dict):
                die(f"assessment contains an invalid control: {control_id!r}")
            update = dict(legacy_update)
            if "finding" in update and "rationale" not in update:
                update["rationale"] = str(update["finding"])
            updates[control_id] = update
    else:
        updates = raw_updates
    controls = {item["id"]: item for item in data["controls"]}
    required_cost = {"estimate", "currency", "as_of", "pricing_basis", "assumptions", "source"}
    for control_id, update in updates.items():
        if control_id not in controls or not isinstance(update, dict):
            die(f"assessment contains an invalid control: {control_id!r}")
        if "status" in update and update["status"] not in ACCEPTED_INPUT_STATUSES:
            die(f"assessment control {control_id} has invalid status")
        refs = update.get("evidence_refs", controls[control_id]["evidence_refs"])
        if not isinstance(refs, list) or not all(isinstance(ref, str) for ref in refs):
            die(f"assessment control {control_id}.evidence_refs must be an array of strings")
        for ref in refs:
            validate_evidence_ref(ref, evidence_ids, bundle_root, repo)
        if "oracle_product" in update:
            product = update["oracle_product"]
            if not isinstance(product, dict) or not isinstance(product.get("cost"), dict):
                die(f"assessment control {control_id}.oracle_product must include cost")
            missing = required_cost - product["cost"].keys()
            if missing or not isinstance(product["cost"].get("assumptions"), list):
                die(f"assessment control {control_id} cost is missing: {', '.join(sorted(missing))}")
        if "remediation_steps" in update:
            steps = update["remediation_steps"]
            if not isinstance(steps, list) or not steps or not all(isinstance(step, str) and step.strip() for step in steps):
                die(f"assessment control {control_id}.remediation_steps must be a non-empty array of strings")
        if "status" in update:
            if update["status"] == "unknown":
                update["status"] = "fail"
            controls[control_id]["status"] = update["status"]
            controls[control_id]["evidence_state"] = (
                "not_evidenced" if not refs else "reviewed"
            )
        for key in ("rationale", "evidence_refs", "remediation", "remediation_steps", "oracle_product"):
            if key in update:
                controls[control_id][key] = update[key]


def recompute_frameworks(data: dict[str, Any]) -> None:
    by_framework: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in data["controls"]:
        if control["status"] == "unknown":
            control["status"] = "fail"
            control["evidence_state"] = "not_evidenced"
        control["compliance_percent"] = compliance_percent(control["status"])
        for framework in control["frameworks"]:
            by_framework[framework].append(control)
    frameworks = []
    for name, controls in sorted(by_framework.items()):
        counts = Counter(control["status"] for control in controls)
        required = len(controls)
        score = (counts["pass"] + 0.5 * counts["partial"]) / required if required else 0.0
        evidenced = sum(1 for control in controls if control["evidence_refs"])
        frameworks.append({
            "id": name,
            "required": required,
            "score": round(score, 4),
            "coverage": round(evidenced / required, 4) if required else 0.0,
            "counts": {status: counts[status] for status in STATUSES},
        })
    data["frameworks"] = frameworks
    data["status_counts"] = dict(Counter(control["status"] for control in data["controls"]))


def has_reviewed_oracle_component(control: dict[str, Any]) -> bool:
    """True when the collector actually observed an Oracle/OCI component for the control."""
    for evidence in control.get("evidence", []):
        if provider_for_collector(str(evidence.get("collector", ""))) in {"OCI", "On-Premises"}:
            return True
    return False


def action_category(control: dict[str, Any]) -> str:
    """Classify a control's remediation track.

    A control is product-enabled (Track A) only when an Oracle product can
    materially mitigate it *and* the collector reviewed at least one Oracle
    component for it. A product-mitigable control with no reviewed Oracle
    component is an evidence/process gap and belongs to the process track
    (Track B); the product track must never carry an entry without a reviewed
    Oracle component.
    """
    product_mitigable = {
        "sec-tls",
        "sec-rest",
        "sec-mfa",
        "sec-logs",
        "sec-secrets",
        "sec-backups",
        "sec-monitoring",
        "data-pseudonym",
    }
    if control["id"] in product_mitigable and has_reviewed_oracle_component(control):
        return "product"
    return "process"


def build_component_assessments(controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    for control in controls:
        for component in control["components"]:
            key = (
                component["provider"],
                component["service"],
                component["name"],
                component["type"],
                component["aspect"],
                component["resource_id"],
            )
            row = grouped.setdefault(
                key,
                {
                    **component,
                    "component_ids": set(),
                    "controls": {},
                    "evidence_ids": set(),
                    "evidence_signals": {},
                    "origin": component["origin"],
                },
            )
            row["component_ids"].add(component["id"])
            row["controls"][control["id"]] = {
                "id": control["id"],
                "name": control["name"],
                "status": control["status"],
                "compliance_percent": control["compliance_percent"],
            }
            if component["origin"] == "observed":
                row["origin"] = "observed"
            for evidence in control["evidence"]:
                if evidence["component"]["id"] == component["id"] and evidence["id"]:
                    row["evidence_ids"].add(evidence["id"])
                    row["evidence_signals"][evidence["id"]] = evidence["signal"]

    assessments = []
    status_rank = {"fail": 0, "partial": 1, "pass": 2}
    for row in grouped.values():
        component_controls = sorted(row["controls"].values(), key=lambda item: item["id"])
        status = default_status(list(row["evidence_signals"].values()))
        percent = compliance_percent(status)
        assessments.append({
            "id": sorted(row["component_ids"])[0],
            "name": row["name"],
            "type": row["type"],
            "provider": row["provider"],
            "service": row["service"],
            "aspect": row["aspect"],
            "resource_id": row["resource_id"],
            "identifier_type": row["identifier_type"],
            "origin": row["origin"],
            "status": status,
            "compliance_percent": percent,
            "control_ids": [item["id"] for item in component_controls],
            "controls": component_controls,
            "evidence_count": len(row["evidence_ids"]),
        })
    return sorted(assessments, key=lambda item: (status_rank[item["status"]], item["provider"], item["service"], item["name"]))


def build_action_catalog(controls: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    catalog: dict[str, list[dict[str, Any]]] = {"product": [], "process": []}
    for control in controls:
        category = action_category(control)
        control["action_category"] = category
        if control["status"] == "pass":
            continue
        catalog[category].append({
            "control_id": control["id"],
            "control_name": control["name"],
            "category": category,
            "status": control["status"],
            "compliance_percent": control["compliance_percent"],
            "components": control["components"],
            "action": control["remediation"],
            "expected_reference": control["expected_reference"],
            "evidence_refs": control["evidence_refs"],
            "oracle_product": control["oracle_product"] if category == "product" else None,
        })
    return catalog


def track_scores(controls: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Score the product-enabled and process tracks independently."""
    tracks: dict[str, dict[str, Any]] = {}
    for category in ("product", "process"):
        rows = [control for control in controls if control.get("action_category") == category]
        required = len(rows)
        counts = Counter(control["status"] for control in rows)
        score = (counts["pass"] + 0.5 * counts["partial"]) / required if required else 0.0
        evidenced = sum(1 for control in rows if control["evidence_refs"])
        tracks[category] = {
            "required": required,
            "score": round(score, 4),
            "coverage": round(evidenced / required, 4) if required else 0.0,
            "counts": {status: counts[status] for status in STATUSES},
            "control_ids": [control["id"] for control in rows],
        }
    return tracks


def recompute_derived_views(data: dict[str, Any]) -> None:
    recompute_frameworks(data)
    data["component_assessments"] = build_component_assessments(data["controls"])
    data["action_catalog"] = build_action_catalog(data["controls"])
    data["track_scores"] = track_scores(data["controls"])


def build_data(bundle: dict[str, Any], controls: dict[str, dict[str, Any]], manifest: dict[str, list[str]]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    by_control: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for evidence in bundle["evidence"]:
        component = component_from_evidence(evidence)
        item = {
            "id": str(evidence.get("id", "")),
            "signal": str(evidence.get("signal", "unknown")),
            "confidence": str(evidence.get("confidence", "unknown")),
            "resource": str(evidence.get("resource", "unknown")),
            "collector": str((evidence.get("source") or {}).get("collector", "unknown")),
            "product": str((evidence.get("source") or {}).get("product", "")),
            "layer": str(evidence.get("layer", "unknown")),
            "ref": str((evidence.get("source") or {}).get("ref", "")),
            "component": component,
        }
        for control_id in evidence.get("control_ids", []):
            if control_id in controls:
                by_control[control_id].append(item)

    control_rows = []
    for control_id, meta in sorted(controls.items()):
        evidence = by_control.get(control_id, [])
        components = list({item["component"]["id"]: item["component"] for item in evidence}.values()) or [expected_component(control_id)]
        status = default_status([item["signal"] for item in evidence])
        refs = list(dict.fromkeys([item["id"] for item in evidence if item["id"]] + [item["ref"] for item in evidence if item["ref"]]))
        control_rows.append({
            **meta,
            "status": status,
            "compliance_percent": compliance_percent(status),
            "evidence_state": "not_evidenced" if not evidence else "observed",
            "rationale": default_rationale(status, len(evidence)),
            "evidence_refs": refs,
            "evidence": evidence,
            "components": components,
            "remediation": REMEDIATIONS.get(control_id, "Asigne un responsable, reúna la evidencia faltante, defina criterios de aceptación, implemente el control y verifique su efectividad operativa."),
            "remediation_steps": list(REMEDIATION_STEPS.get(control_id, GENERIC_REMEDIATION_STEPS)),
            "oracle_product": product_for(control_id, now.date().isoformat()),
        })

    inventory_counts = Counter(str(item.get("type", "unknown")) for item in bundle["inventory"] if isinstance(item, dict))
    observed = [{"type": key, "name": PRODUCT_NAMES.get(key, key.replace("_", " ").title()), "count": count} for key, count in sorted(inventory_counts.items())]
    observed_names = {item["name"] for item in observed}
    evidence_products: dict[tuple[str, str], set[str]] = defaultdict(set)
    collectors: set[str] = set()
    layers = {
        str(item.get("layer"))
        for item in bundle["inventory"]
        if isinstance(item, dict) and item.get("layer")
    }
    for evidence in bundle["evidence"]:
        if not isinstance(evidence, dict):
            continue
        source = evidence.get("source") if isinstance(evidence.get("source"), dict) else {}
        collector = str(source.get("collector") or "unknown")
        collectors.add(collector)
        if evidence.get("layer"):
            layers.add(str(evidence["layer"]))
        provider = provider_for_collector(collector)
        if provider == "On-Premises":
            name = display_onprem_product(str(source.get("product") or ""), collector)
            evidence_products[(provider, name)].add(str(evidence.get("resource") or evidence.get("id") or "resource"))
    for (provider, name), resources in sorted(evidence_products.items()):
        if name not in observed_names:
            observed.append({"type": name.lower().replace(" ", "_"), "name": name, "count": len(resources), "provider": provider})
    providers = {provider_for_collector(name) for name in collectors}
    if bundle["inventory"] and any(
        isinstance(item, dict) and item.get("region") for item in bundle["inventory"]
    ):
        providers.add("OCI")
    providers.discard("Other")
    regions = sorted(
        {
            str(item.get("region"))
            for item in bundle["inventory"]
            if isinstance(item, dict) and item.get("region")
        }
    )
    run = bundle.get("run") if isinstance(bundle.get("run"), dict) else {}
    data = {
        "schema": 1,
        "generated_at": now.isoformat(),
        "disclaimer": DISCLAIMER,
        "assessment_kind": "Evaluación de preparación basada en evidencia",
        "assessed_product": str(run.get("name") or run.get("id") or "Carga de trabajo evaluada por el colector"),
        "scope_notes": "La evidencia del colector cubre únicamente la infraestructura observable y los destinos on-premises configurados. El comportamiento de la aplicación, los contratos, el gobierno y las conclusiones legales requieren evidencia separada.",
        "bundle": {
            "schema": bundle.get("schema"),
            "collector_version": bundle.get("collector_version"),
            "generated_at": bundle.get("generated_at"),
            "inventory_count": len(bundle["inventory"]),
            "evidence_count": len(bundle["evidence"]),
            "regions": regions,
            "providers": sorted(providers) or ["Not identified"],
            "layers": sorted(layers),
            "collectors": sorted(collectors),
            "observed_resource_count": len(
                {
                    str(item.get("resource"))
                    for item in bundle["evidence"]
                    if isinstance(item, dict) and item.get("resource")
                }
            ),
        },
        "observed_products": observed,
        "collector_errors": collector_limitations(bundle),
        "corpus": {key: {"count": len(paths), "files": paths} for key, paths in manifest.items()},
        "controls": control_rows,
        "frameworks": [],
    }
    recompute_derived_views(data)
    return data


def write_html(data: dict[str, Any], destination: Path) -> None:
    encoded = json.dumps(data, ensure_ascii=False).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    title = html.escape(data["assessed_product"])
    template_path = Path(__file__).resolve().parent.parent / "assets" / "report-template.html"
    if template_path.is_file():
        document = template_path.read_text(encoding="utf-8")
        document = document.replace("__REPORT_TITLE__", title).replace("__REPORT_DATA__", encoded)
        destination.write_text(document, encoding="utf-8")
        return
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Collector assessment — {title}</title>
<style>
:root{{--bg:#f4f7fb;--panel:#fff;--text:#162033;--muted:#5d6b82;--line:#dce3ee;--accent:#3659d9;--pass:#16835b;--partial:#ad6800;--fail:#bd2c2c;--unknown:#687385}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
header{{background:linear-gradient(125deg,#15254a,#3659d9);color:#fff;padding:34px max(24px,calc((100% - 1240px)/2))}}header h1{{margin:0 0 7px;font-size:30px}}header p{{margin:3px 0;color:#dfe7ff}}
main{{max-width:1240px;margin:auto;padding:24px}}h2{{font-size:20px;margin:28px 0 12px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}}
.card,.control{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;box-shadow:0 2px 8px #21314d0b}}.metric{{font-size:27px;font-weight:750}}.muted{{color:var(--muted)}}
.bar{{height:8px;border-radius:5px;background:#e6eaf2;overflow:hidden;margin:10px 0}}.bar span{{display:block;height:100%;background:var(--accent)}}
.toolbar{{display:flex;gap:10px;flex-wrap:wrap;position:sticky;top:0;background:var(--bg);padding:10px 0;z-index:2}}input,select{{border:1px solid var(--line);border-radius:8px;padding:10px;background:#fff;color:var(--text)}}input{{flex:1;min-width:220px}}
.controls{{display:grid;gap:10px}}.control-head{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}.control h3{{font-size:16px;margin:0;flex:1}}.badge{{padding:3px 9px;border-radius:999px;color:#fff;font-size:12px;text-transform:uppercase;font-weight:700}}.pass{{background:var(--pass)}}.partial{{background:var(--partial)}}.fail{{background:var(--fail)}}.unknown{{background:var(--unknown)}}
details{{margin-top:10px}}summary{{cursor:pointer;color:var(--accent);font-weight:650}}.detail-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:14px;margin-top:12px}}ul{{padding-left:20px}}code{{word-break:break-word}}.notice{{border-left:4px solid var(--partial)}}footer{{margin-top:30px;padding:20px;border-top:1px solid var(--line);color:var(--muted)}}
@media(prefers-color-scheme:dark){{:root{{--bg:#101521;--panel:#171e2d;--text:#edf2fc;--muted:#a8b3c6;--line:#2c374c}}input,select{{background:#171e2d;color:#edf2fc}}.bar{{background:#2c374c}}}}
</style></head><body>
<header><h1>Collector compliance assessment</h1><p id="product"></p><p>Evidence-based readiness view · not a legal certification</p></header>
<main><section id="summary" class="grid"></section><h2>Framework readiness</h2><section id="frameworks" class="grid"></section>
<h2>Observed products and technologies</h2><section id="products" class="grid"></section><h2>Collector coverage limitations</h2><section id="errors"></section>
<h2>Controls</h2><div class="toolbar"><input id="search" type="search" placeholder="Search control, remediation, or product"><select id="status"><option value="all">All statuses</option><option>pass</option><option>partial</option><option>fail</option></select><select id="framework"><option value="all">All frameworks</option></select></div><p id="shown" class="muted"></p><section id="controls" class="controls"></section>
<footer id="disclaimer"></footer></main><script id="report-data" type="application/json">{encoded}</script>
<script>
const d=JSON.parse(document.getElementById('report-data').textContent);const q=s=>document.querySelector(s);const el=(tag,text,cls)=>{{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n}};
q('#product').textContent=d.assessed_product+' — '+d.scope_notes;q('#disclaimer').textContent=d.disclaimer;
const cards=[['Inventory',d.bundle.inventory_count],['Evidence records',d.bundle.evidence_count],['Regions',d.bundle.regions.join(', ')||'not recorded'],['Controls',d.controls.length],['Non-compliant',d.status_counts.fail||0]];for(const [k,v] of cards){{const c=el('div',undefined,'card');c.append(el('div',v,'metric'),el('div',k,'muted'));q('#summary').append(c)}}
for(const f of d.frameworks){{const c=el('div',undefined,'card');c.append(el('strong',f.id),el('div',Math.round(f.score*100)+'% readiness','metric'));const b=el('div',undefined,'bar');const s=el('span');s.style.width=(f.score*100)+'%';b.append(s);c.append(b,el('div',`pass ${{f.counts.pass}} · partial ${{f.counts.partial}} · fail ${{f.counts.fail}} · unknown ${{f.counts.unknown}}`,'muted'),el('div','Evidence coverage '+Math.round(f.coverage*100)+'%','muted'));q('#frameworks').append(c);q('#framework').append(el('option',f.id))}}
for(const p of d.observed_products){{const c=el('div',undefined,'card');c.append(el('strong',p.name),el('div',p.count+' observed resource(s)','muted'));q('#products').append(c)}}
if(!d.collector_errors.length)q('#errors').append(el('div','No collector coverage errors were recorded.','card'));else for(const x of d.collector_errors){{const c=el('div',undefined,'card notice');c.append(el('strong',x.area),el('div',x.category+' — coverage limitation, not a failed control','muted'));q('#errors').append(c)}}
function list(title,items){{const wrap=el('div');wrap.append(el('strong',title));const ul=el('ul');for(const x of items)ul.append(el('li',x));wrap.append(ul);return wrap}}
function draw(){{const term=q('#search').value.toLowerCase(),status=q('#status').value,fw=q('#framework').value;q('#controls').replaceChildren();const rows=d.controls.filter(c=>(status==='all'||c.status===status)&&(fw==='all'||c.frameworks.includes(fw))&&JSON.stringify([c.id,c.name,c.rationale,c.remediation,c.oracle_product.name]).toLowerCase().includes(term));q('#shown').textContent=rows.length+' of '+d.controls.length+' controls shown';for(const c of rows){{const card=el('article',undefined,'control');const head=el('div',undefined,'control-head');head.append(el('span',c.status,'badge '+c.status),el('h3',c.id+' — '+c.name),el('span',c.frameworks.join(', ')||'cross-framework','muted'));card.append(head,el('p',c.rationale));const details=el('details');details.append(el('summary','Evidence, remediation, product, and cost'));const grid=el('div',undefined,'detail-grid');grid.append(list('Evidence references',c.evidence_refs.length?c.evidence_refs:['None collected']),list('Remediation',[c.remediation]),list('Oracle/OCI candidate',[c.oracle_product.name,c.oracle_product.why,c.oracle_product.enablement]),list('Potential cost',[c.oracle_product.cost.estimate+' '+c.oracle_product.cost.currency+' (as of '+c.oracle_product.cost.as_of+')',c.oracle_product.cost.pricing_basis,...c.oracle_product.cost.assumptions,'Source: '+c.oracle_product.cost.source]));details.append(grid);card.append(details);q('#controls').append(card)}}}}
q('#search').addEventListener('input',draw);q('#status').addEventListener('change',draw);q('#framework').addEventListener('change',draw);draw();
</script></body></html>"""
    destination.write_text(document, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collector-output", required=True, help="Absolute collector run directory or supported archive")
    parser.add_argument("--repo-root", required=True, help="Absolute repository root containing packs/references/sources")
    parser.add_argument("--assessment", help="Optional absolute reviewed assessment overlay JSON")
    parser.add_argument("--output-dir", help="Optional absolute output directory")
    return parser.parse_args()


def require_absolute(value: str, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        die(f"{label} must be an absolute path")
    return path.resolve()


def main() -> int:
    args = parse_args()
    collector_input = require_absolute(args.collector_output, "collector output")
    repo = require_absolute(args.repo_root, "repository root")
    if not collector_input.exists():
        die(f"collector output does not exist: {collector_input}")
    validate_repo(repo)

    temp: tempfile.TemporaryDirectory[str] | None = None
    try:
        if collector_input.is_dir():
            bundle_path = find_bundle(collector_input)
            default_output = bundle_path.parent / "analysis" / "collector-assessment-report"
        elif collector_input.is_file():
            temp = tempfile.TemporaryDirectory(prefix="collector-assessment-")
            extracted = Path(temp.name)
            extract_archive(collector_input, extracted)
            bundle_path = find_bundle(extracted)
            default_output = collector_input.parent / f"{archive_stem(collector_input)}-analysis"
        else:
            die("collector output must be a regular directory or archive file")

        output = require_absolute(args.output_dir, "output directory") if args.output_dir else default_output
        bundle = load_json(bundle_path)
        validate_bundle(bundle)
        controls = parse_controls(repo)
        data = build_data(bundle, controls, corpus_manifest(repo))
        overlay = None
        if args.assessment:
            assessment_path = require_absolute(args.assessment, "assessment")
            overlay = load_json(assessment_path)
            evidence_ids = {str(item.get("id")) for item in bundle["evidence"] if isinstance(item, dict) and item.get("id")}
            apply_overlay(data, overlay, evidence_ids, bundle_path.parent, repo)
            recompute_derived_views(data)

        data = sanitize_for_display(data)
        safe_overlay = sanitize_for_display(overlay) if overlay is not None else None

        output.mkdir(parents=True, exist_ok=True)
        (output / "report-data.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        write_html(data, output / "report.html")
        if safe_overlay is not None:
            (output / "assessment.json").write_text(json.dumps(safe_overlay, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(output / "report.html")
        print(output / "report-data.json")
        return 0
    finally:
        if temp is not None:
            temp.cleanup()


if __name__ == "__main__":
    sys.exit(main())
