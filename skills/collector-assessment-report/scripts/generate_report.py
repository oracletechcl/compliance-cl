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
DISCLAIMER = "Informational technical assessment only; not legal advice or a certification of compliance."
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
    "sec-logs": "Define required audit events, enable service and application logs, set retention, restrict access, and test retrieval.",
    "sec-monitoring": "Define actionable signals, alarms, owners, escalation routes, and regularly test notification delivery.",
    "inc-brechas": "Document incident intake, triage, legal notification decisions, evidence preservation, exercises, and a breach register.",
    "sec-secrets": "Inventory secrets, move them to managed storage, rotate them, restrict policies, and monitor access.",
    "sec-backups": "Set recovery objectives, backup schedules and retention, use isolation where appropriate, and test restores.",
    "sec-tls": "Enforce supported TLS versions and managed certificates on every public and internal endpoint; test renewal.",
    "sec-rest": "Verify encryption at rest and key ownership for every store; document rotation and separation of duties.",
    "sec-mfa": "Require MFA for privileged and workforce identities, remove shared accounts, and test recovery procedures.",
    "sec-tenant": "Enforce tenant boundaries in IAM, network, storage, database, and application authorization; add isolation tests.",
    "data-derechos": "Implement authenticated rights intake, identity verification, deadline tracking, export, correction, deletion, and appeal handling.",
    "data-minimizacion": "Map each data element to a purpose and retention rule; stop collection and delete data without a justified need.",
    "data-info": "Publish a complete privacy notice tied to actual processing, recipients, retention, transfers, rights, and contact channels.",
    "data-eipd": "Run and approve an impact assessment before high-risk processing, then track residual risks and review triggers.",
    "gov-registro": "Maintain an owned processing/activity and risk inventory with systems, data, purposes, recipients, retention, and controls.",
    "gov-politicas": "Approve, publish, train on, and periodically review the required governance and privacy policies.",
}


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


def parse_controls(repo: Path) -> dict[str, dict[str, Any]]:
    controls: dict[str, dict[str, Any]] = {}
    for line in (repo / "references" / "controls.md").read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\| `([a-z][a-z0-9-]+)` \| ([^|]+) \|", line)
        if match:
            control_id, name = match.groups()
            controls[control_id] = {"id": control_id, "name": name.strip(), "frameworks": []}
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
        why = "Provides centralized telemetry, alerting, routing, and investigation inputs."
        enablement = "Enable required service/custom logs, alarms, event rules, topics, retention, and tested escalation routes."
        basis = "Monthly log ingestion and retention, queries, metrics, events, and notification destinations"
    elif control_id in {"sec-secrets", "sec-rest", "data-pseudonym"}:
        name = "OCI Vault and Key Management"
        why = "Manages encryption keys and secrets with IAM-controlled operations and auditability."
        enablement = "Create vault/key/secret policies, migrate values, rotate them, and alert on privileged operations."
        basis = "Vault protection mode, key versions, secret versions, and cryptographic operations"
    elif control_id in {"sec-mfa", "sec-tenant", "sec-passwords"}:
        name = "OCI IAM Identity Domains"
        why = "Supports identity lifecycle, MFA, federation, and policy-based administrative access."
        enablement = "Select an identity-domain edition, enforce MFA and lifecycle rules, and review least-privilege policies."
        basis = "Identity-domain edition, active users, and enterprise identity features"
    elif control_id in {"sec-tls"}:
        name = "OCI Certificates, Load Balancer, WAF, and API Gateway"
        why = "Provides managed certificate lifecycle and TLS enforcement at supported entry points."
        enablement = "Issue/import certificates, bind them to every listener/gateway, enforce TLS policy, and test renewal."
        basis = "Certificate operations, load-balancer shape/bandwidth, gateway requests, and WAF usage"
    elif control_id in {"sec-backups"}:
        name = "OCI Backup services and Full Stack Disaster Recovery"
        why = "Supports managed protection, retention, recovery orchestration, and cross-region patterns."
        enablement = "Define policies from recovery objectives, protect each store, isolate copies, and run restore exercises."
        basis = "Protected capacity, backup storage, operations, retention, and destination region"
    elif control_id.startswith("data-"):
        name = "Oracle Data Safe and OCI Data Catalog (candidate capabilities)"
        why = "Can support database security assessment, sensitive-data discovery, masking, audit, and cataloging."
        enablement = "Confirm applicable data stores, register supported targets, classify data, and integrate findings into governance workflows."
        basis = "Target database/service coverage, catalog usage, region, and selected capabilities"
    elif control_id.startswith("gov-") or control_id == "ctrl-interno":
        name = "Oracle Fusion Cloud Risk Management (optional); documented process remains required"
        why = "May support risk, access-control, and governance workflows but cannot replace accountable policies and evidence."
        enablement = "Define owners and process first; then evaluate subscription fit, workflows, integrations, and evidence retention."
        basis = "Subscription, modules, users, implementation, and integration scope"
    else:
        name = "Process or application change; no single OCI product closes this control"
        why = "The control depends primarily on documented governance or workload behavior."
        enablement = "Assign an owner, define acceptance criteria, implement the process/application change, and collect operating evidence."
        basis = "Implementation effort, legal/process support, engineering, training, and ongoing operation"
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
    if normalized & {"fail", "failed", "noncompliant", "absent", "disabled"}:
        return "fail"
    if normalized & {"pass", "passed", "compliant"}:
        return "pass"
    if normalized & {"partial", "present", "enabled"}:
        return "partial"
    return "fail"


def default_rationale(status: str, evidence_count: int) -> str:
    if status == "partial":
        return f"{evidence_count} collector record(s) indicate related resources or capabilities, but do not prove the complete control."
    if status == "pass":
        return f"{evidence_count} collector record(s) carry an explicit passing signal; confirm scope and operating effectiveness."
    if status == "fail":
        if evidence_count == 0:
            return "Required evidence was not supplied; under the assessment policy this control is not compliant."
        return f"{evidence_count} collector record(s) carry an explicit negative signal that contradicts the control."
    return "Required evidence was not supplied; under the assessment policy this control is not compliant."


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
    updates = overlay.get("controls", {})
    if not isinstance(updates, dict):
        die("assessment controls must be an object keyed by control ID")
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
        if "status" in update:
            if update["status"] == "unknown":
                update["status"] = "fail"
            controls[control_id]["status"] = update["status"]
            controls[control_id]["evidence_state"] = (
                "not_evidenced" if not refs else "reviewed"
            )
        for key in ("rationale", "evidence_refs", "remediation", "oracle_product"):
            if key in update:
                controls[control_id][key] = update[key]


def recompute_frameworks(data: dict[str, Any]) -> None:
    by_framework: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in data["controls"]:
        if control["status"] == "unknown":
            control["status"] = "fail"
            control["evidence_state"] = "not_evidenced"
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


def build_data(bundle: dict[str, Any], controls: dict[str, dict[str, Any]], manifest: dict[str, list[str]]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    by_control: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for evidence in bundle["evidence"]:
        item = {
            "id": str(evidence.get("id", "")),
            "signal": str(evidence.get("signal", "unknown")),
            "confidence": str(evidence.get("confidence", "unknown")),
            "resource": str(evidence.get("resource", "unknown")),
            "collector": str((evidence.get("source") or {}).get("collector", "unknown")),
            "product": str((evidence.get("source") or {}).get("product", "")),
            "layer": str(evidence.get("layer", "unknown")),
            "ref": str((evidence.get("source") or {}).get("ref", "")),
        }
        for control_id in evidence.get("control_ids", []):
            if control_id in controls:
                by_control[control_id].append(item)

    control_rows = []
    for control_id, meta in sorted(controls.items()):
        evidence = by_control.get(control_id, [])
        status = default_status([item["signal"] for item in evidence])
        refs = list(dict.fromkeys([item["id"] for item in evidence if item["id"]] + [item["ref"] for item in evidence if item["ref"]]))
        control_rows.append({
            **meta,
            "status": status,
            "evidence_state": "not_evidenced" if not evidence else "observed",
            "rationale": default_rationale(status, len(evidence)),
            "evidence_refs": refs,
            "evidence": evidence,
            "remediation": REMEDIATIONS.get(control_id, "Assign an owner, gather the missing evidence, define acceptance criteria, implement the control, and verify operating effectiveness."),
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
        "assessment_kind": "Evidence-based readiness assessment",
        "assessed_product": str(run.get("name") or run.get("id") or "Collector-scoped workload"),
        "scope_notes": "Collector evidence covers observable infrastructure and configured on-premises targets only. Application behavior, contracts, governance, and legal conclusions require separate evidence.",
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
    recompute_frameworks(data)
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
<h2>Observed OCI products</h2><section id="products" class="grid"></section><h2>Collector coverage limitations</h2><section id="errors"></section>
<h2>Controls</h2><div class="toolbar"><input id="search" type="search" placeholder="Search control, remediation, or product"><select id="status"><option value="all">All statuses</option><option>pass</option><option>partial</option><option>fail</option><option>unknown</option></select><select id="framework"><option value="all">All frameworks</option></select></div><p id="shown" class="muted"></p><section id="controls" class="controls"></section>
<footer id="disclaimer"></footer></main><script id="report-data" type="application/json">{encoded}</script>
<script>
const d=JSON.parse(document.getElementById('report-data').textContent);const q=s=>document.querySelector(s);const el=(tag,text,cls)=>{{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n}};
q('#product').textContent=d.assessed_product+' — '+d.scope_notes;q('#disclaimer').textContent=d.disclaimer;
const cards=[['Inventory',d.bundle.inventory_count],['Evidence records',d.bundle.evidence_count],['Regions',d.bundle.regions.join(', ')||'not recorded'],['Controls',d.controls.length],['Unknown',d.status_counts.unknown||0]];for(const [k,v] of cards){{const c=el('div',undefined,'card');c.append(el('div',v,'metric'),el('div',k,'muted'));q('#summary').append(c)}}
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
            recompute_frameworks(data)

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
