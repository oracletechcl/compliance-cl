from __future__ import annotations

from pathlib import Path


COLLECTOR_ROOT = Path(__file__).resolve().parents[1]
README = COLLECTOR_ROOT / "README.md"
CONFIG_ROOT = COLLECTOR_ROOT / "configs"
CONFIG_README = CONFIG_ROOT / "README.md"

REQUIRED_PRODUCTS = {
    "DBSAT",
    "Direct SQL",
    "WebLogic",
    "Oracle HTTP Server (OHS)",
    "Oracle Access Manager (OAM)",
    "Oracle Advanced Authentication (OAA)",
    "WebGate",
    "Oracle API Gateway on-premises (OAG)",
    "Audit Vault and Database Firewall (AVDF)",
    "OCI IAM",
    "Cloud Guard",
    "Security Zones",
    "OCI Vault/KMS",
    "OCI Data Safe",
    "OCI Database",
    "GoldenGate",
    "MySQL HeatWave",
    "OCI Database with PostgreSQL",
    "NoSQL Database Cloud",
    "OCI Compute",
    "Block/Boot Volume",
    "Oracle Kubernetes Engine (OKE)",
    "Object Storage",
    "OCI Functions",
    "Container Instances",
    "VCN/Networking",
    "OCI WAF",
    "Network Firewall",
    "Load Balancer",
    "OCI Bastion",
    "OCI Certificates",
    "OCI API Gateway",
    "OCI Audit",
    "OCI Logging",
    "Logging Analytics",
    "OCI Monitoring",
    "OCI Events",
    "OCI Notifications",
    "Threat Intelligence",
    "Full Stack Disaster Recovery",
}


def test_main_readme_indexes_every_supported_product() -> None:
    text = README.read_text(encoding="utf-8")
    missing = sorted(product for product in REQUIRED_PRODUCTS if product not in text)
    assert missing == []


def test_main_readme_links_every_canonical_profile() -> None:
    text = README.read_text(encoding="utf-8")
    profiles = sorted(path.relative_to(COLLECTOR_ROOT).as_posix() for path in CONFIG_ROOT.rglob("*.yaml"))
    assert len(profiles) == 19
    missing = [profile for profile in profiles if profile not in text]
    assert missing == []


def test_main_readme_includes_wrapper_usage_for_each_stack_family() -> None:
    text = README.read_text(encoding="utf-8")
    assert text.count("./collector/run-collector.sh") >= 8
    assert "--only middleware" in text
    assert "--only dbsat" in text
    assert "--only direct_sql" in text
    assert "--only oci" in text
    assert "--only oci.object_storage" in text


def test_main_readme_documents_customer_package_build_and_full_runs() -> None:
    text = README.read_text(encoding="utf-8")

    build = text.split("## 1. Construir el entregable (proveedor)", 1)[1].split(
        "## 2. Ejecutar el entregable (cliente final)", 1
    )[0]
    assert "build-customer-package.sh" in build
    assert "--mode online" in build
    assert "--mode offline" in build
    assert build.count("--extras all") >= 2
    assert "mismo sistema operativo, arquitectura y versión de Python" in build

    customer = text.split("## 2. Ejecutar el entregable (cliente final)", 1)[1].split(
        "## Configuración", 1
    )[0]
    assert "tar -xzf" in customer
    assert "./collector.sh verify" in customer
    assert "./collector.sh list-profiles" in customer
    assert "./collector.sh init" in customer
    assert "./collector.sh doctor" in customer
    assert "./collector.sh run" in customer
    assert "pip install -e" not in customer
    assert "collector run" not in customer
    assert "### 2.1 OCI completo" in customer
    assert "### 2.2 On-premises completo" in customer
    assert "### 2.3 Híbrido completo" in customer
    assert "oci/full-stack" in customer
    assert "onprem/database/database-full" in customer
    assert "onprem/middleware/middleware-full" in customer
    assert "hybrid/onprem-oci-full" in customer
    assert "--offline-only" in customer
    assert "out/<run.name>/evidence-bundle.json" in customer


def test_main_readme_documents_assessment_skill() -> None:
    text = README.read_text(encoding="utf-8")

    analysis = text.split("## Analizar el output con el skill", 1)[1]
    assert "collector-assessment-report" in analysis
    assert "ruta absoluta" in analysis.lower()
    assert "evidence-bundle.json" in analysis
    assert ".zip" in analysis
    assert ".tar.gz" in analysis
    assert "analysis/collector-assessment-report/report.html" in analysis


def test_config_readme_is_categorized_by_deployment_model() -> None:
    text = CONFIG_README.read_text(encoding="utf-8")
    assert "## On-premises" in text
    assert "## OCI" in text
    assert "## Hybrid" in text

    onprem = text.split("## On-premises", 1)[1].split("## OCI", 1)[0]
    oci = text.split("## OCI", 1)[1].split("## Hybrid", 1)[0]
    hybrid = text.split("## Hybrid", 1)[1]

    assert "configs/onprem/database/dbsat-only.yaml" in onprem
    assert "configs/onprem/middleware/weblogic.yaml" in onprem
    assert "configs/oci/full-stack.yaml" in oci
    assert "configs/oci/object-storage.yaml" in oci
    assert "configs/hybrid/onprem-oci-full.yaml" in hybrid
