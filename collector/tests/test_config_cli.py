from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oracle_collector import cli as cli_module
from oracle_collector.cli import (
    RunSelection,
    _implicit_oci_service_skips,
    _oci_tasks,
    _selected_oci_services,
    build_parser,
    execute,
    resolve_selection,
)
from oracle_collector.config import ConfigError, load_config
from oracle_collector.models import CollectorResult


def test_load_config_and_cli_overrides(tmp_path: Path) -> None:
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        """
run:
  name: test-run
  redaction: strict
  parallelism: 4
oci:
  enabled: true
  auth: instance_principal
  tenancy_ocid: ocid1.tenancy.oc1..example
  regions: [sa-santiago-1]
  compartments: all
  services: all
onprem_db:
  enabled: false
onprem_middleware:
  enabled: false
""".strip(),
        encoding="utf-8",
    )

    config = load_config(config_path)
    assert config.run.parallelism == 4
    assert config.run.name == "test-run"
    assert config.run.redaction == "strict"
    assert config.oci.regions == ("sa-santiago-1",)
    assert config.oci.connect_timeout_seconds == 5.0
    assert config.oci.read_timeout_seconds == 30.0

    args = build_parser().parse_args(
        ["run", "--config", str(config_path), "--only", "oci.object_storage", "--skip", "dbsat"]
    )
    selection = resolve_selection(config, args)
    assert selection.only == ("oci.object_storage",)
    assert "dbsat" in selection.skip


def test_services_all_excludes_threat_intelligence_and_exposes_coverage_skip(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        """
run:
  name: implicit-all
oci:
  enabled: true
  auth: instance_principal
  tenancy_ocid: ocid.tenancy
  regions: [us-sanjose-1]
  compartments: [ocid.compartment]
  services: all
""".strip(),
        encoding="utf-8",
    )
    config = load_config(config_path)

    selected = _selected_oci_services(config, RunSelection())
    skipped = _implicit_oci_service_skips(config, RunSelection())

    assert "threat_intelligence" not in selected
    assert "object_storage" in selected
    assert skipped == [
        {
            "service": "threat_intelligence",
            "reason": (
                "excluded from implicit services=all because OCI Threat Intelligence "
                "list_indicators is a global feed, not customer compartment inventory; "
                "select threat_intelligence explicitly to opt in"
            ),
        }
    ]


def test_explicit_threat_intelligence_service_remains_selected(tmp_path: Path) -> None:
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        """
run:
  name: explicit-threat
oci:
  enabled: true
  auth: instance_principal
  tenancy_ocid: ocid.tenancy
  regions: [us-sanjose-1]
  compartments: [ocid.compartment]
  services: [threat_intelligence]
""".strip(),
        encoding="utf-8",
    )
    config = load_config(config_path)

    assert _selected_oci_services(config, RunSelection()) == ["threat_intelligence"]
    assert _implicit_oci_service_skips(config, RunSelection()) == []


def test_execute_records_implicit_global_feed_exclusion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        """
run:
  name: implicit-all-result
oci:
  enabled: true
  auth: instance_principal
  tenancy_ocid: ocid.tenancy
  regions: [us-sanjose-1]
  compartments: [ocid.compartment]
  services: all
""".strip(),
        encoding="utf-8",
    )
    config = load_config(config_path)
    captured: dict[str, CollectorResult] = {}

    monkeypatch.setattr(cli_module, "_onprem_tasks", lambda *_args: [])
    monkeypatch.setattr(cli_module, "_oci_tasks", lambda *_args: ([], {}))
    monkeypatch.setattr(cli_module, "run_tasks", lambda *_args: CollectorResult())
    monkeypatch.setattr(cli_module, "build_bundle", lambda *_args: {})

    def write_output(_bundle, result, out_dir, **_kwargs):
        captured["result"] = result
        return Path(out_dir) / "implicit-all-result"

    monkeypatch.setattr(cli_module, "write_output", write_output)
    args = SimpleNamespace(
        only=None,
        skip=None,
        offline_only=False,
        dry_run=False,
        out=str(tmp_path),
        encryption_key_file=None,
    )

    assert execute(config, args) == 2
    assert captured["result"].services_skipped[0]["service"] == "threat_intelligence"


@pytest.mark.parametrize("redaction", ["none", "unsafe", ""])
def test_invalid_redaction_is_rejected(tmp_path: Path, redaction: str) -> None:
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        f"run:\n  name: x\n  redaction: {redaction!r}\noci:\n  enabled: false\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(config_path)


def test_cleartext_password_in_config_is_rejected(tmp_path: Path) -> None:
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        "run:\n  name: x\n  redaction: strict\noci:\n  enabled: false\npassword: secret\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="secret|password"):
        load_config(config_path)


@pytest.mark.parametrize("key", ["client_secret", "auth_token", "wallet_password", "signing_private_key"])
def test_secret_key_variants_are_rejected(tmp_path: Path, key: str) -> None:
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        f"run:\n  name: x\n  redaction: strict\noci:\n  enabled: false\n{key}: forbidden\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="secret|password"):
        load_config(config_path)


def test_oci_tasks_pass_tenancy_context_to_compartment_collectors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        """
run:
  name: context-test
oci:
  enabled: true
  auth: instance_principal
  tenancy_ocid: ocid.tenancy
  regions: [us-sanjose-1]
  compartments: [ocid.compartment]
  services: [logging_analytics]
""".strip(),
        encoding="utf-8",
    )
    config = load_config(config_path)
    assert config.run.parallelism == 16
    captured: dict[str, dict[str, dict[str, object]]] = {}

    closed: list[str] = []

    class Client:
        def __init__(self, name: str) -> None:
            self.name = name
            self.base_client = type(
                "BaseClient",
                (),
                {"session": type("Session", (), {"close": lambda _self: closed.append(name)})()},
            )()

    clients = {"iam": Client("iam"), "logging_analytics": Client("logging_analytics")}
    monkeypatch.setattr(cli_module, "create_client", lambda service, *_: clients[service])
    monkeypatch.setattr(
        cli_module,
        "resolve_compartments",
        lambda *_: ["ocid.compartment"],
    )

    def collect_service(
        _service: str,
        _client: object,
        _compartments: tuple[str, ...],
        _region: str,
        *,
        context_by_compartment: dict[str, dict[str, object]],
    ) -> CollectorResult:
        captured["contexts"] = context_by_compartment
        return CollectorResult()

    monkeypatch.setattr(cli_module, "collect_service_across_compartments", collect_service)

    tasks, _environment = _oci_tasks(config, RunSelection())
    assert closed == ["iam"]
    tasks[0].collect()

    assert captured["contexts"] == {
        "ocid.compartment": {"tenancy_ocid": "ocid.tenancy"}
    }
    assert closed == ["iam", "logging_analytics"]


def test_cloud_guard_services_use_reporting_region_and_close_discovery_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        """
run:
  name: cloud-guard-region-test
oci:
  enabled: true
  auth: instance_principal
  tenancy_ocid: ocid.tenancy
  regions: [us-sanjose-1]
  compartments: [ocid.compartment]
  services: [cloud_guard, security_zones]
""".strip(),
        encoding="utf-8",
    )
    config = load_config(config_path)
    created: list[tuple[str, str, str]] = []
    closed: list[str] = []
    collected: list[tuple[str, str, str]] = []

    class Client:
        def __init__(self, label: str) -> None:
            self.label = label
            self.base_client = type(
                "BaseClient",
                (),
                {"session": type("Session", (), {"close": lambda _self: closed.append(label)})()},
            )()

        def get_configuration(self, compartment_id: str) -> object:
            assert compartment_id == "ocid.tenancy"
            data = type("Configuration", (), {"reporting_region": "eu-frankfurt-1"})()
            return type("Response", (), {"data": data})()

    def create_client(service: str, _config: object, region: str) -> Client:
        label = f"{service}:{region}:{len(created)}"
        created.append((service, region, label))
        return Client(label)

    monkeypatch.setattr(cli_module, "create_client", create_client)
    monkeypatch.setattr(cli_module, "resolve_compartments", lambda *_: ["ocid.compartment"])

    def collect_service(
        service: str,
        client: Client,
        _compartments: tuple[str, ...],
        region: str,
        **_kwargs: object,
    ) -> CollectorResult:
        collected.append((service, client.label, region))
        return CollectorResult()

    monkeypatch.setattr(cli_module, "collect_service_across_compartments", collect_service)

    tasks, _environment = _oci_tasks(config, RunSelection())

    assert [(service, region) for service, region, _label in created] == [
        ("iam", "us-sanjose-1"),
        ("cloud_guard", "us-sanjose-1"),
        ("cloud_guard", "eu-frankfurt-1"),
        ("security_zones", "eu-frankfurt-1"),
    ]
    assert closed == [created[0][2], created[1][2]]
    assert [task.region for task in tasks] == ["us-sanjose-1", "us-sanjose-1"]

    for task in tasks:
        task.collect()

    assert [(service, region) for service, _label, region in collected] == [
        ("cloud_guard", "us-sanjose-1"),
        ("security_zones", "us-sanjose-1"),
    ]
    assert closed == [created[0][2], created[1][2], created[2][2], created[3][2]]


def test_cloud_guard_reporting_region_discovery_failure_falls_back_and_closes_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        """
run:
  name: cloud-guard-region-fallback-test
oci:
  enabled: true
  auth: instance_principal
  tenancy_ocid: ocid.tenancy
  regions: [us-sanjose-1]
  compartments: [ocid.compartment]
  services: [security_zones]
""".strip(),
        encoding="utf-8",
    )
    config = load_config(config_path)
    created: list[tuple[str, str]] = []
    closed: list[str] = []

    class Client:
        def __init__(self, label: str) -> None:
            self.label = label
            self.base_client = type(
                "BaseClient",
                (),
                {"session": type("Session", (), {"close": lambda _self: closed.append(label)})()},
            )()

        def get_configuration(self, compartment_id: str) -> object:
            assert compartment_id == "ocid.tenancy"
            raise RuntimeError("configuration unavailable")

    def create_client(service: str, _config: object, region: str) -> Client:
        label = f"{service}:{region}:{len(created)}"
        created.append((service, region))
        return Client(label)

    monkeypatch.setattr(cli_module, "create_client", create_client)
    monkeypatch.setattr(cli_module, "resolve_compartments", lambda *_: ["ocid.compartment"])
    monkeypatch.setattr(
        cli_module,
        "collect_service_across_compartments",
        lambda *_args, **_kwargs: CollectorResult(),
    )

    tasks, _environment = _oci_tasks(config, RunSelection())

    assert created == [
        ("iam", "us-sanjose-1"),
        ("cloud_guard", "us-sanjose-1"),
        ("security_zones", "us-sanjose-1"),
    ]
    assert closed == ["iam:us-sanjose-1:0", "cloud_guard:us-sanjose-1:1"]

    tasks[0].collect()
    assert closed == [
        "iam:us-sanjose-1:0",
        "cloud_guard:us-sanjose-1:1",
        "security_zones:us-sanjose-1:2",
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("connect_timeout_seconds", 0),
        ("connect_timeout_seconds", 301),
        ("read_timeout_seconds", 0),
        ("read_timeout_seconds", 301),
    ],
)
def test_invalid_oci_timeouts_are_rejected(tmp_path: Path, field: str, value: int) -> None:
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        f"""
run:
  name: timeout-test
oci:
  enabled: true
  auth: instance_principal
  regions: [us-sanjose-1]
  {field}: {value}
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="timeout"):
        load_config(config_path)
