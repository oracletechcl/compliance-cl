from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json

from oracle_collector.collectors.oci.auth import CLIENT_PATHS
from oracle_collector.collectors.oci import registry as registry_module
from oracle_collector.collectors.oci.registry import (
    IMPLICIT_ALL_EXCLUDED_SERVICES,
    SERVICE_COLLECTORS,
    collect_registered_service,
    collect_service_across_compartments,
    resolve_configured_services,
)
from oracle_collector.collectors.oci.traversal import paginate, resolve_compartments


REQUIRED_SERVICES = {
    "iam",
    "cloud_guard",
    "security_zones",
    "vault",
    "data_safe",
    "database",
    "goldengate",
    "mysql",
    "postgresql",
    "nosql",
    "compute",
    "block_storage",
    "oke",
    "object_storage",
    "functions",
    "container_instances",
    "networking",
    "waf",
    "network_firewall",
    "load_balancer",
    "bastion",
    "certificates",
    "api_gateway",
    "audit",
    "logging",
    "logging_analytics",
    "monitoring",
    "events",
    "notifications",
    "threat_intelligence",
    "disaster_recovery",
}


@dataclass
class Data:
    items: list[dict[str, str]]


@dataclass
class Response:
    data: Data
    headers: dict[str, str]


def test_registry_covers_every_service_family_in_spec() -> None:
    assert REQUIRED_SERVICES.issubset(SERVICE_COLLECTORS)


def test_implicit_all_service_scope_excludes_global_feeds() -> None:
    services, skipped = resolve_configured_services("all")

    assert "threat_intelligence" not in services
    assert skipped == [
        {
            "service": "threat_intelligence",
            "reason": IMPLICIT_ALL_EXCLUDED_SERVICES["threat_intelligence"],
        }
    ]


def test_explicit_service_scope_keeps_threat_intelligence_opt_in() -> None:
    services, skipped = resolve_configured_services(("threat_intelligence",))

    assert services == ["threat_intelligence"]
    assert skipped == []


def test_paginate_follows_opc_next_page() -> None:
    calls: list[str | None] = []

    def list_resources(page: str | None = None) -> Response:
        calls.append(page)
        if page is None:
            return Response(Data([{"id": "one"}]), {"opc-next-page": "page-2"})
        return Response(Data([{"id": "two"}]), {})

    assert paginate(list_resources) == [{"id": "one"}, {"id": "two"}]
    assert calls == [None, "page-2"]


def test_unsupported_service_is_skipped_not_fatal() -> None:
    result = collect_registered_service("not-real", object(), "ocid.compartment", "sa-santiago-1")
    assert result.exit_code == 2
    assert result.services_skipped[0]["service"] == "not-real"


def test_compartment_traversal_accepts_sdk_objects_and_dicts() -> None:
    class Identity:
        def list_compartments(self, **_: object) -> Response:
            return Response(Data([{"id": "ocid.compartment.dict"}]), {})

    assert resolve_compartments(Identity(), "ocid.tenancy", "all") == [
        "ocid.tenancy",
        "ocid.compartment.dict",
    ]


def test_object_storage_supplies_namespace_and_aggregates_compartments() -> None:
    class Namespace:
        data = "tenant-namespace"

    class ObjectStorage:
        def get_namespace(self, **_: object) -> Namespace:
            return Namespace()

        def list_buckets(self, *, namespace_name: str, compartment_id: str, page: str | None = None) -> Response:
            assert namespace_name == "tenant-namespace"
            return Response(
                Data(
                    [
                        {
                            "id": f"bucket-{compartment_id}",
                            "name": "exports",
                            "public_access_type": "ObjectRead",
                        }
                    ]
                ),
                {},
            )

    result = collect_service_across_compartments(
        "object_storage",
        ObjectStorage(),
        ["compartment-a", "compartment-b"],
        "sa-santiago-1",
    )

    assert len(result.evidence) == 2
    assert len({record.id for record in result.evidence}) == 2
    assert all(record.signal == "misconfigured" for record in result.evidence)
    assert len(result.raw_files["oci/object_storage/sa-santiago-1.json"]) == 2


def test_evidence_ids_use_stable_resource_ids_when_display_names_match() -> None:
    class Compute:
        def list_instances(self, **_: object) -> Response:
            return Response(
                Data(
                    [
                        {"id": "instance-1", "display_name": "shared-name"},
                        {"id": "instance-2", "display_name": "shared-name"},
                    ]
                ),
                {},
            )

    result = collect_registered_service("compute", Compute(), "compartment", "sa-santiago-1")

    assert [record.resource for record in result.evidence] == ["shared-name", "shared-name"]
    assert len({record.id for record in result.evidence}) == 2


def test_service_collects_every_supported_read_operation() -> None:
    class Identity:
        def list_users(self, **_: object) -> Response:
            return Response(Data([{"id": "user-1", "name": "alice", "is_mfa_activated": False}]), {})

        def list_groups(self, **_: object) -> Response:
            return Response(Data([{"id": "group-1", "name": "admins"}]), {})

        def list_policies(self, **_: object) -> Response:
            return Response(
                Data([{"id": "policy-1", "name": "writers", "statements": ["Allow group writers to manage all-resources in tenancy"]}]),
                {},
            )

    result = collect_registered_service("iam", Identity(), "ocid.tenancy", "sa-santiago-1")

    assert {item["id"] for item in result.inventory} == {"user-1", "group-1", "policy-1"}
    assert any("permisos de escritura" in warning for warning in result.warnings)
    by_resource = {record.resource: record for record in result.evidence}
    assert by_resource["alice"].attribute == "mfa_state"
    assert by_resource["alice"].signal == "absent"
    assert by_resource["writers"].attribute == "iam_policy"


def test_sdk_datetime_values_are_json_serializable() -> None:
    class Compute:
        def list_instances(self, **_: object) -> Response:
            return Response(
                Data([{"id": "instance-1", "display_name": "app", "time_created": datetime(2026, 7, 3, tzinfo=timezone.utc)}]),
                {},
            )

    result = collect_registered_service("compute", Compute(), "compartment", "sa-santiago-1")
    json.dumps(result.raw_files)
    assert result.evidence[0].value["time_created"] == "2026-07-03T00:00:00+00:00"
    assert result.evidence[0].signal == "unknown"


def test_functions_traverses_applications_before_functions() -> None:
    class Functions:
        def list_applications(self, *, compartment_id: str, page: str | None = None) -> Response:
            return Response(Data([{"id": f"app-{compartment_id}", "display_name": "payments"}]), {})

        def list_functions(self, *, application_id: str, page: str | None = None) -> Response:
            return Response(Data([{"id": "fn-1", "display_name": "redact", "application_id": application_id}]), {})

    result = collect_registered_service("functions", Functions(), "compartment", "sa-santiago-1")
    assert {item["id"] for item in result.inventory} == {"app-compartment", "fn-1"}
    assert result.errors == []
    assert result.services_scanned == ["functions"]


def test_boot_volumes_receive_each_availability_domain() -> None:
    class BlockStorage:
        def list_volumes(self, *, compartment_id: str, page: str | None = None) -> Response:
            return Response(Data([{"id": "volume-1"}]), {})

        def list_boot_volumes(
            self,
            *,
            availability_domain: str,
            compartment_id: str,
            page: str | None = None,
        ) -> Response:
            return Response(Data([{"id": f"boot-{availability_domain}"}]), {})

    result = collect_registered_service(
        "block_storage",
        BlockStorage(),
        "compartment",
        "sa-santiago-1",
        context={"availability_domains": ["AD-1", "AD-2"]},
    )
    assert {item["id"] for item in result.inventory} == {"volume-1", "boot-AD-1", "boot-AD-2"}
    assert result.errors == []


def test_logging_analytics_resolves_namespace_before_entities() -> None:
    class LogAnalytics:
        def list_namespaces(self, *, compartment_id: str, page: str | None = None) -> Response:
            assert compartment_id == "ocid.tenancy"
            return Response(Data([{"namespace_name": "tenant_ns"}]), {})

        def list_log_analytics_entities(
            self,
            namespace_name: str,
            compartment_id: str,
            *,
            page: str | None = None,
        ) -> Response:
            assert namespace_name == "tenant_ns"
            return Response(Data([{"id": "entity-1", "name": "db-host"}]), {})

    result = collect_registered_service(
        "logging_analytics",
        LogAnalytics(),
        "compartment",
        "sa-santiago-1",
        context={"tenancy_ocid": "ocid.tenancy"},
    )
    assert {item["id"] for item in result.inventory} == {"entity-1"}
    assert result.errors == []


def test_threat_intelligence_uses_tenancy_scope_but_compartment_evidence_identity() -> None:
    calls: list[dict[str, object]] = []

    class ThreatIntelligence:
        def list_indicators(
            self,
            *,
            compartment_id: str,
            limit: int,
            page: str | None = None,
        ) -> Response:
            calls.append({"compartment_id": compartment_id, "limit": limit, "page": page})
            return Response(Data([{"id": "indicator-1", "name": "malicious-ip"}]), {})

    first = collect_registered_service(
        "threat_intelligence",
        ThreatIntelligence(),
        "ocid.compartment.first",
        "us-sanjose-1",
        context={"tenancy_ocid": "ocid.tenancy"},
    )
    second = collect_registered_service(
        "threat_intelligence",
        ThreatIntelligence(),
        "ocid.compartment.second",
        "us-sanjose-1",
        context={"tenancy_ocid": "ocid.tenancy"},
    )

    assert calls == [
        {"compartment_id": "ocid.tenancy", "limit": 1, "page": None},
        {"compartment_id": "ocid.tenancy", "limit": 1, "page": None},
    ]
    assert first.inventory[0]["compartment"] == "ocid.compartment.first"
    assert second.inventory[0]["compartment"] == "ocid.compartment.second"
    assert first.evidence[0].id != second.evidence[0].id
    assert first.warnings == []
    assert second.warnings == []


def test_threat_intelligence_collects_one_presence_page_and_reports_truncation() -> None:
    calls: list[dict[str, str]] = []

    class ThreatIntelligence:
        def list_indicators(self, **kwargs: str) -> Response:
            calls.append(kwargs)
            return Response(
                Data([{"id": "indicator-1", "name": "malicious-ip"}]),
                {"opc-next-page": "page-2"},
            )

    result = collect_registered_service(
        "threat_intelligence",
        ThreatIntelligence(),
        "ocid.compartment.first",
        "us-sanjose-1",
        context={"tenancy_ocid": "ocid.tenancy"},
    )

    assert calls == [{"compartment_id": "ocid.tenancy", "limit": 1}]
    assert [item["id"] for item in result.raw_files["oci/threat_intelligence/us-sanjose-1.json"]] == [
        "indicator-1"
    ]
    assert len(result.evidence) == 1
    assert result.services_scanned == ["threat_intelligence"]
    assert result.errors == []
    assert result.warnings == [
        "OCI threat_intelligence list_indicators limited to the first page; "
        "additional indicators were not collected because this is presence evidence"
    ]


def test_audit_collects_first_page_from_30_day_window_and_reports_truncation(
    monkeypatch,
) -> None:
    fixed_now = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)
    calls: list[dict[str, object]] = []

    class FrozenDatetime:
        @classmethod
        def now(cls, tz):
            assert tz is timezone.utc
            return fixed_now

    class Audit:
        def list_events(self, **kwargs: object) -> Response:
            calls.append(kwargs)
            if kwargs.get("page"):
                return Response(Data([{"id": "event-2", "event_name": "second"}]), {})
            return Response(
                Data([{"id": "event-1", "event_name": "first"}]),
                {"opc-next-page": "page-2"},
            )

    monkeypatch.setattr(registry_module, "datetime", FrozenDatetime)

    result = collect_registered_service(
        "audit",
        Audit(),
        "ocid.compartment",
        "us-sanjose-1",
    )

    assert calls == [
        {
            "compartment_id": "ocid.compartment",
            "start_time": fixed_now - timedelta(days=30),
            "end_time": fixed_now,
        }
    ]
    assert [item["id"] for item in result.raw_files["oci/audit/us-sanjose-1.json"]] == [
        "event-1"
    ]
    assert len(result.evidence) == 1
    assert result.warnings == [
        "OCI audit list_events limited to the first page of the 30-day window; "
        "additional events were not collected because this is a bounded evidence sample"
    ]


def test_audit_one_page_sample_does_not_report_truncation() -> None:
    class Audit:
        def list_events(self, **_kwargs: object) -> Response:
            return Response(Data([{"id": "event-1", "event_name": "only"}]), {})

    result = collect_registered_service(
        "audit",
        Audit(),
        "ocid.compartment",
        "us-sanjose-1",
    )

    assert [item["id"] for item in result.raw_files["oci/audit/us-sanjose-1.json"]] == [
        "event-1"
    ]
    assert result.warnings == []


def test_audit_event_ids_are_preserved_as_unique_resource_identities() -> None:
    events = [
        {"event_id": "audit-event-1", "event_name": "first"},
        {"event_id": "audit-event-2", "event_name": "second"},
    ]

    class Audit:
        def list_events(self, **_kwargs: object) -> Response:
            return Response(Data(events), {})

    result = collect_registered_service(
        "audit",
        Audit(),
        "ocid.compartment",
        "us-sanjose-1",
    )

    raw_events = result.raw_files["oci/audit/us-sanjose-1.json"]
    assert [item["event_id"] for item in raw_events] == ["audit-event-1", "audit-event-2"]
    assert [item["event_name"] for item in raw_events] == ["first", "second"]
    assert all(item["_collector_operation"] == "list_events" for item in raw_events)
    assert [item["id"] for item in result.inventory] == ["audit-event-1", "audit-event-2"]
    assert [item["name"] for item in result.inventory] == ["audit-event-1", "audit-event-2"]
    assert [record.resource for record in result.evidence] == ["audit-event-1", "audit-event-2"]
    assert len({record.id for record in result.evidence}) == 2
    assert all(record.resource != "unknown" for record in result.evidence)


def test_total_operation_failure_is_not_reported_as_scanned() -> None:
    class BrokenCompute:
        def list_instances(self, *, compartment_id: str, page: str | None = None) -> Response:
            raise PermissionError("denied")

    result = collect_registered_service("compute", BrokenCompute(), "compartment", "sa-santiago-1")
    assert result.services_scanned == []
    assert result.services_skipped == [{"service": "compute", "reason": "all supported operations failed"}]
    assert result.exit_code == 2


def test_notifications_uses_control_plane_client() -> None:
    assert CLIENT_PATHS["notifications"] == "ons.NotificationControlPlaneClient"
