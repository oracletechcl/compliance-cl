from __future__ import annotations

from oracle_collector.collectors.base import as_mapping


class SdkChild:
    def __init__(self) -> None:
        self.swagger_types = {"name": "str"}
        self.attribute_map = {"name": "name"}
        self._name = "nested-value"

    @property
    def name(self) -> str:
        return self._name


class SdkResource:
    """Minimal model with the storage layout used by OCI Python SDK models."""

    def __init__(self) -> None:
        self.swagger_types = {
            "id": "str",
            "display_name": "str",
            "child": "SdkChild",
        }
        self.attribute_map = {
            "id": "id",
            "display_name": "displayName",
            "child": "child",
        }
        self._id = "resource-1"
        self._display_name = "payments"
        self._child = SdkChild()

    @property
    def id(self) -> str:
        return self._id

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def child(self) -> SdkChild:
        return self._child


def test_as_mapping_serializes_oci_sdk_style_private_value_fields() -> None:
    mapped = as_mapping(SdkResource())

    assert mapped == {
        "id": "resource-1",
        "display_name": "payments",
        "child": {"name": "nested-value"},
    }
    assert "swagger_types" not in mapped
    assert "attribute_map" not in mapped
