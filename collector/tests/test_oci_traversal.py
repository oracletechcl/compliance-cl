from types import SimpleNamespace

import pytest

from oracle_collector.collectors.oci.traversal import paginate


def _response(items, headers=None):
    return SimpleNamespace(data=items, headers=headers or {})


@pytest.mark.parametrize(
    "operation_name",
    ["identity.list_availability_domains", "log_analytics.list_namespaces"],
)
def test_paginate_omits_page_for_sdk_operations_that_reject_it(operation_name):
    calls = []

    def sdk_operation(**kwargs):
        calls.append(kwargs)
        if "page" in kwargs:
            raise TypeError(f"{operation_name} does not accept page")
        return _response([operation_name])

    assert paginate(sdk_operation, compartment_id="ocid1.compartment.test") == [operation_name]
    assert calls == [{"compartment_id": "ocid1.compartment.test"}]


def test_paginate_adds_page_only_after_non_empty_header_token():
    calls = []
    responses = iter(
        [
            _response(["first"], {"opc-next-page": "page-2"}),
            _response(["second"], {"opc_next_page": "page-3"}),
            _response(["third"], {"opc-next-page": ""}),
        ]
    )

    def sdk_operation(**kwargs):
        calls.append(kwargs)
        return next(responses)

    assert paginate(sdk_operation, compartment_id="ocid1.compartment.test") == [
        "first",
        "second",
        "third",
    ]
    assert calls == [
        {"compartment_id": "ocid1.compartment.test"},
        {"page": "page-2", "compartment_id": "ocid1.compartment.test"},
        {"page": "page-3", "compartment_id": "ocid1.compartment.test"},
    ]


def test_paginate_can_bound_pages_and_signal_truncation():
    calls = []
    truncations = []

    def sdk_operation(**kwargs):
        calls.append(kwargs)
        return _response(["presence-sample"], {"opc-next-page": "page-2"})

    assert paginate(
        sdk_operation,
        max_pages=1,
        on_truncated=lambda: truncations.append(True),
        compartment_id="ocid1.tenancy.test",
    ) == ["presence-sample"]
    assert calls == [{"compartment_id": "ocid1.tenancy.test"}]
    assert truncations == [True]


def test_paginate_rejects_non_positive_page_limit():
    with pytest.raises(ValueError, match="max_pages must be at least 1"):
        paginate(lambda: _response([]), max_pages=0)


def test_paginate_retries_429_with_bounded_exponential_backoff(monkeypatch):
    calls = []
    sleeps = []

    class TooManyRequests(Exception):
        status = 429

    def sdk_operation(**kwargs):
        calls.append(kwargs)
        if len(calls) <= 2:
            raise TooManyRequests()
        return _response(["recovered"])

    monkeypatch.setattr(
        "oracle_collector.collectors.oci.traversal.time.sleep", sleeps.append
    )

    assert paginate(sdk_operation, max_retries=2, namespace_name="namespace") == [
        "recovered"
    ]
    assert calls == [{"namespace_name": "namespace"}] * 3
    assert sleeps == [1, 2]


def test_paginate_raises_after_retry_limit(monkeypatch):
    calls = []
    sleeps = []

    class TooManyRequests(Exception):
        status = 429

    def sdk_operation(**kwargs):
        calls.append(kwargs)
        raise TooManyRequests()

    monkeypatch.setattr(
        "oracle_collector.collectors.oci.traversal.time.sleep", sleeps.append
    )

    with pytest.raises(TooManyRequests):
        paginate(sdk_operation, max_retries=2, compartment_id="ocid1.compartment.test")

    assert calls == [{"compartment_id": "ocid1.compartment.test"}] * 3
    assert sleeps == [1, 2]
