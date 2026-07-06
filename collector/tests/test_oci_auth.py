from __future__ import annotations

from types import SimpleNamespace

from oracle_collector.collectors.oci import auth
from oracle_collector.config import OciConfig


def test_session_token_uses_loaded_private_key_object(monkeypatch, tmp_path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("session-token", encoding="utf-8")
    key_file = tmp_path / "key.pem"
    key_file.write_text("not-read-by-fake", encoding="utf-8")
    captured = {}

    class Config:
        @staticmethod
        def from_file(path, profile):
            return {
                "security_token_file": str(token_file),
                "key_file": str(key_file),
                "pass_phrase": None,
                "tenancy": "ocid.tenancy",
            }

    class SignerModule:
        @staticmethod
        def load_private_key_from_file(path, pass_phrase):
            captured["key_path"] = path
            return object()

    class SecurityTokenSigner:
        def __init__(self, token, private_key):
            captured["token"] = token
            captured["private_key"] = private_key

    fake_oci = SimpleNamespace(
        config=Config,
        signer=SignerModule,
        auth=SimpleNamespace(signers=SimpleNamespace(SecurityTokenSigner=SecurityTokenSigner)),
    )
    monkeypatch.setattr(auth, "_oci", lambda: fake_oci)

    values, signer = auth.auth_context(
        OciConfig(enabled=True, auth="session_token", regions=("sa-santiago-1",))
    )

    assert values["tenancy"] == "ocid.tenancy"
    assert isinstance(signer, SecurityTokenSigner)
    assert captured["token"] == "session-token"
    assert captured["key_path"] == str(key_file)
    assert not isinstance(captured["private_key"], str)


def test_create_client_applies_configured_timeouts(monkeypatch) -> None:
    captured = {}

    class BaseClient:
        def set_region(self, region: str) -> None:
            captured["region"] = region

    class ComputeClient:
        def __init__(self, values, **kwargs) -> None:
            captured["values"] = values
            captured["kwargs"] = kwargs
            self.base_client = BaseClient()

    class NoneRetryStrategy:
        pass

    fake_oci = SimpleNamespace(
        core=SimpleNamespace(ComputeClient=ComputeClient),
        retry=SimpleNamespace(NoneRetryStrategy=NoneRetryStrategy),
    )
    monkeypatch.setattr(auth, "_oci", lambda: fake_oci)
    monkeypatch.setattr(auth, "auth_context", lambda _config: ({"tenancy": "ocid.tenancy"}, None))
    config = OciConfig(
        enabled=True,
        regions=("us-sanjose-1",),
        connect_timeout_seconds=3.5,
        read_timeout_seconds=17.0,
    )

    auth.create_client("compute", config, "us-sanjose-1")

    assert captured["kwargs"]["timeout"] == (3.5, 17.0)
    assert isinstance(captured["kwargs"]["retry_strategy"], NoneRetryStrategy)
    assert captured["region"] == "us-sanjose-1"


def test_create_client_applies_read_timeout_floor_only_to_audit(monkeypatch) -> None:
    captured_timeouts = []

    class BaseClient:
        def set_region(self, _region: str) -> None:
            pass

    class SlowClient:
        def __init__(self, _values, **kwargs) -> None:
            captured_timeouts.append(kwargs["timeout"])
            self.base_client = BaseClient()

    class NoneRetryStrategy:
        pass

    fake_oci = SimpleNamespace(
        audit=SimpleNamespace(AuditClient=SlowClient),
        threat_intelligence=SimpleNamespace(ThreatintelClient=SlowClient),
        retry=SimpleNamespace(NoneRetryStrategy=NoneRetryStrategy),
    )
    monkeypatch.setattr(auth, "_oci", lambda: fake_oci)
    monkeypatch.setattr(auth, "auth_context", lambda _config: ({"tenancy": "ocid.tenancy"}, None))

    for read_timeout in (17.0, 180.0):
        config = OciConfig(
            enabled=True,
            regions=("us-sanjose-1",),
            connect_timeout_seconds=3.5,
            read_timeout_seconds=read_timeout,
        )
        for service in ("audit", "threat_intelligence"):
            auth.create_client(service, config, "us-sanjose-1")

    assert captured_timeouts == [
        (3.5, 120.0),
        (3.5, 17.0),
        (3.5, 180.0),
        (3.5, 180.0),
    ]


def test_close_client_closes_underlying_sdk_session() -> None:
    closed = []
    session = SimpleNamespace(close=lambda: closed.append(True))
    client = SimpleNamespace(base_client=SimpleNamespace(session=session))

    auth.close_client(client)

    assert closed == [True]
