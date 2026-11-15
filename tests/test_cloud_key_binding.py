"""Account MQTT keys are usable without a generic app bind exchange."""

from unittest.mock import AsyncMock

from aiogree import device_api_client
from aiogree.cipher import EncryptionVersion, get_cipher
from aiogree.device_api_client import DeviceApiClient
from aiogree.transport import BindingInfo
from aiogree.transport_udp import GreeUdpTransport
import pytest

from .fakes.device import DEFAULT_SESSION_KEY, FakeGreeDevice
from .test_binary_api import CONTROLLER, MAC, RecordingMqtt

KEY = "0123456789abcdef"


def recording_cloud(monkeypatch: pytest.MonkeyPatch, response: dict) -> RecordingMqtt:
    """Keep real pack encryption while replacing only broker subscription."""
    transport = RecordingMqtt(get_cipher(EncryptionVersion.V1, KEY), response)
    monkeypatch.setattr(transport, "_subscribe", AsyncMock())
    monkeypatch.setattr(transport, "_unsubscribe", AsyncMock())
    return transport


@pytest.mark.parametrize("version", [None, EncryptionVersion.V1])
async def test_cloud_key_skips_generic_bind_and_probe(
    monkeypatch: pytest.MonkeyPatch, version: EncryptionVersion | None
) -> None:
    """Only the following information request is sent, using the account key."""
    transport = recording_cloud(
        monkeypatch, {"pack": {"t": "dat", "cols": ["hid"], "dat": ["test-model"]}}
    )
    client = DeviceApiClient(MAC, userid=1234)
    await client.set_transport(transport)
    try:
        await client.bind(CONTROLLER, version, KEY)
        assert client.bound
        assert client.encryption_key == KEY
        assert client.encryption_version == EncryptionVersion.V1
        assert not transport.requests
        result = await client.query_props(["hid"])
        assert result.prop_values == {"hid": "test-model"}
        assert len(transport.requests) == 1
        # RecordingMqtt decrypts the encrypted wire packet with the account key.
        request = transport.requests[0][1]
        assert request["i"] == 0
        assert request["pack"]["t"] == "status"
        assert request["pack"]["cols"] == ["hid"]
    finally:
        await client.unbind()


@pytest.mark.parametrize("key", [None, "", "   "])
async def test_cloud_without_key_keeps_generic_binding(
    monkeypatch: pytest.MonkeyPatch, key: str | None
) -> None:
    """A missing account key still uses the existing key discovery path."""
    transport = recording_cloud(monkeypatch, {})
    binding = BindingInfo(
        KEY, EncryptionVersion.V1, get_cipher(EncryptionVersion.V1, KEY)
    )
    bind = AsyncMock(return_value=binding)
    probe = AsyncMock()
    monkeypatch.setattr(device_api_client, "gree_try_bind", bind)
    client = DeviceApiClient(MAC, userid=1234)
    monkeypatch.setattr(client, "probe_device_limits", probe)
    await client.set_transport(transport)
    try:
        await client.bind(CONTROLLER, preferred_key=key)
        bind.assert_awaited_once_with(CONTROLLER, 1234, None, key, transport)
        probe.assert_awaited_once()
    finally:
        await client.unbind()


async def test_cloud_v2_keeps_existing_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    """The verified direct account-key path is limited to V1."""
    transport = recording_cloud(monkeypatch, {})
    binding = BindingInfo(
        KEY, EncryptionVersion.V2, get_cipher(EncryptionVersion.V2, KEY)
    )
    bind = AsyncMock(return_value=binding)
    monkeypatch.setattr(device_api_client, "gree_try_bind", bind)
    client = DeviceApiClient(MAC, userid=1234)
    monkeypatch.setattr(client, "probe_device_limits", AsyncMock())
    await client.set_transport(transport)
    try:
        await client.bind(CONTROLLER, EncryptionVersion.V2, KEY)
        bind.assert_awaited_once_with(
            CONTROLLER, 1234, EncryptionVersion.V2, KEY, transport
        )
    finally:
        await client.unbind()


@pytest.mark.parametrize("force_bind", [False, True])
async def test_cloud_rebind_keeps_account_key(
    monkeypatch: pytest.MonkeyPatch, force_bind: bool
) -> None:
    """Unbinding must not lose the account key and start a generic bind."""
    transport = recording_cloud(monkeypatch, {})
    client = DeviceApiClient(MAC, userid=1234)
    await client.set_transport(transport)
    try:
        await client.bind(CONTROLLER, EncryptionVersion.V1, KEY)
        await client.rebind(force_bind=force_bind)
        assert client.bound
        assert client.encryption_key == KEY
        assert not transport.requests
    finally:
        await client.unbind()


async def test_udp_with_known_key_still_binds() -> None:
    """The account MQTT shortcut must not change UDP bind or column probing."""
    fake = FakeGreeDevice()
    await fake.start()
    transport = GreeUdpTransport(fake.host, fake.port, max_retries=1, timeout=0.3)
    client = DeviceApiClient(fake.mac, userid=0)
    await client.set_transport(transport)
    try:
        await client.bind(fake.mac, EncryptionVersion.V1, DEFAULT_SESSION_KEY)
        assert any(pack.get("t") == "bind" for pack in fake.packs)
        assert any(pack.get("t") == "status" for pack in fake.packs)
        assert client.encryption_key == DEFAULT_SESSION_KEY
        assert (await client.query_props(["Pow"])).prop_values == {"Pow": "1"}
    finally:
        await client.unbind()
        await transport.disconnect()
        fake.close()
