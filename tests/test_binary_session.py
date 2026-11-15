"""A binary AC poll requires a fresh full push, not a cached report or res."""

import asyncio
from collections.abc import AsyncIterator
from copy import deepcopy
from unittest.mock import AsyncMock

from aiogree.api import GreeProp
from aiogree.cipher import EncryptionVersion, get_cipher
from aiogree.device_api_client import DeviceApiClient
from aiogree.errors import GreeConnectionError, GreeProtocolError, GreeRuntimeError
from aiogree.helpers import gree_encrypt_pack
from aiogree.transport import BindingInfo
from aiogree.transport_udp import GreeUdpTransport
import pytest

from .fakes.device import FakeGreeDevice
from .fakes.transport import FakePushTransport
from .test_binary_api import CONTROLLER, MAC, PROFILE, TEMPLATE, RecordingMqtt
from .test_binary_client import binary_pack


@pytest.fixture(name="client")
async def bound_client() -> AsyncIterator[tuple[DeviceApiClient, FakePushTransport]]:
    """Use the real binding and pack cipher with an in-memory transport."""
    fake = FakeGreeDevice()
    transport = FakePushTransport(fake)
    api_client = DeviceApiClient(fake.mac, userid=0)
    await api_client.set_transport(transport)
    await api_client.bind(fake.mac)
    api_client.configure_binary_ac_status(timeout=0.03)
    try:
        yield api_client, transport
    finally:
        await api_client.unbind()


def full_status(**updates: str) -> dict[str, str]:
    """Include basic controls, device information and unknown guard fields."""
    return {
        "Pow": "0",
        "Mod": "1",
        "SetTem": "25",
        "WdSpd": "0",
        "SwUpDn": "1",
        "SwingLfRig": "0",
        "TemSen": "65",
        "TemUn": "0",
        "Add0.5": "0",
        "hid": "synthetic-model",
        "UnknownGuard": "7",
        "TemRec": "9",
        "Quiet": "0",
        **updates,
    }


def push(
    client: DeviceApiClient,
    transport: FakePushTransport,
    values: dict[str, str],
    kind: str = "dat",
) -> None:
    """Deliver an encrypted full JSON status as the real MQTT callback does."""
    pack = {"t": kind, "cols": list(values), "dat": list(values.values())}
    transport.push(
        client.controller_mac,
        "status/test",
        gree_encrypt_pack({"t": "pack", "pack": pack}, client.cipher),
    )


async def test_early_push_is_registered_before_request(
    client: tuple[DeviceApiClient, FakePushTransport], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full push arriving before the receipt is enough to finish the poll."""
    api_client, transport = client

    async def request(*_args: object) -> dict:
        push(api_client, transport, full_status())
        return {"pack": {"t": "res", "r": 200}}

    mock = AsyncMock(side_effect=request)
    monkeypatch.setattr(transport, "request_json", mock)
    result = await api_client.query_props(["Pow", "SetTem", "Quiet", "TemRec"])
    assert result.prop_values == {"Pow": "0", "SetTem": "25", "TemRec": "0"}
    assert result.missing_props == ["Quiet"]
    assert api_client.binary_ac_status == full_status()
    assert api_client.binary_ac_status_revision == 1
    assert api_client.available
    pack = mock.call_args.args[1]["pack"]
    assert pack["t"] == "freqCount"
    assert pack["opt"] == ["SendFreq", "FreqTime"]
    assert pack["p"] == [1, 300]


async def test_full_push_after_receipt(
    client: tuple[DeviceApiClient, FakePushTransport], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The receipt does not end waiting for the status push."""
    api_client, transport = client

    async def request(*_args: object) -> dict:
        asyncio.get_running_loop().call_soon(push, api_client, transport, full_status())
        return {"pack": {"t": "res", "r": 200}}

    monkeypatch.setattr(transport, "request_json", AsyncMock(side_effect=request))
    result = await api_client.query_props(["SetTem"])
    assert result.prop_values == {"SetTem": "25"}


async def test_full_push_with_fault_arrays_completes_poll(
    client: tuple[DeviceApiClient, FakePushTransport], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real full reports contain fault arrays alongside scalar controls."""
    api_client, transport = client
    seen = []
    api_client.add_status_listener(seen.append)

    async def request(*_args: object) -> dict:
        values = full_status()
        pack = {
            "t": "dat",
            "cols": [*values, "ShutdownFault", "SubhealthFault"],
            "dat": [*values.values(), [], []],
        }
        transport.push(
            api_client.controller_mac,
            "status/test",
            gree_encrypt_pack({"pack": pack}, api_client.cipher),
        )
        return {"pack": {"t": "res", "r": 200}}

    monkeypatch.setattr(transport, "request_json", AsyncMock(side_effect=request))
    result = await api_client.query_props(["Pow", "SetTem"])
    assert result.prop_values == {"Pow": "0", "SetTem": "25"}
    assert api_client.binary_ac_status["ShutdownFault"] == "[]"
    assert api_client.binary_ac_status["SubhealthFault"] == "[]"
    assert api_client.binary_ac_status_revision == 1
    assert "ShutdownFault" not in seen[0]


async def test_early_push_survives_a_missing_receipt(
    client: tuple[DeviceApiClient, FakePushTransport], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bound the receipt wait so it cannot discard an already received push."""
    api_client, transport = client

    async def request(*_args: object) -> dict:
        push(api_client, transport, full_status())
        await asyncio.Future()
        return {}

    monkeypatch.setattr(transport, "request_json", AsyncMock(side_effect=request))
    assert (await api_client.query_props(["Pow"])).prop_values == {"Pow": "0"}


async def test_configuring_before_bind_skips_ordinary_control_probe() -> None:
    """The regular Pow column probe has no meaning for binary-mode devices."""
    fake = FakeGreeDevice()
    transport = FakePushTransport(fake)
    api_client = DeviceApiClient(fake.mac, userid=0)
    await api_client.set_transport(transport)
    api_client.configure_binary_ac_status()
    await api_client.bind(fake.mac)
    try:
        assert not any(pack.get("t") == "status" for pack in fake.packs)
    finally:
        await api_client.unbind()


@pytest.mark.parametrize("error", [TimeoutError(), GreeConnectionError("No receipt")])
async def test_report_without_normal_reply(
    client: tuple[DeviceApiClient, FakePushTransport],
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    """A real status push remains valid when freqCount has no direct reply."""
    api_client, transport = client

    async def request(*_args: object) -> dict:
        push(api_client, transport, full_status())
        raise error

    monkeypatch.setattr(transport, "request_json", AsyncMock(side_effect=request))
    assert (await api_client.query_props(["Pow"])).prop_values == {"Pow": "0"}


async def test_cached_status_does_not_keep_device_available(
    client: tuple[DeviceApiClient, FakePushTransport], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every poll needs a new report, even if the previous snapshot was valid."""
    api_client, transport = client
    push(api_client, transport, full_status())
    monkeypatch.setattr(
        transport, "request_json", AsyncMock(return_value={"pack": {"r": 200}})
    )
    with pytest.raises(GreeConnectionError, match="fresh full"):
        await api_client.query_props(["SetTem"], error_as_missing=True)
    assert not api_client.available
    assert api_client.binary_ac_status == full_status()
    # A late push restores state, but cannot satisfy a later poll by itself.
    push(api_client, transport, full_status(SetTem="26"))
    assert api_client.available
    with pytest.raises(GreeConnectionError):
        await api_client.query_props(["SetTem"])
    assert not api_client.available


async def test_half_degree_adapts_cloud_flag_only(
    client: tuple[DeviceApiClient, FakePushTransport], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The raw generic TemRec column must not override the cloud Add0.5 flag."""
    api_client, transport = client
    seen = []
    api_client.add_status_listener(seen.append)

    async def request(*_args: object) -> dict:
        push(api_client, transport, full_status(**{"Add0.5": "1"}))
        return {}

    monkeypatch.setattr(transport, "request_json", AsyncMock(side_effect=request))
    result = await api_client.query_props([prop.value for prop in GreeProp])
    assert result.prop_values["SetTem"] == "25"
    assert result.prop_values["TemRec"] == "1"
    assert "Quiet" not in result.prop_values
    assert "UnknownGuard" not in seen[0]
    assert api_client.binary_ac_status["TemRec"] == "9"
    assert api_client.binary_ac_status["Add0.5"] == "1"


@pytest.mark.parametrize("kind", ["connect", "res"])
async def test_non_status_cannot_complete_poll(
    client: tuple[DeviceApiClient, FakePushTransport],
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    """A message with control-looking columns still needs to be a status."""
    api_client, transport = client

    async def request(*_args: object) -> dict:
        push(api_client, transport, full_status(), kind)
        return {"pack": {"t": "res", "r": 200}}

    monkeypatch.setattr(transport, "request_json", AsyncMock(side_effect=request))
    with pytest.raises(GreeConnectionError):
        await api_client.query_props(["Pow"])
    assert api_client.binary_ac_status == {}


async def test_partial_and_malformed_pushes_cannot_overwrite_snapshot(
    client: tuple[DeviceApiClient, FakePushTransport],
) -> None:
    """Never merge a partial report into a full command guard snapshot."""
    api_client, transport = client
    push(api_client, transport, full_status())
    snapshot = api_client.binary_ac_status
    push(api_client, transport, {"Pow": "1"})
    push(api_client, transport, full_status(Pow="invalid"))
    transport.push(api_client.controller_mac, "status/test", {"pack": []})
    assert api_client.binary_ac_status == snapshot
    assert api_client.binary_ac_status_revision == 1
    snapshot["Pow"] = "1"
    assert api_client.binary_ac_status["Pow"] == "0"
    replacement = full_status(SetTem="26")
    del replacement["UnknownGuard"]
    push(api_client, transport, replacement)
    assert "UnknownGuard" not in api_client.binary_ac_status


async def test_information_query_does_not_replace_binary_state(
    client: tuple[DeviceApiClient, FakePushTransport],
) -> None:
    """Model queries can use ordinary JSON without importing zero controls."""
    api_client, transport = client
    push(api_client, transport, full_status())
    original = deepcopy(api_client.binary_ac_status)
    await api_client.query_props(["hid", "ver"], 2)
    assert api_client.binary_ac_status == original
    assert transport.device.packs[-1]["t"] == "status"
    assert transport.device.packs[-1]["cols"] == ["hid", "ver"]


async def test_unbind_discards_snapshot(
    client: tuple[DeviceApiClient, FakePushTransport],
) -> None:
    """A previous transport's snapshot cannot be used after unbinding."""
    api_client, transport = client
    push(api_client, transport, full_status())
    await api_client.unbind()
    assert api_client.binary_ac_status == {}
    assert not api_client.available


async def test_switching_to_udp_clears_binary_mode(
    client: tuple[DeviceApiClient, FakePushTransport],
) -> None:
    """A new transport must match its own profile before using binary status."""
    api_client, previous = client
    push(api_client, previous, full_status())
    fake = FakeGreeDevice()
    await fake.start()
    transport = GreeUdpTransport(fake.host, fake.port, max_retries=1, timeout=0.3)
    try:
        await api_client.set_transport(transport)
        assert api_client.binary_ac_status == {}
        assert api_client.binary_ac_status_revision == 0
        await api_client.bind(fake.mac)
        result = await api_client.query_props(["Pow", "SetTem"], 2)
        assert result.prop_values == {"Pow": "1", "SetTem": "21"}
        assert not any(pack.get("t") == "freqCount" for pack in fake.packs)
        await api_client.set_props({"SetTem": 22})
        assert fake.values["SetTem"] == 22
    finally:
        await api_client.unbind()
        await transport.disconnect()
        fake.close()


async def test_switching_transport_clears_decode_only_opt_in(
    client: tuple[DeviceApiClient, FakePushTransport],
) -> None:
    """A raw binary decoder opt-in must not leak to another transport."""
    api_client, _previous = client
    fake = FakeGreeDevice()
    transport = FakePushTransport(fake)
    await api_client.set_transport(transport)
    await api_client.bind(fake.mac)
    api_client.enable_binary_status()
    # Even replacing the same transport requires a new profile opt-in.
    await api_client.set_transport(transport)
    await api_client.bind(fake.mac)
    seen = []
    api_client.add_status_listener(seen.append)
    transport.push(
        api_client.controller_mac,
        "binStatus/test",
        gree_encrypt_pack({"t": "pack", "pack": binary_pack()}, api_client.cipher),
    )
    assert not seen


async def test_same_transport_rebind_keeps_binary_mode(
    client: tuple[DeviceApiClient, FakePushTransport], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rebinding clears the snapshot but still requires a fresh binary push."""
    api_client, transport = client
    push(api_client, transport, full_status())
    await api_client.rebind()
    assert api_client.binary_ac_status == {}

    async def request(*_args: object) -> dict:
        push(api_client, transport, full_status(SetTem="26"))
        return {"pack": {"t": "res", "r": 200}}

    mock = AsyncMock(side_effect=request)
    monkeypatch.setattr(transport, "request_json", mock)
    result = await api_client.query_props(["SetTem"])
    assert result.prop_values == {"SetTem": "26"}
    assert mock.call_args.args[1]["pack"]["t"] == "freqCount"


async def test_binary_control_rejects_non_mqtt_transport(
    client: tuple[DeviceApiClient, FakePushTransport],
) -> None:
    """An enabled status decoder alone does not allow other control paths."""
    api_client, _transport = client
    with pytest.raises(GreeRuntimeError, match="MQTT"):
        await api_client.set_binary_props({"SetTem": 26}, b"", b"")


async def test_generic_control_cannot_bypass_binary_profile(
    client: tuple[DeviceApiClient, FakePushTransport],
) -> None:
    """The normal JSON command path cannot send to a binary-mode device."""
    api_client, transport = client
    previous = len(transport.device.requests)
    with pytest.raises(GreeProtocolError, match="matched profile"):
        await api_client.set_props({"Pow": 1})
    assert len(transport.device.requests) == previous


async def test_binary_control_receipt_does_not_create_state_or_availability() -> None:
    """Accepted commands still need a later full report to prove device state."""
    cipher = get_cipher(EncryptionVersion.V1, "0123456789abcdef")
    transport = RecordingMqtt(cipher, {"pack": {"t": "res", "r": 200}})
    api_client = DeviceApiClient(MAC, userid=1234)
    await api_client.set_transport(transport)
    api_client.controller_mac = CONTROLLER
    transport.connections[CONTROLLER] = [MAC]
    transport.set_controller_binding_info(
        CONTROLLER, BindingInfo("0123456789abcdef", EncryptionVersion.V1, cipher)
    )
    api_client.configure_binary_ac_status()
    assert not api_client.available
    await api_client.set_binary_props({"SetTem": 26}, TEMPLATE, PROFILE)
    assert not api_client.available
    assert api_client.binary_ac_status == {}
    assert api_client.binary_ac_status_revision == 0
    assert transport.requests[0][1]["pack"]["t"] == "binCmd"
