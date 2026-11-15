"""Binary status pushes need a model-specific client opt-in."""

import base64
from collections.abc import AsyncIterator
from copy import deepcopy

from aiogree.device_api_client import DeviceApiClient
from aiogree.helpers import gree_encrypt_pack
import pytest

from .fakes.device import FakeGreeDevice
from .fakes.transport import FakePushTransport


@pytest.fixture(name="client")
async def bound_client() -> AsyncIterator[tuple[DeviceApiClient, FakePushTransport]]:
    """Bind entirely in memory, with a synthetic device and key."""
    fake = FakeGreeDevice()
    transport = FakePushTransport(fake)
    client = DeviceApiClient(fake.mac, userid=0)
    await client.set_transport(transport)
    await client.bind(fake.mac)
    try:
        yield client, transport
    finally:
        await client.unbind()


def binary_pack() -> dict:
    """Build a synthetic 0x31 report with known state fields."""
    raw = bytearray(52)
    raw[:4] = b"~~\x31\x31"
    raw[8] = 0x90
    raw[9] = 0xA0
    raw[12] = 0x10
    raw[22] = 8
    raw[46] = 65
    return {"t": "binStatus", "binStatus": base64.b64encode(raw).decode("ascii")}


def encrypted(client: DeviceApiClient, pack: dict) -> dict:
    """Use the same encrypted push format as the MQTT transport."""
    return gree_encrypt_pack({"t": "pack", "pack": pack}, client.cipher)


async def test_binary_push_requires_opt_in(
    client: tuple[DeviceApiClient, FakePushTransport],
) -> None:
    """A shared frame marker alone does not identify an appliance layout."""
    api_client, transport = client
    seen = []
    api_client.add_status_listener(seen.append)
    payload = encrypted(api_client, binary_pack())
    transport.push(api_client.controller_mac, "binStatus/test", payload)
    assert not seen
    assert isinstance(payload["pack"], str)


async def test_enabled_binary_status_reaches_normal_listeners(
    client: tuple[DeviceApiClient, FakePushTransport],
) -> None:
    """Known properties use the same string values as JSON status."""
    api_client, transport = client
    api_client.enable_binary_status()
    seen = []
    api_client.add_status_listener(seen.append)
    transport.push(
        api_client.controller_mac,
        "binStatus/test",
        encrypted(api_client, binary_pack()),
    )
    assert seen == [
        {
            "Pow": "1",
            "Mod": "1",
            "SetTem": "26",
            "TemSen": "65",
            "SwUpDn": "1",
            "SwingLfRig": "0",
            "WdSpd": "0",
        }
    ]


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("topic", ["status/test", "binStatus/test"])
async def test_json_status_still_works(
    client: tuple[DeviceApiClient, FakePushTransport], enabled: bool, topic: str
) -> None:
    """The opt-in does not change existing cols/dat status reports."""
    api_client, transport = client
    if enabled:
        api_client.enable_binary_status()
    seen = []
    api_client.add_status_listener(seen.append)
    transport.push(
        api_client.controller_mac,
        topic,
        encrypted(
            api_client,
            {
                "t": "dat",
                "cols": ["Pow", "SetTem"],
                "dat": [1, 26],
            },
        ),
    )
    assert seen == [{"Pow": "1", "SetTem": "26"}]


@pytest.mark.parametrize("binary", [False, True])
async def test_same_envelope_can_be_processed_twice(
    client: tuple[DeviceApiClient, FakePushTransport], binary: bool
) -> None:
    """Decrypting one callback must not replace the shared encrypted pack."""
    api_client, transport = client
    api_client.enable_binary_status()
    seen = []
    api_client.add_status_listener(seen.append)
    pack = binary_pack() if binary else {"t": "dat", "cols": ["Pow"], "dat": [1]}
    payload = encrypted(api_client, pack)
    original = deepcopy(payload)
    transport.push(api_client.controller_mac, "status/test", payload)
    transport.push(api_client.controller_mac, "status/test", payload)
    assert payload == original
    assert len(seen) == 2
    assert seen[0] == seen[1]


@pytest.mark.parametrize(
    "pack",
    [
        {"t": "binStatus", "binStatus": "!bad!"},
        {"t": "binStatus", "binStatus": 123},
        {"t": "binStatus", "binStatus": "fn4xMQ=="},
    ],
)
async def test_invalid_binary_status_is_ignored(
    client: tuple[DeviceApiClient, FakePushTransport], pack: dict
) -> None:
    """Malformed reports cannot publish a partial or empty device state."""
    api_client, transport = client
    api_client.enable_binary_status()
    seen = []
    api_client.add_status_listener(seen.append)
    transport.push(
        api_client.controller_mac, "binStatus/test", encrypted(api_client, pack)
    )
    assert not seen
