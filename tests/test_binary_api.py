"""Experimental binary requests use MQTT and only report acceptance."""

import json
from typing import Any, override

from aiogree.api import gree_set_binary_status
from aiogree.cipher import CipherBase, EncryptionVersion, get_cipher
from aiogree.cloud_api import GreeRegion
from aiogree.errors import GreeConnectionError, GreeProtocolError
from aiogree.helpers import gree_decrypt_pack, gree_encrypt_pack
from aiogree.transport_mqtt import GreeMqttTransport
from aiogree.transport_udp import GreeUdpTransport
import pytest

MAC = "020000000001"
CONTROLLER = "020000000002"
PROFILE = b"~~\x13\x6a" + b"EXAMPLEPROFILE00" + b"\x00"
TEMPLATE = b"~~\x2f\x01" + bytes(46)


class RecordingMqtt(GreeMqttTransport):
    """Run real pack encryption in memory, without opening a connection."""

    def __init__(self, cipher: CipherBase, response: dict | None) -> None:
        """Keep a fake reply and collect requests after decryption."""
        super().__init__("1234", "test-token", GreeRegion.CN)
        self.cipher = cipher
        self.response = response
        self.requests: list[tuple[str, dict[str, Any], int | None]] = []

    @override
    async def request(
        self,
        mac_controller: str,
        json_str: str,
        max_attempts: int | None = None,
        timeout: float | None = None,
    ) -> str:
        """Check the encrypted wire envelope, then return an encrypted reply."""
        request = json.loads(json_str)
        assert isinstance(request["pack"], str)
        assert "tag" not in request
        self.requests.append(
            (mac_controller, gree_decrypt_pack(request, self.cipher), max_attempts)
        )
        if self.response is None:
            raise GreeConnectionError("No test reply")
        return json.dumps(gree_encrypt_pack(self.response, self.cipher))


@pytest.fixture(name="cipher")
def device_cipher() -> CipherBase:
    """Use a synthetic key, with no device or cloud connection."""
    return get_cipher(EncryptionVersion.V1, "0123456789abcdef")


async def test_binary_acceptance_is_not_a_state_confirmation(
    cipher: CipherBase,
) -> None:
    """A full command stays together, and an empty res/200 returns no state."""
    transport = RecordingMqtt(cipher, {"pack": {"t": "res", "r": 200}})
    pushes = []
    transport.add_listener(MAC, lambda topic, payload: pushes.append((topic, payload)))
    result = await gree_set_binary_status(
        CONTROLLER,
        MAC,
        1234,
        {"Mod": 1, "SetTem": 26, "Pow": 1},
        TEMPLATE,
        PROFILE,
        cipher,
        transport,
    )
    assert result is None
    assert not pushes
    assert len(transport.requests) == 1
    controller, payload, attempts = transport.requests[0]
    assert controller == CONTROLLER
    assert attempts == 1
    assert payload["tcid"] == CONTROLLER
    assert payload["uid"] == 1234
    assert payload["t"] == "pack"
    assert payload["i"] == 0
    assert payload["pack"]["mac"] == MAC
    assert payload["pack"]["t"] == "binCmd"
    assert {item[1] for item in payload["pack"]["fragment"]} >= {5, 6, 11, 44}
    assert "opt" not in payload["pack"]


@pytest.mark.parametrize(
    "pack",
    [
        {"t": "res", "r": 500},
        {"t": "res"},
        {"t": "res", "r": "200"},
        {"t": "res", "r": 200.0},
        {"t": "dat", "r": 200},
        {},
        [],
    ],
)
async def test_invalid_binary_acceptance_is_rejected(
    cipher: CipherBase, pack: Any
) -> None:
    """A different reply or loose result-code type cannot claim acceptance."""
    transport = RecordingMqtt(cipher, {"pack": pack})
    with pytest.raises(GreeProtocolError):
        await gree_set_binary_status(
            CONTROLLER, MAC, 1234, {"Pow": 1}, TEMPLATE, PROFILE, cipher, transport
        )


async def test_missing_pack_is_rejected(cipher: CipherBase) -> None:
    """A response envelope without a pack is not an acknowledgement."""
    transport = RecordingMqtt(cipher, {"t": "pack"})
    with pytest.raises(GreeProtocolError, match="missing 'pack'"):
        await gree_set_binary_status(
            CONTROLLER, MAC, 1234, {"Pow": 1}, TEMPLATE, PROFILE, cipher, transport
        )


async def test_no_reply_does_not_claim_acceptance(cipher: CipherBase) -> None:
    """Keep connection failures distinct from rejected commands."""
    transport = RecordingMqtt(cipher, None)
    with pytest.raises(GreeConnectionError):
        await gree_set_binary_status(
            CONTROLLER, MAC, 1234, {"Pow": 1}, TEMPLATE, PROFILE, cipher, transport
        )


async def test_udp_is_rejected_before_sending(cipher: CipherBase) -> None:
    """The cloud network frame cannot accidentally be sent over UDP."""
    transport = GreeUdpTransport("127.0.0.1")
    with pytest.raises(GreeProtocolError, match="MQTT transport"):
        await gree_set_binary_status(
            CONTROLLER, MAC, 1234, {"Pow": 1}, TEMPLATE, PROFILE, cipher, transport
        )


async def test_gcm_is_rejected_before_sending() -> None:
    """The experimental MQTT protocol has only been observed with V1."""
    cipher = get_cipher(EncryptionVersion.V2, "0123456789abcdef")
    transport = RecordingMqtt(cipher, {"pack": {"t": "res", "r": 200}})
    with pytest.raises(GreeProtocolError, match="V1 encryption"):
        await gree_set_binary_status(
            CONTROLLER, MAC, 1234, {"Pow": 1}, TEMPLATE, PROFILE, cipher, transport
        )
    assert not transport.requests


async def test_unproven_controls_are_rejected_before_sending(
    cipher: CipherBase,
) -> None:
    """Codec validation happens before encryption or any transport call."""
    transport = RecordingMqtt(cipher, {"pack": {"t": "res", "r": 200}})
    with pytest.raises(GreeProtocolError, match="Invalid binary AC command"):
        await gree_set_binary_status(
            CONTROLLER, MAC, 1234, {"WdSpd": 3}, TEMPLATE, PROFILE, cipher, transport
        )
    assert not transport.requests
