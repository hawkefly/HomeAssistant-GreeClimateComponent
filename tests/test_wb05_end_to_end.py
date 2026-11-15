"""Run the full device lifecycle against a fake MQTT binary module."""

import base64
import json
from pathlib import Path
from typing import override

from aiogree.api import GreeProp
from aiogree.cipher import EncryptionVersion, get_cipher
from aiogree.cloud_api import GreeRegion
from aiogree.device import GreeDevice
from aiogree.helpers import gree_decrypt_pack, gree_encrypt_pack
from aiogree.transport_mqtt import GreeMqttTransport
import pytest

MAC = "020000000001"
KEY = "0123456789abcdef"


class BinaryModuleTransport(GreeMqttTransport):
    """Model this module's query zeros, full pushes and whole-frame controls."""

    def __init__(self) -> None:
        """Start from the anonymous captured defaults, switched off."""
        super().__init__("1234", "fake-token", GreeRegion.CN)
        path = Path(__file__).parent / "fixtures" / "wb05_tg_state.json"
        self.state: dict[str, str] = json.loads(path.read_text())
        self.state["Pow"] = "0"
        self.packs: list[dict] = []

    @override
    async def _subscribe(self, _mac_controller: str) -> None:
        """No network is used in this lifecycle test."""

    @override
    async def _unsubscribe(self, _mac_controller: str) -> None:
        """Leave the recorded requests available for checks."""

    def full_push(self) -> None:
        """Publish a complete report to the real client callback."""
        payload = gree_encrypt_pack(
            {
                "pack": {
                    "t": "dat",
                    "cols": [*self.state, "ShutdownFault", "SubhealthFault"],
                    "dat": [*self.state.values(), [], []],
                }
            },
            get_cipher(EncryptionVersion.V1, KEY),
        )
        for listener in self._listeners.get(MAC, ()):
            listener(f"status/{MAC}", payload)

    @override
    async def request(
        self,
        mac_controller: str,
        json_str: str,
        max_attempts: int | None = None,
        timeout: float | None = None,
    ) -> str:
        """Decrypt real requests and expose the changed frame as a later push."""
        envelope = json.loads(json_str)
        cipher = get_cipher(EncryptionVersion.V1, None if envelope["i"] == 1 else KEY)
        pack = gree_decrypt_pack(envelope, cipher)["pack"]
        self.packs.append(pack)
        kind = pack["t"]
        if kind == "bind":
            reply = {"t": "bindok", "r": 200, "mac": MAC, "key": KEY}
        elif kind == "status":
            cols = pack["cols"]
            # This unit's ordinary control queries return zeros. Information
            # fields remain valid, as observed on the real module.
            reply = {
                "t": "dat",
                "cols": cols,
                "dat": [
                    self.state.get(k, "0") if k in ("hid", "mid", "ver") else "0"
                    for k in cols
                ],
            }
        elif kind == "freqCount":
            self.full_push()
            reply = {"t": "res", "r": 200}
        elif kind == "binCmd":
            raw = base64.b64decode(pack["hex01"])
            self.state.update(
                {
                    "Pow": str(raw[8] >> 7),
                    "Mod": str((raw[8] >> 4) & 7),
                    "SetTem": str((raw[9] >> 4) + 16),
                    "Add0.5": str((raw[14] >> 3) & 1),
                    "SwUpDn": str(raw[12] >> 4),
                }
            )
            reply = {"t": "res", "r": 200}
        else:
            pytest.fail(f"Unexpected request {kind}")
        return json.dumps(gree_encrypt_pack({"pack": reply}, cipher))


async def test_bind_poll_control_and_confirm_use_the_actual_binary_path() -> None:
    """The complete client never replaces a full report with query zeros."""
    transport = BinaryModuleTransport()
    device = GreeDevice(
        "Synthetic WB05", MAC, preferred_encryption_key=KEY, user_id=1234
    )
    try:
        await device.bind_with_transport(
            mqtt_transport=transport, mqtt_controller_mac=MAC
        )
        assert device.is_binary_ac
        assert device.target_temperature == 25
        assert not device.power_mode
        assert device.indoors_temperature_c == 25
        assert not device.supports_property(GreeProp.FEAT_TURBO_MODE)
        device.set_target_temperature(26)
        await device.push_device_status()
        assert device.target_temperature == 26
        assert not device.power_mode
        command = next(pack for pack in transport.packs if pack["t"] == "binCmd")
        raw = base64.b64decode(command["hex01"])
        assert raw[8] >> 7 == 0
        assert raw[9] >> 4 == 10
        assert [p["t"] for p in transport.packs].count("freqCount") == 3
        assert not any(pack["t"] == "cmd" for pack in transport.packs)
    finally:
        await device.unbind_device()
