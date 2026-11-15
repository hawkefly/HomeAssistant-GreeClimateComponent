"""Checks for the live test's stale-template and push-confirmation guards."""

import asyncio
import base64
import importlib.util
import json
from pathlib import Path

from aiogree.binary_ac import BinaryAcError
import pytest

SPEC = importlib.util.spec_from_file_location(
    "binary_probe", Path(__file__).parents[1] / "tools" / "probe_binary_ac.py"
)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)

EXPECTED = {"Pow": "1", "Mod": "1", "WdSpd": "0", "SwUpDn": "1", "SwingLfRig": "0"}
BEFORE = {
    **EXPECTED,
    "SetTem": "25",
    "Add0.5": "0",
    "mid": "10015",
    "hid": "362001065909+U-WB05_TGV1.30.bin",
}


@pytest.mark.parametrize(
    ("field", "value"), [("Pow", "0"), ("WdSpd", "1"), ("hid", "other")]
)
def test_wrong_template_state_stops_before_send(field: str, value: str) -> None:
    """Reject a capture whose profile or known state differs from the device."""
    with pytest.raises(BinaryAcError):
        PROBE.validate_live_state({**BEFORE, field: value}, EXPECTED, 26)


def test_unchanged_temperature_cannot_confirm_a_test() -> None:
    """A test must change state so an old push cannot confirm it."""
    with pytest.raises(BinaryAcError, match="already matches"):
        PROBE.validate_live_state(BEFORE, EXPECTED, 25)


async def test_stale_push_is_skipped_until_temperature_changes() -> None:
    """Confirmation comes from reported state, with half-degree cleared."""
    pushes: asyncio.Queue[dict[str, str]] = asyncio.Queue()
    pushes.put_nowait(BEFORE)
    pushes.put_nowait({**BEFORE, "SetTem": "26", "Add0.5": "1"})
    pushes.put_nowait({**BEFORE, "SetTem": "26"})
    await PROBE.confirm_temperature(pushes, EXPECTED, 26, 1)
    assert pushes.empty()


async def test_changed_temperature_with_other_state_change_is_rejected() -> None:
    """A full command template must not silently change a known second field."""
    pushes: asyncio.Queue[dict[str, str]] = asyncio.Queue()
    pushes.put_nowait({**BEFORE, "SetTem": "26", "Pow": "0"})
    with pytest.raises(BinaryAcError, match="another known field"):
        await PROBE.confirm_temperature(pushes, EXPECTED, 26, 1)


@pytest.mark.parametrize("power", [0, 1])
def test_template_selection_preserves_live_power(tmp_path: Path, power: int) -> None:
    """Select an actual captured state instead of replacing the live power bit."""
    (tmp_path / "device-private.json").write_text(json.dumps({"mac": "test"}))
    rows = []
    for captured_power in (1, 0):
        raw = bytearray(50)
        raw[:4] = b"~~\x2f\x01"
        raw[8] = 0x10 | captured_power << 7
        raw[9] = 0xA0
        raw[12] = 0x10
        raw[22] = 8
        pack = {
            "t": "binCmd",
            "hex01": base64.b64encode(raw).decode(),
            "hex6A": base64.b64encode(b"~~\x13\x6a" + bytes(17)).decode(),
        }
        encoded = json.dumps(pack).encode()
        # Use both supported JSON-only and padded capture representations.
        if captured_power == 0:
            padding = 16 - len(encoded) % 16
            encoded += bytes([padding]) * padding
        rows.append({"kind": "request", "raw_hex": encoded.hex()})
    (tmp_path / "pcap-decrypted-private.json").write_text(json.dumps(rows))
    _, template, _ = PROBE.load_template(tmp_path, {**EXPECTED, "Pow": str(power)})
    assert (template[8] >> 7) & 1 == power
