"""Binary codec checks using anonymous captured control byte vectors."""

import base64
import json
from pathlib import Path

from aiogree.binary_ac import (
    BinaryAcError,
    apply_fragments,
    build_bin_cmd,
    decode_bin_status,
    split_bin_status,
)
import pytest


def command_template() -> bytes:
    """Make a synthetic template with the observed network frame shape."""
    raw = bytearray(50)
    raw[:4] = b"~~\x2f\x01"
    raw[8] = 0x11
    raw[9] = 0xA0
    raw[22] = 9
    return bytes(raw)


def report_frame(opcode: int = 0x31, size: int = 52) -> bytes:
    """Build a synthetic status frame; it contains no identity."""
    raw = bytearray(size)
    raw[:4] = bytes((0x7E, 0x7E, size - 3, opcode))
    return bytes(raw)


def encoded(raw: bytes) -> str:
    """Encode bytes as the network's Base64 text."""
    return base64.b64encode(raw).decode("ascii")


HEX6A = b"~~\x13\x6a" + b"EXAMPLEPROFILE00" + b"\x00"
VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "binary_ac_controls.json").read_text()
)["vectors"]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: str(vector["frame"]))
def test_captured_fragments_match_command_and_next_status(vector: dict) -> None:
    """All 16 captured operations agree with sent bytes and later reports."""
    before = bytearray(command_template())
    for index, value in vector["before"].items():
        before[int(index)] = value
    result = apply_fragments(bytes(before), vector["fragment"])
    for _, offset, mask, _ in vector["fragment"]:
        absolute = offset + 3
        assert result[absolute] & mask == vector["command"][str(absolute)] & mask
        assert result[absolute] & mask == vector["after"][str(absolute)] & mask
    assert before[8] == vector["before"]["8"]  # Input was not changed.


@pytest.mark.parametrize(
    ("frame", "power", "temperature", "swing", "fan"),
    [
        (158, 1, 26, 0, None),
        (218, 1, 25, 0, None),
        (268, 1, 25, 0, 0),
        (322, 1, 25, 1, 0),
        (362, 1, 26, 1, 0),
        (379, 0, 26, 1, 0),
    ],
)
def test_captured_control_bytes_decode_basic_state(
    frame: int, power: int, temperature: int, swing: int, fan: int | None
) -> None:
    """Decode each real next-state vector inside an anonymous frame shell."""
    vector = next(item for item in VECTORS if item["frame"] == frame)
    raw = bytearray(report_frame())
    for index, value in vector["after"].items():
        raw[int(index)] = value
    state = decode_bin_status(encoded(bytes(raw))).properties
    assert state["Pow"] == power
    assert state["Mod"] == 1
    assert state["SetTem"] == temperature
    assert state["SwUpDn"] == swing
    assert state["SwingLfRig"] == 0
    assert state.get("WdSpd") == fan


def test_split_real_frame_shapes_and_decode_core_fields() -> None:
    """Status frames retain order; the mode uses bits4..6, not fan bits."""
    frames = [
        report_frame(code, size)
        for code, size in (
            (0x44, 53),
            (0x33, 50),
            (0x31, 52),
            (0x35, 50),
            (0x3C, 51),
            (0x34, 50),
        )
    ]
    state = bytearray(frames[2])
    state[8] = 0x90
    state[9] = 0xA0
    state[12] = 0x13
    state[14] = 8
    state[22] = 8
    state[46] = 65
    frames[2] = bytes(state)
    result = decode_bin_status(encoded(b"".join(frames)))
    assert result.frames == tuple(frames)
    assert result.raw_status == bytes(state)
    assert result.properties == {
        "Pow": 1,
        "Mod": 1,
        "SetTem": 26,
        "TemSen": 65,
        "WdSpd": 0,
        "SwUpDn": 1,
        "SwingLfRig": 3,
    }
    assert result.temperature_extra_bit == 1


def test_nonzero_fan_is_left_unknown() -> None:
    """A fine fan code is not claimed to be the normal WdSpd enum."""
    raw = bytearray(report_frame())
    raw[8] = 0x11
    raw[22] = 9
    assert "WdSpd" not in decode_bin_status(encoded(bytes(raw))).properties


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"xx\x05\x31\x00\x00\x00\x00",
        b"~~",
        b"~~\x00\x31",
        report_frame()[:-1],
        report_frame() + b"x",
    ],
)
def test_bad_status_headers_and_lengths(raw: bytes) -> None:
    """Truncation and trailing bytes must not produce a partial state."""
    with pytest.raises(BinaryAcError):
        split_bin_status(encoded(raw))


@pytest.mark.parametrize("text", ["!not-base64!", "~~~~", "AAAA\n", "A" * 8193])
def test_invalid_base64(text: str) -> None:
    """The Base64 decoder must reject garbage and oversized text."""
    with pytest.raises(BinaryAcError):
        split_bin_status(text)


@pytest.mark.parametrize(
    "raw",
    [
        report_frame(0x33),
        report_frame() * 2,
        report_frame(size=48),
    ],
)
def test_missing_duplicate_or_short_state(raw: bytes) -> None:
    """Only one complete 0x31 frame can supply a state."""
    with pytest.raises(BinaryAcError):
        decode_bin_status(encoded(raw))


@pytest.mark.parametrize(
    "fragment",
    [
        [2, 5, 128, 1],
        [True, 5, 128, 1],
        [1, -1, 128, 1],
        [1, 1, 1, 1],
        [1, 46, 1, 1],
        [1, 5, 0, 1],
        [1, 5, 256, 1],
        [1, 5, 5, 1],
        [1, 5, 128, 2],
        [1, 5, 128, -1],
        [1, 5, 128, True],
        [1, 5, 128],
    ],
)
def test_invalid_fragment_is_rejected(fragment: list) -> None:
    """Type, bounds and contiguous masks are checked before any send."""
    with pytest.raises(BinaryAcError):
        apply_fragments(command_template(), [fragment])


def test_fragment_values_are_shifted_and_unrelated_bits_survive() -> None:
    """A high-nibble value is shifted; ordered writes keep other bits."""
    raw = bytearray(command_template())
    raw[9] = 0xAF
    result = apply_fragments(bytes(raw), [[1, 6, 240, 9], [1, 6, 8, 0]])
    assert result[9] == 0x97
    assert raw[9] == 0xAF


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        command_template()[:-1],
        b"~~\x2e\x01" + bytes(46),
        b"~~\x2f\x31" + bytes(46),
        b"~~\x2f\x01\x01" + bytes(45),
        command_template()[:-1] + b"\xff",
    ],
)
def test_invalid_command_template(raw: bytes) -> None:
    """A status frame cannot be used as a command without model evidence."""
    with pytest.raises(BinaryAcError):
        apply_fragments(raw, [])


def test_build_matches_captured_power_auto_fan_and_swing_fragments() -> None:
    """The known single-property paths have exact captured patch sequences."""
    for properties, frame in (
        ({"Pow": 1}, 158),
        ({"WdSpd": 0}, 268),
        ({"SwUpDn": 1}, 322),
        ({"SetTem": 26}, 362),
        ({"Pow": 0}, 379),
    ):
        expected = next(vector for vector in VECTORS if vector["frame"] == frame)
        result = build_bin_cmd(properties, template=command_template(), hex6a=HEX6A)
        assert result["fragment"] == expected["fragment"]
        assert result["t"] == "binCmd"
        assert result["hex6A"] == encoded(HEX6A)
        assert "mac" not in result


def test_build_mode_temperature_and_both_swings_preserves_other_bits() -> None:
    """Properties share bytes, so changing one must retain the others."""
    original = bytearray(command_template())
    original[8] = 0x93
    original[9] = 0xA7
    original[12] = 0xB6
    original[14] = 0xFF
    original[47] = 0xF9
    result = build_bin_cmd(
        {"Mod": 4, "SetTem": 25, "SwUpDn": 1, "SwingLfRig": 3},
        template=bytes(original),
        hex6a=HEX6A,
    )
    raw = base64.b64decode(result["hex01"])
    assert raw[8] == 0xC3
    assert raw[9] == 0x97
    assert raw[12] == 0x13
    assert raw[14] == 0xF7
    assert raw[47] == 9
    assert original[12] == 0xB6


@pytest.mark.parametrize(
    "properties",
    [
        {},
        {"Pow": 2},
        {"Mod": 5},
        {"SetTem": 25.5},
        {"SetTem": 15},
        {"WdSpd": 1},
        {"SwUpDn": 12},
        {"SwingLfRig": 7},
        {"TemRec": 1},
    ],
)
def test_unknown_or_unsupported_property_is_rejected(properties: dict) -> None:
    """Unproven fan and fractional temperature commands must not be sent."""
    with pytest.raises(BinaryAcError):
        build_bin_cmd(properties, template=command_template(), hex6a=HEX6A)


@pytest.mark.parametrize("hex6a", [b"", HEX6A[:-1], b"~~\x13\x6b" + bytes(17)])
def test_invalid_profile_frame(hex6a: bytes) -> None:
    """The caller must supply the matched 0x6a frame, with its own length rule."""
    with pytest.raises(BinaryAcError):
        build_bin_cmd({"Pow": 1}, template=command_template(), hex6a=hex6a)
