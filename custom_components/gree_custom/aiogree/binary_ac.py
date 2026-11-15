"""Experimental binary AC codec, without transport or device identity.

The layout follows captured 0x31 reports and 0x01 network commands. Network
frames have zero checksum placeholders. They are not physical UART packets.
Only the auto fan setting has been checked against this device family.
"""

import base64
import binascii
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


class BinaryAcError(ValueError):
    """A binary packet or requested property is outside the known format."""


@dataclass(frozen=True)
class BinaryAcStatus:
    """Keep raw frames so callers can retain fields this codec cannot name."""

    frames: tuple[bytes, ...]
    raw_status: bytes
    properties: dict[str, int]
    temperature_extra_bit: int


def _integer(value: object, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise BinaryAcError("Value is outside the supported integer range")
    return value


def split_bin_status(encoded: str) -> tuple[bytes, ...]:
    """Decode a complete Base64 binStatus into length-prefixed subframes."""
    if not isinstance(encoded, str) or not encoded or len(encoded) > 8192:
        raise BinaryAcError("Invalid binStatus text length")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as err:
        raise BinaryAcError("Invalid binStatus Base64") from err
    frames = []
    offset = 0
    while offset < len(raw):
        if raw[offset : offset + 2] != b"~~" or len(raw) - offset < 4:
            raise BinaryAcError("Invalid binStatus frame header")
        length = raw[offset + 2] + 3
        if length < 5 or offset + length > len(raw):
            raise BinaryAcError("Invalid binStatus frame length")
        frames.append(raw[offset : offset + length])
        offset += length
    if not frames:
        raise BinaryAcError("Empty binStatus")
    return tuple(frames)


def decode_bin_status(encoded: str) -> BinaryAcStatus:
    """Read known fields, leaving the extra temperature bit uninterpreted."""
    frames = split_bin_status(encoded)
    reports = [frame for frame in frames if frame[3] == 0x31]
    if len(reports) != 1 or len(reports[0]) < 49:
        raise BinaryAcError("Expected one complete 0x31 state report")
    raw = reports[0]
    properties = {
        "Pow": (raw[8] & 0x80) >> 7,
        "Mod": (raw[8] & 0x70) >> 4,
        "SetTem": (raw[9] >> 4) + 16,
        "TemSen": raw[46],
        "SwUpDn": raw[12] >> 4,
        "SwingLfRig": raw[12] & 0x07,
    }
    # Nonzero fine fan codes need a model-specific speed table.
    if raw[8] & 0x03 == 0 and raw[22] & 0x07 == 0:
        properties["WdSpd"] = 0
    return BinaryAcStatus(frames, raw, properties, (raw[14] & 0x08) >> 3)


def _validate_template(template: bytes) -> None:
    if (
        not isinstance(template, bytes)
        or len(template) != 50
        or template[:4] != b"~~\x2f\x01"
        or template[4:8] != bytes(4)
        or template[-1] != 0
    ):
        raise BinaryAcError("Expected a 50-byte 0x01 network command template")


def apply_fragments(template: bytes, fragments: Sequence[Sequence[int]]) -> bytes:
    """Apply [opcode, offset, mask, unshifted value] records to a copy."""
    _validate_template(template)
    if not isinstance(fragments, (list, tuple)) or len(fragments) > 64:
        raise BinaryAcError("Invalid fragment list")
    result = bytearray(template)
    for record in fragments:
        if not isinstance(record, (list, tuple)) or len(record) != 4:
            raise BinaryAcError("A fragment must have four integers")
        opcode, offset, mask, value = record
        _integer(opcode, 1, 1)
        absolute = _integer(offset, 5, len(template) - 5) + 3
        _integer(mask, 1, 255)
        shift = (mask & -mask).bit_length() - 1
        width_mask = mask >> shift
        if width_mask & (width_mask + 1):
            raise BinaryAcError("Fragment mask must have contiguous bits")
        _integer(value, 0, width_mask)
        result[absolute] = (result[absolute] & ~mask) | (value << shift)
    return bytes(result)


def build_bin_cmd(
    properties: Mapping[str, int], *, template: bytes, hex6a: bytes
) -> dict[str, Any]:
    """Build a network command using caller-supplied, matched model frames.

    This accepts whole Celsius degrees only. The two related temperature
    fields are cleared as in captured whole-degree commands. Their meaning
    and fractional settings are not inferred. Fan control accepts auto only.
    The caller adds the device identity and encrypts the returned pack.
    """
    _validate_template(template)
    if (
        not isinstance(hex6a, bytes)
        or len(hex6a) != 21
        or hex6a[:4] != b"~~\x13\x6a"
        or hex6a[-1] != 0
    ):
        raise BinaryAcError("Expected a caller-supplied 21-byte 0x6a frame")
    if not isinstance(properties, Mapping) or not properties:
        raise BinaryAcError("Expected at least one supported property")
    fragments: list[list[int]] = []
    for name, value in properties.items():
        if name == "Pow":
            _integer(value, 0, 1)
            if not value:
                fragments.extend([[1, 5, 8, 0], [1, 7, 4, 0]])
            fragments.extend([[1, 6, 8, 0], [1, 5, 128, value]])
        elif name in ("Mod", "SwUpDn", "SwingLfRig"):
            offset, mask, maximum = {
                "Mod": (5, 112, 4),
                "SwUpDn": (9, 240, 11),
                "SwingLfRig": (9, 7, 6),
            }[name]
            fragments.append([1, offset, mask, _integer(value, 0, maximum)])
        elif name == "SetTem":
            value = _integer(value, 16, 31)
            fragments.extend([[1, 44, 240, 0], [1, 6, 240, value - 16], [1, 11, 8, 0]])
        elif name == "WdSpd":
            _integer(value, 0, 0)
            fragments.extend([[1, 19, 7, 0], [1, 5, 3, 0], [1, 17, 12, 0]])
        else:
            raise BinaryAcError("Unsupported binary AC property")
    command = apply_fragments(template, fragments)
    return {
        "t": "binCmd",
        "hex01": base64.b64encode(command).decode("ascii"),
        "hex6A": base64.b64encode(hex6a).decode("ascii"),
        "fragment": fragments,
    }
