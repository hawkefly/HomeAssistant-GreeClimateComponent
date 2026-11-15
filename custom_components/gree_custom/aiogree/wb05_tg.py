"""Narrow control profile for the captured U-WB05_TGV1.30 air conditioner.

This firmware sends the full hex01 frame to the controller. Use this profile
only with its checked basic settings. Other features must stay at the captured
defaults until their byte mappings are known.
"""

import base64
from collections.abc import Mapping

from .binary_ac import BinaryAcError, apply_fragments, build_bin_cmd
from .errors import GreeProtocolError

WB05_TG_HID = "362001065909+U-WB05_TGV1.30.bin"
WB05_TG_VERSION = "V3.5.M"

# Anonymous network frames from the captured power-off command. No device
# identity, encryption key or account data is stored in these frames.
_TEMPLATE = base64.b64decode(
    "fn4vAQAAAAAQoAICEAAAAAAAAAAAqggAu7u6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)
_PROFILE = base64.b64decode("fn4TajFfMl9mMzcwNDU1MzBjZjQA")

# These settings are not changed by this profile. Reject a command when the
# full push reports a different value, rather than replacing that feature
# with the captured default as a side effect of sending the whole frame.
_REQUIRED_DEFAULTS = {
    "TemUn": "0",
    "Tur": "0",
    "Quiet": "0",
    "Health": "0",
    "Lig": "1",
    "SlpMod": "0",
    "SwhSlp": "0",
    "Air": "0",
    "Blo": "0",
    "SvSt": "0",
    "StHt": "0",
    "AssHt": "0",
    "AntiDirectBlow": "0",
    "UDFanPort": "0",
    "SmartWind": "0",
    "SmartSlpMod": "0",
    "NobodySave": "0",
    "UnmanedShutDown": "0",
    "AutoClean": "0",
    "Coolmod": "0",
    "Wind": "0",
    "DnPUDSwing": "0",
    "DnPLLRSwing": "0",
    "DnPRLRSwing": "0",
    "PowReduceType": "0",
    "AutoPowReduce": "0",
    "PowReduceGear": "0",
    "CoolFeel": "0",
    "BuzzerCtrl": "1",
    "ChildLock": "0",
    "Emod": "0",
    "VocCtl": "0",
    "Wet": "0",
    "Dmod": "0",
    "Dwet": "0",
    "Dpump": "0",
    "DsplySt": "0",
    "EnvFun": "0",
    "UvcControl": "0",
    "SmartSlpModEx": "5",
    "Dazzling": "0",
    "WisdomRisk": "0",
    "OxygenSwitch": "0",
    "NightLig": "0",
}
_CONTROL_NAMES = frozenset(
    ("Pow", "Mod", "SetTem", "WdSpd", "SwUpDn", "SwingLfRig", "TemRec", "TemUn")
)


def matches_wb05_tg(info: Mapping[str, str]) -> bool:
    """Match the hardware and firmware, never just a broad model id."""
    return (
        info.get("mid") == "10015"
        and info.get("hid") == WB05_TG_HID
        and info.get("ver") == WB05_TG_VERSION
    )


def _read_int(state: Mapping[str, str], name: str, minimum: int, maximum: int) -> int:
    try:
        value = int(state[name])
    except (KeyError, TypeError, ValueError) as err:
        raise GreeProtocolError(f"Binary AC status is missing a valid {name}") from err
    if not minimum <= value <= maximum:
        raise GreeProtocolError(f"Binary AC status has unsupported {name}")
    return value


def _validate_changes(values: Mapping[str, int], state: Mapping[str, str]) -> None:
    """Reject settings outside the checked template and feature defaults."""
    if not values or values.keys() - _CONTROL_NAMES:
        raise GreeProtocolError("This binary AC control is not supported")
    if any(isinstance(v, bool) or not isinstance(v, int) for v in values.values()):
        raise GreeProtocolError("Binary AC controls require integer values")
    for name, expected in _REQUIRED_DEFAULTS.items():
        if state.get(name) != expected:
            raise GreeProtocolError(
                f"Binary AC requires the captured default for {name}; use the Gree app"
            )
    if values.get("Mod", 1) != 1 or values.get("WdSpd", 0) != 0:
        raise GreeProtocolError(
            "This binary AC profile supports cooling and auto fan only"
        )
    if values.get("SwingLfRig", 0) != 0 or values.get("SwUpDn", 0) not in (0, 1):
        raise GreeProtocolError(
            "This binary AC profile supports vertical stop/full swing only"
        )
    if values.get("TemUn", 0) != 0 or values.get("TemRec", 0) != 0:
        raise GreeProtocolError(
            "This binary AC profile writes whole Celsius degrees only"
        )
    if "TemRec" in values and "SetTem" not in values:
        raise GreeProtocolError("The temperature bit requires a target temperature")


def prepare_wb05_tg_command(
    values: Mapping[str, int], state: Mapping[str, str]
) -> tuple[dict[str, int], bytes, bytes]:
    """Preserve live basic state, then apply a supported user change.

    The caller must supply a new full push from this device before every
    command. Acknowledgement alone must not update local state. Fractional
    temperatures can be read, but only whole Celsius degrees can be written.
    """
    if not matches_wb05_tg(state):
        raise GreeProtocolError("Binary AC hardware or firmware does not match")
    _validate_changes(values, state)
    half = _read_int(state, "Add0.5", 0, 1)
    if half and "SetTem" not in values:
        raise GreeProtocolError(
            "Set a whole Celsius temperature before changing another control"
        )
    basic = {
        "Pow": _read_int(state, "Pow", 0, 1),
        "Mod": _read_int(state, "Mod", 1, 1),
        "SetTem": _read_int(state, "SetTem", 16, 31),
        "WdSpd": _read_int(state, "WdSpd", 0, 0),
        "SwUpDn": _read_int(state, "SwUpDn", 0, 1),
        "SwingLfRig": _read_int(state, "SwingLfRig", 0, 0),
    }
    # Copy known live fields into the captured frame without running the
    # extra power-off fragment operations while merely preparing a template.
    fragments = [
        [1, 5, 128, basic["Pow"]],
        [1, 5, 112, basic["Mod"]],
        [1, 6, 240, basic["SetTem"] - 16],
        [1, 9, 240, basic["SwUpDn"]],
    ]
    try:
        template = apply_fragments(_TEMPLATE, fragments)
        changes = {k: v for k, v in values.items() if k not in ("TemRec", "TemUn")}
        if not changes:
            raise GreeProtocolError("No supported binary AC change was requested")
        build_bin_cmd(changes, template=template, hex6a=_PROFILE)
    except BinaryAcError as err:
        raise GreeProtocolError("Invalid binary AC control value") from err
    return changes, template, _PROFILE
