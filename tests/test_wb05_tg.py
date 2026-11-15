"""The exact firmware profile preserves basic state and refuses unknown modes."""

import base64
import json
from pathlib import Path

from aiogree.binary_ac import build_bin_cmd
from aiogree.errors import GreeProtocolError
from aiogree.wb05_tg import matches_wb05_tg, prepare_wb05_tg_command
import pytest


@pytest.fixture(name="full_state")
def captured_full_state() -> dict[str, str]:
    """Use anonymous full state fields with captured feature defaults."""
    return json.loads(
        (Path(__file__).parent / "fixtures" / "wb05_tg_state.json").read_text()
    )


def test_profile_needs_exact_hardware_and_version(full_state: dict[str, str]) -> None:
    """The broad 10015 model id alone must never select this frame layout."""
    assert matches_wb05_tg(full_state)
    for key in ("mid", "hid", "ver"):
        assert not matches_wb05_tg({**full_state, key: "other"})


def test_temperature_command_matches_real_captured_bytes(
    full_state: dict[str, str],
) -> None:
    """The matched cooling/auto/swing state reproduces the 26 C command."""
    props, template, profile = prepare_wb05_tg_command(
        {"SetTem": 26, "TemRec": 0}, full_state
    )
    pack = build_bin_cmd(props, template=template, hex6a=profile)
    assert (
        pack["hex01"]
        == "fn4vAQAAAACQoAICEAAAAAAAAAAAqggAu7u6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )


@pytest.mark.parametrize("power", [0, 1])
@pytest.mark.parametrize("swing", [0, 1])
def test_temperature_keeps_live_power_and_swing(
    full_state: dict[str, str], power: int, swing: int
) -> None:
    """Sending a whole frame must not restore the captured power/swing state."""
    props, template, profile = prepare_wb05_tg_command(
        {"SetTem": 25}, {**full_state, "Pow": str(power), "SwUpDn": str(swing)}
    )
    raw = base64.b64decode(
        build_bin_cmd(props, template=template, hex6a=profile)["hex01"]
    )
    assert raw[8] >> 7 == power
    assert raw[12] >> 4 == swing
    assert raw[9] >> 4 == 9


@pytest.mark.parametrize(
    "values",
    [
        {"WdSpd": 1},
        {"Mod": 4},
        {"SwUpDn": 2},
        {"SwingLfRig": 1},
        {"SetTem": 15},
        {"SetTem": 32},
        {"TemRec": 1},
        {"TemUn": 1},
        {"Tur": 1},
        {"Pow": 2},
        {"Pow": True},
        {"Pow": "1"},
        {"SetTem": 25.5},
        {},
        {"TemRec": 0},
    ],
)
def test_unproven_controls_are_rejected(
    full_state: dict[str, str], values: dict
) -> None:
    """Unsupported settings fail before transport or state changes."""
    with pytest.raises(GreeProtocolError):
        prepare_wb05_tg_command(values, full_state)


@pytest.mark.parametrize(
    ("field", "value"),
    [("Tur", "1"), ("Lig", "0"), ("SmartSlpModEx", "0"), ("Quiet", "2")],
)
def test_active_extra_features_stop_the_command(
    full_state: dict[str, str], field: str, value: str
) -> None:
    """A fixed whole-frame template must not turn off an extra feature."""
    with pytest.raises(GreeProtocolError, match="captured default"):
        prepare_wb05_tg_command({"SetTem": 26}, {**full_state, field: value})


@pytest.mark.parametrize("key", ["Tur", "Pow", "Add0.5", "hid"])
def test_incomplete_snapshot_cannot_build_a_control(
    full_state: dict[str, str], key: str
) -> None:
    """No field is filled from a guessed or old cache value."""
    full_state.pop(key)
    with pytest.raises(GreeProtocolError):
        prepare_wb05_tg_command({"Pow": 0}, full_state)


def test_half_degree_requires_an_explicit_whole_temperature(
    full_state: dict[str, str],
) -> None:
    """Do not change 25.5 to 25 as a side effect of a power command."""
    state = {**full_state, "Add0.5": "1"}
    with pytest.raises(GreeProtocolError, match="whole Celsius"):
        prepare_wb05_tg_command({"Pow": 0}, state)
    props, _, _ = prepare_wb05_tg_command({"SetTem": 26, "TemRec": 0}, state)
    assert props == {"SetTem": 26}
