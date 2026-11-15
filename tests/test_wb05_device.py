"""The exact WB05-TG profile uses fresh pushes and guarded binary commands."""

import math
from unittest.mock import AsyncMock, MagicMock, patch

from aiogree.api import GreeProp, InfoProp, StatusResult, TemperatureUnits
from aiogree.device import GreeDevice
from aiogree.device_api_client import DeviceApiClient
from aiogree.errors import GreeConnectionError, GreeProtocolError
from aiogree.transport_mqtt import GreeMqttTransport
from aiogree.transport_udp import GreeUdpTransport
import pytest

from .test_wb05_end_to_end import KEY, MAC as MODULE_MAC, BinaryModuleTransport

MAC = "aabbccddeeff"
INFO = {
    "mid": "10015",
    "hid": "362001065909+U-WB05_TGV1.30.bin",
    "ver": "V3.5.M",
}
STATE = {
    "Pow": "0",
    "Mod": "1",
    "SetTem": "26",
    "TemRec": "0",
    "TemUn": "0",
    "WdSpd": "0",
    "SwUpDn": "0",
    "SwingLfRig": "0",
    "TemSen": "65",
}


async def bind_profile(
    info: dict[str, str],
    *,
    mqtt: bool = True,
    early_status: dict[str, str] | None = None,
) -> tuple[GreeDevice, MagicMock]:
    """Bind through a mocked client without contacting a device or broker."""
    transport = MagicMock(spec=GreeMqttTransport if mqtt else GreeUdpTransport)
    client = MagicMock(spec=DeviceApiClient)
    client.transport = transport
    client.controller_mac = MAC
    client.query_props = AsyncMock(
        side_effect=[StatusResult(info, []), StatusResult(STATE, [])]
    )
    if early_status:
        reports = iter([StatusResult(info, []), StatusResult(STATE, [])])

        async def query(*_args, **_kwargs) -> StatusResult:
            if client.query_props.await_count == 1:
                listener = client.add_status_listener.call_args.args[0]
                listener(early_status)
            return next(reports)

        client.query_props.side_effect = query
    client.set_binary_props = AsyncMock()
    with patch("aiogree.device.DeviceApiClient", return_value=client):
        device = GreeDevice("Test AC", MAC)
    if mqtt:
        await device.bind_with_transport(
            mqtt_transport=transport, mqtt_controller_mac=MAC
        )
    else:
        await device.bind_with_transport(
            local_transport=transport, local_controller_mac=MAC
        )
    return device, client


@pytest.mark.parametrize(
    "changes",
    [
        {"mid": "10001"},
        {"hid": "362001065909+U-WB05_TGV1.31.bin"},
        {"ver": "V3.5.N"},
        {"ver": ""},
    ],
)
async def test_other_profile_keeps_standard_status(changes: dict[str, str]) -> None:
    """A shared model id cannot enable a different hardware or firmware."""
    device, client = await bind_profile({**INFO, **changes})
    assert not device.is_binary_ac
    client.configure_binary_ac_status.assert_not_called()


async def test_exact_profile_requires_mqtt() -> None:
    """The verified firmware profile is not enabled for a UDP connection."""
    device, client = await bind_profile(INFO, mqtt=False)
    assert not device.is_binary_ac
    client.configure_binary_ac_status.assert_not_called()


async def test_exact_profile_activates_after_info() -> None:
    """Only a completed info fetch enables binary status before the first poll."""
    device, client = await bind_profile(INFO)
    assert device.is_binary_ac
    client.configure_binary_ac_status.assert_called_once_with()
    methods = [call[0] for call in client.mock_calls]
    assert methods.index("query_props") < methods.index("configure_binary_ac_status")
    assert methods.index("configure_binary_ac_status") < methods.index(
        "query_props", methods.index("query_props") + 1
    )
    assert not device.supports_property(GreeProp.BEEPER)
    assert not device.supports_property(GreeProp.FEAT_TURBO_MODE)


async def test_binary_command_reads_before_and_after_send() -> None:
    """Sending a command requires fresh state and a new status after its ACK."""
    device, client = await bind_profile(INFO)
    events: list[str] = []
    reports = iter([STATE, {**STATE, "Pow": "1"}])

    async def query(*_args, **_kwargs) -> StatusResult:
        events.append("query")
        return StatusResult(next(reports), [])

    def prepare(values, snapshot):
        events.append("prepare")
        assert values == {"Pow": 1}
        assert snapshot == {**INFO, **STATE, "Add0.5": "0"}
        return values, b"template", b"profile"

    async def send(*_args) -> None:
        events.append("send")

    client.binary_ac_status = {**STATE, "Add0.5": "0"}
    client.query_props.side_effect = query
    client.set_binary_props.side_effect = send
    device.set_power_mode(True)
    with patch("aiogree.device.prepare_wb05_tg_command", side_effect=prepare):
        await device.push_device_status()
    assert events == ["query", "prepare", "send", "query"]
    client.set_binary_props.assert_awaited_once_with(
        {"Pow": 1}, b"template", b"profile"
    )
    client.set_props.assert_not_awaited()
    assert device.power_mode is True


async def test_command_ack_without_push_does_not_confirm_state() -> None:
    """A successful send cannot replace the last device-reported value."""
    device, client = await bind_profile(INFO)
    client.query_props.side_effect = [
        StatusResult(STATE, []),
        GreeConnectionError("No new binary status"),
    ]
    device.set_power_mode(True)
    with (
        patch(
            "aiogree.device.prepare_wb05_tg_command",
            return_value=({"Pow": 1}, b"template", b"profile"),
        ),
        pytest.raises(GreeConnectionError),
    ):
        await device.push_device_status()
    client.set_binary_props.assert_awaited_once()
    assert device.power_mode is False


@pytest.mark.parametrize("value", [15, 32, 25.5, math.nan, math.inf])
async def test_binary_temperature_rejects_unsupported_values(value: float) -> None:
    """A binary command must not silently round or clamp a requested value."""
    device, _client = await bind_profile(INFO)
    with pytest.raises(GreeProtocolError, match="integer temperature"):
        device.set_target_temperature(value)


async def test_binary_temperature_unit_stays_celsius() -> None:
    """The protocol unit cannot switch to the unverified Fahrenheit mapping."""
    device, _client = await bind_profile(INFO)
    with pytest.raises(GreeProtocolError, match="only support Celsius"):
        device.set_target_temperature_unit(TemperatureUnits.F)
    assert device.target_temperature_unit is TemperatureUnits.C


async def test_binary_status_keeps_half_degree_readback() -> None:
    """Half degrees remain visible even though commands require whole degrees."""
    device, client = await bind_profile(INFO)
    client.query_props.side_effect = [StatusResult({**STATE, "TemRec": "1"}, [])]
    await device.fetch_device_status()
    assert device.target_temperature == 26.5
    device.set_target_temperature(27)
    assert device.target_temperature == 27


async def test_early_full_push_cannot_enable_advanced_features() -> None:
    """Fields received before the profile check are removed from capabilities."""
    device, _client = await bind_profile(INFO, early_status={"Tur": "1", "Lig": "1"})
    assert device.is_binary_ac
    assert not device.supports_property(GreeProp.FEAT_TURBO_MODE)
    assert not device.supports_property(GreeProp.FEAT_LIGHT)


async def test_mqtt_malformed_batch_retries_each_info_column() -> None:
    """A truncated info batch cannot shift values into the wrong columns."""
    transport = BinaryModuleTransport()
    original = transport.request_json

    async def malformed_reply(*args, **kwargs):
        response = await original(*args, **kwargs)
        pack = response.get("pack", {})
        cols = pack.get("cols", [])
        if "mid" in cols and len(cols) > 1:
            # Keep cols intact while removing an earlier value. Zipping the
            # arrays would attach the wrong hardware and firmware strings.
            pack["dat"].pop(0)
        elif cols == ["ModelType"]:
            # A single unsupported info field is missing, not a new error.
            pack["dat"] = []
        return response

    device = GreeDevice(
        "Synthetic WB05", MODULE_MAC, preferred_encryption_key=KEY, user_id=1234
    )
    try:
        with patch.object(transport, "request_json", side_effect=malformed_reply):
            await device.bind_with_transport(
                mqtt_transport=transport, mqtt_controller_mac=MODULE_MAC
            )
        assert device.is_binary_ac
        assert device.target_temperature == 25
        columns = [p["cols"] for p in transport.packs if p["t"] == "status"]
        info_columns = [prop.value for prop in InfoProp]
        batch_index = columns.index(info_columns)
        assert columns[batch_index + 1 :] == [[prop] for prop in info_columns]
    finally:
        await device.unbind_device()


async def test_udp_malformed_info_batch_still_raises() -> None:
    """UDP keeps its existing error path without a metadata retry sweep."""
    device, client = await bind_profile(INFO, mqtt=False)
    client.query_props.reset_mock()
    client.query_props.side_effect = GreeProtocolError("Malformed response")
    with pytest.raises(GreeProtocolError, match="Malformed response"):
        await device.fetch_device_info()
    columns = [prop.value for prop in InfoProp]
    client.query_props.assert_awaited_once_with(columns, len(columns))


async def test_mqtt_info_connection_error_is_not_retried_as_missing() -> None:
    """A lost connection does not become a successful empty metadata read."""
    device, client = await bind_profile(INFO)
    client.query_props.reset_mock()
    client.query_props.side_effect = GreeConnectionError("Disconnected")
    with pytest.raises(GreeConnectionError, match="Disconnected"):
        await device.fetch_device_info()
    columns = [prop.value for prop in InfoProp]
    client.query_props.assert_awaited_once_with(columns, len(columns))
