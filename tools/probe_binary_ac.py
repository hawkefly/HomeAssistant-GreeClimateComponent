"""Test one captured binary temperature command and check later cloud pushes.

Credentials stay in the terminal. No command is sent without --send. The
capture directory is local evidence from this investigation, not an export.
"""

# ruff: noqa: INP001, T201

import argparse
import asyncio
import base64
from getpass import getpass
import json
import logging
from pathlib import Path
import sys
import traceback
from typing import override

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "custom_components" / "gree_custom")
)

from aiogree.api import (
    gree_discover_devices_cloud,
    gree_get_status,
    gree_process_status_pack,
    gree_set_binary_status,
    gree_set_status,
)
from aiogree.binary_ac import BinaryAcError, build_bin_cmd
from aiogree.cipher import CipherBase, EncryptionVersion, get_cipher
from aiogree.cloud_api import GreeCloudApi, GreeRegion
from aiogree.device import GreeDevice
from aiogree.helpers import gree_decrypt_pack
from aiogree.transport_mqtt import GreeMqttTransport


def load_template(
    capture: Path, live_state: dict[str, str] | None = None
) -> tuple[dict, bytes, bytes]:
    """Select a captured whole-degree command that matches known live fields."""
    identity = json.loads((capture / "device-private.json").read_text())
    rows = json.loads((capture / "pcap-decrypted-private.json").read_text())
    candidates = []
    for row in rows:
        if row["kind"] != "request":
            continue
        raw = bytes.fromhex(row["raw_hex"])
        if raw and 1 <= raw[-1] <= 16 and raw.endswith(bytes([raw[-1]]) * raw[-1]):
            raw = raw[: -raw[-1]]
        pack = json.loads(raw.rstrip(b"\0"))
        if pack.get("t") != "binCmd":
            continue
        template = base64.b64decode(pack["hex01"], validate=True)
        if (
            len(template) != 50
            or template[14] & 8
            or template[8] & 3
            or template[22] & 7
        ):
            continue
        known = template_state(template)
        if live_state is not None and any(
            live_state.get(k) != v for k, v in known.items()
        ):
            continue
        hex6a = base64.b64decode(pack["hex6A"], validate=True)
        build_bin_cmd({"SetTem": 26}, template=template, hex6a=hex6a)
        candidates.append((template, hex6a))
    if not candidates:
        raise BinaryAcError(
            "No captured whole-degree auto-fan template matches the live state"
        )
    return identity, *candidates[-1]


def template_state(template: bytes) -> dict[str, str]:
    """Expose known state fields that must match before a temperature test."""
    if template[8] & 3 or template[22] & 7:
        raise BinaryAcError("This test requires an auto-fan command template")
    return {
        "Pow": str((template[8] >> 7) & 1),
        "Mod": str((template[8] >> 4) & 7),
        "WdSpd": "0",
        "SwUpDn": str(template[12] >> 4),
        "SwingLfRig": str(template[12] & 7),
    }


def validate_live_state(
    before: dict[str, str], expected: dict[str, str], temperature: int
) -> None:
    """Reject a stale template and a test that would leave temperature unchanged."""
    if (
        before.get("mid") != "10015"
        or before.get("hid") != "362001065909+U-WB05_TGV1.30.bin"
    ):
        raise BinaryAcError("Live hardware profile differs from the captured target")
    if any(before.get(key) != value for key, value in expected.items()):
        raise BinaryAcError(
            "Live power/mode/fan/swing differs from template; no command sent"
        )
    if before["SetTem"] == str(temperature) and before["Add0.5"] == "0":
        raise BinaryAcError(
            "Temperature already matches; choose a different temperature"
        )


async def confirm_temperature(
    pushes: asyncio.Queue[dict[str, str]],
    expected: dict[str, str],
    temperature: int,
    wait_seconds: int,
) -> None:
    """Require a later state push; a reply alone is not confirmation."""
    async with asyncio.timeout(wait_seconds):
        while True:
            after = await pushes.get()
            print("After:", {k: after.get(k) for k in (*expected, "SetTem", "Add0.5")})
            if after["SetTem"] == str(temperature) and after["Add0.5"] == "0":
                if any(after.get(key) != value for key, value in expected.items()):
                    raise BinaryAcError(
                        "Temperature changed, but another known field also changed"
                    )
                print("CONFIRMED: later full push reports the requested temperature.")
                return


async def request_full_report(
    transport: GreeMqttTransport,
    cipher: CipherBase,
    mac: str,
    controller: str,
    uid: int,
) -> None:
    """Use the captured report request; it may have no response topic reply."""
    payload = {
        "t": "pack",
        "i": 0,
        "uid": uid,
        "cid": "app",
        "tcid": controller,
        "pack": {
            "mac": mac,
            "t": "freqCount",
            "opt": ["SendFreq", "FreqTime"],
            "p": [1, 300],
        },
    }
    try:
        await transport.request_json(
            controller, payload, cipher, max_attempts=1, timeout=3
        )
    except TimeoutError:
        print("Report request has no response reply; waiting for a push.", flush=True)


class TracedGreeDevice(GreeDevice):  # type: ignore[misc]  # CLI imports from the component path.
    """Show setup stages without printing credentials or response contents."""

    @override
    async def fetch_device_info(self) -> None:
        """Label the information query separately from binding."""
        print("Stage: HA client device information query", flush=True)
        await super().fetch_device_info()
        print(
            f"Stage: HA information received; exact profile={self.firmware_version}",
            flush=True,
        )

    @override
    async def fetch_device_status(self, first_fetch: bool = False) -> None:
        """Label the fresh status wait and profile activation."""
        print(
            f"Stage: HA client full status poll; binary={self.is_binary_ac}", flush=True
        )
        await super().fetch_device_status(first_fetch)


async def probe_ha_client(
    mac: str,
    key: str | None,
    userid: int,
    transport: GreeMqttTransport,
    temperature: int,
) -> bool:
    """Use the same device setup, poll and command code as Home Assistant."""
    device = TracedGreeDevice(
        "WB05 verification", mac, preferred_encryption_key=key, user_id=userid
    )
    try:
        print(
            "Stage: HA client bind, exact profile detection and initial full poll",
            flush=True,
        )
        await device.bind_with_transport(
            mqtt_transport=transport, mqtt_controller_mac=mac
        )
        if not device.is_binary_ac:
            raise BinaryAcError("HA client did not enable the exact WB05-TG profile")
        print(
            f"HA before: power={device.power_mode}, target={device.target_temperature}, room={device.indoors_temperature_c}"
        )
        if device.target_temperature == temperature:
            raise BinaryAcError(
                "Temperature already matches; choose a different temperature"
            )
        was_on = device.power_mode
        device.set_target_temperature(temperature)
        print(
            "Stage: HA client guarded command and fresh confirmation poll", flush=True
        )
        await device.push_device_status()
        print(
            f"HA after: power={device.power_mode}, target={device.target_temperature}, room={device.indoors_temperature_c}"
        )
        if device.target_temperature != temperature or device.power_mode != was_on:
            raise BinaryAcError("HA client received a different resulting state")
        print(
            "CONFIRMED: the HA device client reports the changed temperature and preserved power."
        )
        return True
    finally:
        await device.unbind_device()
        await transport.disconnect()


async def initial_status(
    pushes: asyncio.Queue[dict[str, str]],
    wait_seconds: int,
) -> dict[str, str]:
    """Wait for full state without sending a control on timeout."""
    try:
        return await asyncio.wait_for(pushes.get(), timeout=wait_seconds)
    except TimeoutError as err:
        raise BinaryAcError("No initial full status push; no control sent") from err


async def probe(args: argparse.Namespace) -> bool:
    """Watch real pushes, send once if requested, then require a changed push."""
    identity, template, hex6a = load_template(args.capture)
    expected = template_state(template)
    print(f"Captured template state: {expected}")
    print(f"Requested whole-degree temperature: {args.temperature} C")
    if not args.send:
        print("Preview only. Add --send to connect and send one command.")
        return True

    username = (await asyncio.to_thread(input, "Gree account: ")).strip()
    password = await asyncio.to_thread(getpass, "Gree password: ")
    async with GreeCloudApi(GreeRegion[args.region], username, password) as cloud:
        print("Stage: cloud login", flush=True)
        credentials = await cloud.login()
        print("Stage: account device discovery", flush=True)
        devices = await gree_discover_devices_cloud(cloud)
        device = next((dev for dev in devices if dev.mac == identity["mac"]), None)
        if device is None or device.ver != identity["firmware"]:
            raise BinaryAcError(
                "Capture identity or firmware does not match the account"
            )
        cipher = get_cipher(EncryptionVersion.V1, device.key)
        transport = GreeMqttTransport(
            str(credentials.user_id), credentials.token, GreeRegion[args.region]
        )
        if args.ha_client:
            return await probe_ha_client(
                device.mac, device.key, credentials.user_id, transport, args.temperature
            )
        pushes: asyncio.Queue[dict[str, str]] = asyncio.Queue()

        def pushed(topic: str, envelope: dict) -> None:
            kind = topic.split("/", maxsplit=1)[0]
            print(f"Push received: {kind}", flush=True)
            if kind != "status":
                return
            try:
                pack = gree_decrypt_pack(envelope.copy(), cipher).get("pack", {})
                state = gree_process_status_pack(pack, None).prop_values
                if {"Pow", "Mod", "SetTem", "Add0.5", "mid", "hid"} <= state.keys():
                    pushes.put_nowait(state)
            except Exception as err:  # noqa: BLE001 - keep listening without secret output
                print(f"Push decode failed: {type(err).__name__}")

        try:
            print("Stage: MQTT connect and subscribe", flush=True)
            # A retained status can arrive while the remaining topics subscribe.
            transport.add_listener(device.mac, pushed)
            await transport.add_device(device.mac, device.mac_controller_mqtt)
            print(
                "Stage: read-only wake query (returned values are ignored)", flush=True
            )
            await gree_get_status(
                device.mac_controller_mqtt,
                device.mac,
                credentials.user_id,
                ["Pow", "Mod", "SetTem", "TemSen"],
                cipher,
                transport,
                timeout=10,
            )
            print("Stage: request full status report (freqCount 1,300)", flush=True)
            await request_full_report(
                transport,
                cipher,
                device.mac,
                device.mac_controller_mqtt,
                credentials.user_id,
            )
            print("Stage: waiting for initial full status; no control sent", flush=True)
            before = await initial_status(pushes, args.wait)
            print(
                "Before:", {k: before.get(k) for k in (*expected, "SetTem", "Add0.5")}
            )
            _, template, hex6a = load_template(args.capture, before)
            expected = template_state(template)
            print(f"Matched captured template state: {expected}")
            validate_live_state(before, expected, args.temperature)
            while not pushes.empty():
                pushes.get_nowait()
            print(f"Stage: sending one {args.protocol} temperature command", flush=True)
            if args.protocol == "json":
                await gree_set_status(
                    device.mac_controller_mqtt,
                    device.mac,
                    credentials.user_id,
                    {"SetTem": args.temperature},
                    cipher,
                    transport,
                )
            else:
                await gree_set_binary_status(
                    device.mac_controller_mqtt,
                    device.mac,
                    credentials.user_id,
                    {"SetTem": args.temperature},
                    template,
                    hex6a,
                    cipher,
                    transport,
                )
            print("Request accepted. Waiting for a later full status push.")
            await confirm_temperature(pushes, expected, args.temperature, args.wait)
            return True
        finally:
            await transport.disconnect()


def main() -> None:
    """Require explicit send options and keep errors free of account data."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--temperature", type=int, choices=range(16, 32), required=True)
    parser.add_argument("--region", choices=GreeRegion.__members__, default="CN")
    parser.add_argument("--protocol", choices=("binary", "json"), default="binary")
    parser.add_argument("--wait", type=int, default=45)
    parser.add_argument("--send", action="store_true")
    parser.add_argument(
        "--ha-client",
        action="store_true",
        help="Test the full Home Assistant device path",
    )
    args = parser.parse_args()
    if not 5 <= args.wait <= 120:
        parser.error("--wait must be between 5 and 120 seconds")
    logging.disable(logging.CRITICAL)
    try:
        success = asyncio.run(probe(args))
    except Exception as err:  # noqa: BLE001 - library errors can contain account data
        if isinstance(err, BinaryAcError):
            print(f"Stopped: {err}")
        else:
            print(f"Test failed: {type(err).__name__}")
            if args.ha_client:
                current: BaseException | None = err
                while current is not None:
                    frames = traceback.extract_tb(current.__traceback__)
                    print(
                        f"Error type: {type(current).__name__}; path: "
                        + " -> ".join(
                            f"{frame.name}:{frame.lineno}" for frame in frames[-6:]
                        )
                    )
                    current = current.__cause__
        sys.exit(1)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
