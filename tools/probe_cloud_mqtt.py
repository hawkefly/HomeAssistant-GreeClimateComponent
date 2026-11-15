"""Check one cloud device without changing its power, mode or temperature.

Run with Python 3.14 and the protocol dependencies installed. Credentials are
entered at the terminal. They are not saved or printed.
"""

# This is a command line tool, not a package.
# ruff: noqa: INP001, T201

import argparse
import asyncio
import base64
from getpass import getpass
import json
import logging
import os
from pathlib import Path
import sys

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "custom_components" / "gree_custom"),
)

from aiogree.api import gree_discover_devices_cloud, gree_get_status
from aiogree.cipher import EncryptionVersion, get_cipher
from aiogree.cloud_api import GreeCloudApi, GreeRegion
from aiogree.helpers import gree_decrypt_pack
from aiogree.transport_mqtt import GreeMqttTransport


async def probe(
    region: GreeRegion, mac: str, listen_seconds: int, capture: Path | None = None
) -> None:
    """Find the device in the account, query it and watch its status topics."""
    username = (await asyncio.to_thread(input, "Gree account: ")).strip()
    password = await asyncio.to_thread(getpass, "Gree password: ")
    async with GreeCloudApi(region, username, password) as cloud:
        credentials = await cloud.login()
        devices = await gree_discover_devices_cloud(cloud)
        device = next((device for device in devices if device.mac == mac), None)
        if device is None:
            print("Target MAC is not listed in this account and region.")
            return

        print(f"Found {device.mac}; firmware {device.ver}.")
        cipher = get_cipher(EncryptionVersion.V1, device.key)

        def save(name: str, value: dict) -> None:
            if capture is None:
                return
            capture.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                capture / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(descriptor, "w") as stream:
                json.dump(value, stream, ensure_ascii=False)

        save(
            "device-private.json",
            {
                "mac": device.mac,
                "controller": device.mac_controller_mqtt,
                "firmware": device.ver,
                "key": device.key,
            },
        )
        transport = GreeMqttTransport(
            str(credentials.user_id), credentials.token, region
        )

        sequence = 0

        def pushed(topic: str, envelope: dict) -> None:
            """Show the topic and pack fields without printing secret values."""
            nonlocal sequence
            sequence += 1
            save(f"push-{sequence:04d}.json", {"topic": topic, "envelope": envelope})
            try:
                push_cipher = (
                    get_cipher(EncryptionVersion.V1, None)
                    if envelope.get("i") == 1
                    else cipher
                )
                response = gree_decrypt_pack(envelope.copy(), push_cipher)
                pack = response.get("pack")
                fields = sorted(pack) if isinstance(pack, dict) else []
                print(f"Push {topic.split('/', maxsplit=1)[0]}: fields {fields}")
            except Exception as err:  # noqa: BLE001 - keep listening for the next push
                encoded = envelope.get("pack")
                count = (
                    len(base64.b64decode(encoded)) if isinstance(encoded, str) else 0
                )
                print(
                    f"Push {topic.split('/', maxsplit=1)[0]} could not be decoded: "
                    f"{type(err).__name__}; ciphertext bytes={count}"
                )

        try:
            # A retained status can arrive while the remaining topics subscribe.
            transport.add_listener(mac, pushed)
            await transport.add_device(mac, device.mac_controller_mqtt)
            result = await gree_get_status(
                device.mac_controller_mqtt,
                mac,
                credentials.user_id,
                ["Pow", "Mod", "SetTem", "TemSen"],
                cipher,
                transport,
                timeout=10,
            )
            print(f"Status: {result.prop_values}")
            print(f"Listening for {listen_seconds} seconds.")
            await asyncio.sleep(listen_seconds)
        finally:
            await transport.disconnect()


def main() -> None:
    """Read options and run the cloud probe."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mac", required=True, help="Device MAC from the Gree app")
    parser.add_argument("--region", choices=GreeRegion.__members__, default="CN")
    parser.add_argument(
        "--listen", type=int, default=15, help="Seconds to watch pushes"
    )
    parser.add_argument(
        "--capture",
        type=Path,
        help="Save device key and encrypted pushes locally for offline analysis; "
        "use a new private directory and do not upload its contents",
    )
    args = parser.parse_args()
    if not 0 <= args.listen <= 300:
        parser.error("--listen must be between 0 and 300")
    mac = args.mac.replace(":", "").replace("-", "").lower()
    # The library has debug logs for developers. This probe prints only its
    # own results, and never dumps account responses or device keys.
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(probe(GreeRegion[args.region], mac, args.listen, args.capture))
    except Exception as err:  # noqa: BLE001 - server exceptions may contain secrets
        print(f"Probe failed: {type(err).__name__}")
        sys.exit(1)


if __name__ == "__main__":
    main()
