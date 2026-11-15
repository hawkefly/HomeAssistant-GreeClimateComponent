"""Fresh full status reports for an explicitly matched binary AC model."""

import asyncio
from collections.abc import Mapping
from contextlib import suppress
import math

from .api import StatusResult, _create_payload
from .cipher import CipherBase
from .errors import GreeConnectionError
from .transport import GreeBaseTransport

BINARY_STATUS_PROPS = frozenset(
    {
        "Pow",
        "Mod",
        "SetTem",
        "TemSen",
        "WdSpd",
        "SwUpDn",
        "SwingLfRig",
        "TemUn",
        "TemRec",
    }
)
_REQUIRED = frozenset(
    {"Pow", "Mod", "SetTem", "WdSpd", "SwUpDn", "SwingLfRig", "Add0.5"}
)


class BinaryAcSession:
    """Keep full reports separate from ordinary JSON query results."""

    def __init__(self, timeout: float) -> None:
        """Set the full push timeout, including the report request."""
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Binary status timeout must be positive and finite")
        self.timeout = timeout
        self.status: dict[str, str] = {}
        self.revision = 0
        self._waiters: set[asyncio.Event] = set()
        self._lock = asyncio.Lock()

    def accept(self, values: Mapping[str, str]) -> bool:
        """Save a complete report without mixing old and new fields."""
        if not _REQUIRED.issubset(values):
            return False
        try:
            numbers = {key: int(values[key]) for key in _REQUIRED}
        except TypeError, ValueError:
            return False
        if (
            numbers["Pow"] not in (0, 1)
            or numbers["Add0.5"] not in (0, 1)
            or not 0 <= numbers["Mod"] <= 4
            or not 16 <= numbers["SetTem"] <= 31
            or not 0 <= numbers["WdSpd"] <= 5
            or not 0 <= numbers["SwUpDn"] <= 11
            or not 0 <= numbers["SwingLfRig"] <= 6
        ):
            return False
        self.status = dict(values)
        self.revision += 1
        for event in self._waiters:
            event.set()
        return True

    def clear(self) -> None:
        """Discard the previous transport's status snapshot."""
        self.status = {}

    def properties(self) -> dict[str, str]:
        """Read basic fields and adapt the cloud half-degree flag for HA."""
        values = {
            key: value
            for key, value in self.status.items()
            if key in BINARY_STATUS_PROPS and key != "TemRec"
        }
        if "Add0.5" in self.status:
            values["TemRec"] = self.status["Add0.5"]
        return values

    async def query(
        self,
        props: list[str],
        controller: str,
        mac: str,
        userid: int,
        cipher: CipherBase,
        transport: GreeBaseTransport,
    ) -> StatusResult:
        """Request a new report and wait for its push, not its receipt."""
        async with self._lock:
            event = asyncio.Event()
            # Register before publishing, since the push may arrive before res.
            self._waiters.add(event)
            try:
                async with asyncio.timeout(self.timeout):
                    payload = _create_payload(
                        {
                            "t": "freqCount",
                            "mac": mac,
                            "opt": ["SendFreq", "FreqTime"],
                            "p": [1, 300],
                        },
                        "pack",
                        0,
                        controller,
                        userid,
                    )
                    # This firmware need not return a normal response pack.
                    reply_timeout = min(3.0, self.timeout / 2)
                    with suppress(TimeoutError, GreeConnectionError):
                        await asyncio.wait_for(
                            transport.request_json(
                                controller, payload, cipher, 1, reply_timeout
                            ),
                            timeout=reply_timeout,
                        )
                    await event.wait()
            except TimeoutError as err:
                raise GreeConnectionError("No fresh full binary AC status") from err
            finally:
                self._waiters.discard(event)
            supported = self.properties()
            values = {key: supported[key] for key in props if key in supported}
            return StatusResult(values, [key for key in props if key not in values])
