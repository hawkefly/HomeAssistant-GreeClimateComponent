# WB05-TG V1.30 UDP findings

The tested unit answers ping and cloud MQTT, but does not answer UDP 7000
discovery or device-information queries. The strongest explanation is a missing
UDP receive path in normal Wi-Fi station mode in this build. This is supported
by both live network tests and offline firmware analysis.

## Live checks

The target MAC was confirmed by ARP. From the same subnet:

- A wired computer received discovery replies from four other units. The
  target did not reply to the same unicast or broadcast scan.
- Target scans from an ephemeral source port, port 5001 and port 7000 all
  received no reply.
- Generic ECB scan and device-key ECB `status` requests for `hid/ver` also
  received no reply. The same device key works for cloud requests.
- A host-side packet capture confirmed transmission to the target MAC. It
  contained no target UDP reply or ICMP destination-unreachable.
- An Android phone on the same Wi-Fi repeated the result. It could ping the
  target and discover other units, but got no target discovery reply from
  either an ephemeral source port or port 5001.

Only scan and information queries were sent. No bind, control, Wi-Fi reset,
platform setting or firmware update was used. The phone helper was removed.
These checks reduce the chance of a computer interface or wired/Wi-Fi path
problem. They do not prove the absence of a device-specific network rule.

## Exact firmware path

The public firmware for code `362001065909`, build `U-WB05_TGV1.30`, has
SHA-256 `911de43161e85855137f10b6574dbb84fd7c906ac5a421e9991cf27e47d3a27a`.
The decompressed image has SHA-256
`65f4f44b556131ab33d3c8320495f26b915b1d6d8c708694f2acec96ec4b20d5`.
It was read with Capstone 5.0.7 as RV32 with compressed instructions. Runtime
flash address equals file offset plus `0x22fff000`. This is static evidence,
not a trace of the running unit.

In the recovered station-mode state machine, `0x2300746e` calls
`socket_connect_start` at `0x23007b1e`. It creates an IPv4 UDP socket bound to
`0.0.0.0:7000` and saves its descriptor at SRAM `0x420105b8`. It then requests
cloud settings with `needMqtt=1`; the next stage starts MQTT. Choosing MQTT
does not skip UDP creation in this recovered route.

The saved descriptor has three validated memory references:

| Site | Use |
| --- | --- |
| `0x23007b3a` | Load the old descriptor before closing it. |
| `0x23007b6c` | Store the newly created descriptor. |
| `0x23007a54` | Load it for `sendto` at `0x23007a68`. |

No receive or select use was found for that descriptor. In contrast, the
access-point setup path creates a separate local UDP socket, selects it at
`0x23006c66`, receives at `0x23006dd8`, dispatches JSON at `0x23006ff4` and
replies to the original sender. Finding this setup code does not establish
LAN control in normal station mode.

The descriptor scan covered file offsets `0x1000` through `0xdbe00`, at each
halfword, including GP references and 160-byte local alias windows. Direct
references to socket receive/select wrappers and full-file pointer constants
were also checked. Unusual computed pointers and dynamic callbacks remain
outside this bounded result. The running unit's socket table and RAM were
not read, so a successful live bind is not proved.

The other SDK `recvfrom` call at `0x23047b42` was traced to an ALCS/CoAP
server configured for UDP 5683 and multicast `224.0.1.187`. Its parser handles
CoAP headers and URI options. It is a separate protocol, not a hidden Gree
7000 receiver. Its live availability and third-party authentication were not
tested, so this result does not rule out every possible local protocol.

## Effect on this integration

Changing a packet prefix, source port or cipher cannot add a receive task to
the firmware. There is no verified LAN-enable command for this build. The
experimental profile therefore keeps using the tested China cloud MQTT path.
This finding is specific to the checked build and must not be applied to all
WB05 modules or every firmware with the same code.
