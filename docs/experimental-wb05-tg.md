# Experimental WB05-TG support

This branch adds a narrow cloud profile for model `10015`, hardware id
`362001065909+U-WB05_TGV1.30.bin`, communication version `V3.5.M`.
The profile is selected only when all three values match and the connection
uses MQTT. Other devices keep the normal protocol path.

## What was tested

A real unit accepted a `binCmd` temperature command. A later full status push
confirmed 25 to 26 Celsius while power stayed off. Mode, auto fan and swing
also stayed unchanged. The same unit then passed the HA device client path:
account-key binding, exact profile detection, a full status poll, a guarded
26 to 25 Celsius command and a fresh confirmation poll. Power stayed off and
the room temperature was 25 Celsius. This verifies the client used by HA;
installation and the UI still need to be checked in a running HA instance.
A command receipt alone is never treated as state confirmation.

## Install and discover

This branch requires Home Assistant 2026.11 or newer and Python 3.14.
Use this fork's `experimental/gree-china-mqtt` branch with HACS as a custom
repository, or copy `custom_components/gree_custom` to your HA config folder.
Restart HA. Keep the domain and folder name `gree_custom`.

Add **Gree A/C**, choose a cloud account and select **China Mainland**.
The unit should appear in the account device list even when it does not answer
local discovery. Choose its cloud connection. Do not enter a new local packet
prefix or a different UDP port. Read [installation.md](installation.md) for
migration from older versions.

The tested build did not answer UDP 7000 from either a wired computer or a
phone on the same Wi-Fi. Its firmware keeps a station-mode UDP send socket,
but no receive consumer was found for it. See [UDP findings](wb05-tg-udp-findings.md)
for the evidence and its limits. This profile requires cloud connectivity.

## Available controls

- Cooling and off.
- Whole Celsius target temperatures from 16 to 31.
- Automatic fan.
- Vertical swing stopped or full swing.
- Target temperature, power and room temperature from full cloud pushes.

Half-degree target values set by the official app remain visible, but this
profile writes whole degrees only. It does not offer heat, dry, manual fan
speeds, horizontal swing, quiet, turbo, display, beeper or other extra features.
These limits describe the current implementation, not the unit's abilities.

The firmware sends the whole command frame to the air conditioner. Before
sending, this profile requests new full state, copies the known basic fields
and checks extra features against the captured defaults. When a feature has a
different or missing value, the command is refused with a protocol error.
Use the Gree app for those settings. Do not remove the guard to force a command.
The checks reduce unwanted changes, but the complete model mapping is still
being recovered. Use this experimental profile with that limit in mind.

## State and availability

A normal property query on this module can return zeros while the real state
is different. The profile requests a full report with `freqCount` and waits for
a new cloud push on every poll and before and after a control. A missing fresh
report makes the device unavailable. It does not reuse old state to keep it
online, or replace a push with ordinary query zeros.

China uses `mqtt.gree.com:1984`. Login may end the official app's account
session. Account passwords, tokens and device keys must not be pasted into an
issue. The local tools accept account credentials only in the terminal.
