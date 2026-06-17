<img src="logo.png" alt="Sensmos" height="80">

# Sensmos — ESP32 Firmware

Firmware that turns a cheap ESP32 into a **Sensmos** node — it reads sensors, cryptographically signs its data, runs logic at the edge, and joins the network. Built on the Arduino-ESP32 framework.

> Sensmos is a DePIN sensor network: nodes measure the real world, publish to a shared map, trade data peer-to-peer, and earn the GALU token. This firmware is the node itself.

## Features

- **Entities** — native (`pub.*`) network-rewarded readings and custom (`own.*`) values you define.
- **On-device identity** — each node generates a secp256k1 keypair locally and **signs every data batch**. The private key never ships in the firmware image.
- **Provisioning & trust** — BLE setup (WiFi credentials, wallet pairing) and a timed Bluetooth **attestation** ceremony proving the node is physical (anti-sybil).
- **Edge script engine** — up to 4-step rules (`if → action`): webhook, push, web fetch, ping/monitor, or a message to another node — all running locally, no cloud.
- **Local HTTP API** — read/write entities directly on the LAN (used by the [Home Assistant integration](https://github.com/Galusz/sensmos-homeassistant) and ESPHome setups).

## Flash it

The easiest way is the **web flasher** (Chrome/Edge): **https://sensmos.com/flash/** — plug the board in over USB and click flash.

Or build from source with the Arduino IDE / `arduino-cli` (open `SENSMOS_Firmware.ino`, target an ESP32 board).

## Layout

```
SENSMOS_Firmware.ino     entry point
src/
  ble_config.*           BLE provisioning + attestation
  wifi_manager.*         WiFi connect / captive setup
  data_sender.*          batch build + signing + upload
  entity_store.*         pub.* / own.* entities
  http_client_util.*     web fetch / webhooks
  config.h               build-time settings
```

## Part of the Sensmos project

| | |
|---|---|
| 🌐 Website | https://sensmos.com |
| 📱 App | https://github.com/Galusz/sensmos-app |
| 🏠 Home Assistant | https://github.com/Galusz/sensmos-homeassistant |
| 💬 Discord | https://discord.com/channels/1516178525814526044/1516181082750451772 |

GALU runs on Polygon. © 2026 Sensmos.
