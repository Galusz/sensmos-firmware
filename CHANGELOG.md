# Changelog — SENSMOS Firmware (ESP32)

Firmware ships via **OTA** (app-only bins served by the backend) and the **web flasher**
(`firmware/sensmos-*.bin` on the `main` branch) — **not** via GitHub Releases.
This file is the version history reconstructed from commits. Current version:
`FW_VERSION` in `src/data_sender.h`.

## 0.89 — 2026-08-22
- **WebSocket watchdog** (`ws_client.cpp`). A node could end up with WiFi alive but the
  WS client wedged — connected to nothing, retrying nothing — and stay silent for hours
  (seen in the field: 1 node of 263 after a server-side nginx restart). The watchdog
  probes the WS endpoint with a bare TCP connect (via the net worker, non-blocking)
  as soon as WS drops: every 20 s for the first 5 minutes, then every 60 s.
  - TCP passes while WS has been dead ≥ 5 min → the node itself is wedged → restart
    (the 5-min grace keeps fleet-wide backend deploys, which cut WS for 10-30 s,
    from triggering mass restarts).
  - TCP and WS both dead for 2 h straight → one prophylactic restart (fresh network
    stack for when the link returns).
- **Outage evidence** (`ws_outage`). The watchdog keeps an episode record with
  **absolute timestamps**: when WS dropped and when the first TCP probe failed (the
  clock is trustworthy at that moment — synced by the very session that just died).
  The record survives watchdog restarts and even power loss (NVS), and is reported
  to the backend after reconnect. Failed probes mark the window in which the
  household's internet was actually down — groundwork for an ISP-outage history
  that can back a complaint to the provider.
- **`POST /node/reboot`** (PIN-protected, local HTTP). Plain remote restart over LAN —
  until now the only remote path was the BLE-mode detour, and the WS `reboot` command
  needs a live WS, which is exactly what's missing when you need it.
- **LoRa build identifies itself as `esp32s3-lora`** in firmware integrity checks
  (`fw_digest.h`). The check used to fail on the chip-string comparison before ever
  reaching the hash — every LoRa node showed a false `version_mismatch`.

## 0.80 — 2026-07-28
- **Hardware task watchdog** on the main loop (120 s, `esp_task_wdt`). All software
  safeguards (BLE timeout, WiFi-down reboot, onboarding watchdog) live inside `loop()`
  and die with it — a hung node used to stay offline forever with nothing noticing.
  Now a hang turns into a hard reset within two minutes. OTA download loop feeds the
  watchdog explicitly (a 1.6 MB image on a slow link can legitimately take that long).

## 0.79 — 2026-07-28
- **Onboarding watchdog no longer wipes the node's identity.** On timeout it used to
  clear the whole NVS namespace — including the device keypair — so every failed
  onboarding minted a brand-new `device_id` (one user burned through 7 IDs in
  21 minutes). Now it clears only owner/WiFi config and reboots into BLE provisioning
  with the identity kept.
- BLE provisioning exits on its own after 5 min if a WiFi config exists (clean
  deinit + restart) — a node stuck in BLE after a transient WiFi failure now returns
  to normal operation instead of sitting in provisioning forever.

## 0.78 — 2026-07-27
- **All runtime logs in English** — full sweep of every log literal in the tree
  (286 strings audited), not a spot fix.

## 0.77 — 2026-07-27
- Monitor results report `reason=blocked` (distinguishes "target refused" from
  "target down"). WiFi password failure diagnostics. First batch of English logs.
  Web-flasher bins refreshed.

## 0.75 — 2026-07-27
- **mon-split**: NET telemetry moves to its own `mon[12]` entity buffer and its own
  WS frame (`mon_batch`), separated from the public entity stream. Groundwork for
  treating network telemetry independently of sellable/subscribable data.

## 0.74 — 2026-07-25
- **WiFi reconnect watchdog** (`wifi_maintain()` in `loop()`): reconnect every 20 s
  when WiFi drops, hard reboot after 4 min down, `setAutoReconnect(true)`. Fixes
  nodes dying overnight after a router reboot and never coming back.

## 0.73 — 2026-07-24
- **Loop-context TLS eliminated**: `/remote/data`+`/subscribe` → WS fire-and-forget;
  `/wallet/*` and `/remote/available` removed (app/HA read the backend directly).
- `node_integration` → a job on the async worker every 60 s (one batched POST).
  Tunnel is **on-demand** with teardown (~27 KB RAM only for the session's lifetime).
  Streaming fetch with a hard cap.
- Monitor slots 24→16. ESP-IDF log shim through Serial (no more garbled UART).
  BT controller memory released before `wifi_init`.

## 0.65 — 2026-07-23
- **RemoteTerminal (FW side)**: `tunnel.cpp` — a dumb TCP pipe LAN↔backend
  (encrypted), on its own task (doesn't starve net_worker/monitors). Opt-in via NVS
  `remote_ok` (fleet default = zero footprint), **RFC1918 targets only**, idle 5 min /
  session 2 h, `remote` flag in identify.

## 0.64 — 2026-07-22
- WS `identify` confirms onboarding (disarms the factory-reset watchdog).

## 0.62–0.63 — 2026-07-21
- `monitor_status` (levels + age every 60 s, immediate reply after set/clear).
  Confirmation burst (~8 s while a state transition is in flight — detection ≈
  interval+16 s instead of N×interval). Minimum interval 30 s.

## 0.61 — 2026-07-20
- **WS encryption** (ECDH + HKDF + AES-GCM) as the **only** mechanism. K3/nonce/
  batch-sig/session_token all removed.

## 0.59–0.60 — 2026-07-19
- **gateway-ping** (the hop to your own router, `pub.link_*`). **UDP punch-trace**
  through the NAT hole (`traceroute_run_udp` + conntrack). `net_loss` fix (dead peers
  were poisoning loss by ~20%). SSRF exception for the gateway.

## 0.57–0.58 — 2026-07-14/15
- **checknow**: returns the target IP as seen by the node (GeoDNS/CDN — proof the
  probe is real; lwIP cache lookup after a successful HTTP). **DNS** and **TCP
  connect** phases measured separately.

## 0.56 — 2026-07-14
- **checknow**: one-shot HTTP probe from a signed backend command (third net_worker
  client). WiFi **fuzzy match** (space/case-insensitive via BSSID), hidden-SSID retry
  without the trailing space + config fix-up on success. **esp32s3-n16r8** OTA target
  (octal PSRAM) from 0.56 on.

## 0.51–0.55 — 2026-07-11/12  (the WiFi saga)
- 0.55: SSID robustness — trim on save + connect to the AP actually seen in the scan
  (exact bytes + BSSID); ends the "GladiLANtor " hidden-trailing-space saga.
- 0.54: diagnostic scan moved BEFORE connect (post-fail scan falsely returned 0 →
  "dead radio" was a false reading).
- 0.53: `NimBLEDevice::deinit()` before reset — clean BLE→WiFi radio handoff
  (otherwise WiFi RX could come up dead).
- 0.52: WiFi country '01', channels 1–13 (EU hotspots on ch12/13 were invisible →
  NO_AP_FOUND). `esp32s3-n16r8` build variant added.
- 0.51: connect-failure diagnostics (ESP-IDF reason code + AP scan: what's visible /
  is the target present + RSSI).

## 0.50 — 2026-07-11
- `NATIVE_MAX` 32→40 (the catalog has 37 entities — `grid_v`/`pv_power`/`load_power`
  come back). OTA logs its outcome to `node_log` (diagnosis without a serial cable).

## 0.45–0.49 — 2026-07-09
- 0.49: RAM audit (~25 KB more free heap in node mode).
- 0.48: `set_device_id` renames BLE to `SENSMOS-<new id>` (restore/attestation fix).
- 0.46–0.47: `device_id` override — restoring a node's identity after a reflash;
  `ble_mac` in `/info` (later reverted).
- 0.45: WS `deleted` → BLE onboarding (owner-initiated soft delete).

## 0.41–0.43 — 2026-07-09
- 0.43: **UDP hole punch** (real end-to-end peer measurement) + global trace cooldown.
- 0.42: trace up to 30 hops + geo validation of the last hop (rDNS on the node).
- 0.41: **async network worker** + queue metrics + resumable scripts.

## 0.35–0.38 — 2026-07-07
- OTA rollout (min_spiffs partitions, 2 slots; NimBLE made the app fit). BLE ceremony
  fix on classic ESP32. BLE commands handled in `loop()` instead of the NimBLE
  callback. Chip/firmware in identify (once per connection). RAM optimizations.

## 0.30–0.34 — 2026-07-06
- Migration to **NimBLE**. Version banner from `FW_VERSION` (was hardcoded 0.33).
  Boot / identity work.

## 0.21–0.29 — 2026-07-02/05
- Early versions: checknet / traceroute / monitor foundations, critical fixes from
  the first code review.
