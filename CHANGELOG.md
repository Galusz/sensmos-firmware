# Changelog — SENSMOS Firmware (ESP32)

Firmware wystawiany przez **OTA** (biny app-only na backendzie) i **web-flasher**
(`firmware/sensmos-*.bin` na gałęzi `main`) — **nie** przez GitHub Releases.
Ten plik to historia wersji na podstawie commitów. Wersja bieżąca: `FW_VERSION`
w `src/data_sender.h`.

## 0.74 — 2026-07-25
- **Watchdog reconnectu WiFi** (`wifi_maintain()` w `loop()`): reconnect co 20 s gdy WiFi padnie, twardy reboot po 4 min, `setAutoReconnect(true)`. Naprawia nody padające w nocy po reboocie routera i niewracające.

## 0.73 — 2026-07-24
- Koniec **loop-context TLS**: `/remote/data`+`/subscribe` → WS fire-and-forget; `/wallet/*` i `/remote/available` skasowane (apka/HA czytają BE wprost).
- `node_integration` → job na worze co 60 s (batch w 1 POST). Tunel **on-demand** + teardown (~27 KB RAM tylko na czas sesji). Fetch strumieniowy z twardym capem.
- Sloty monitorów 24→16. Shim logów ESP-IDF przez Serial. Zwolnienie pamięci BT przed `wifi_init`.

## 0.65 — 2026-07-23
- **RemoteTerminal (FW)**: `tunnel.cpp` — rura TCP LAN↔BE (szyfrowana), osobny task (nie dławi net_workera/monitorów). Opt-in przez NVS `remote_ok` (flota = zero footprint), tylko RFC1918, idle 5 min / sesja 2 h, flaga `remote` w identify.

## 0.64 — 2026-07-22
- WS `identify` potwierdza onboarding (rozbraja factory-reset watchdog).

## 0.62–0.63 — 2026-07-21
- `monitor_status` (poziomy + wiek co 60 s, odpowiedź po set/clear). Burst potwierdzeń (~8 s w przejściu — wykrycie ≈ interwał+16 s zamiast N×interwał). Interwał min 30 s.

## 0.61 — 2026-07-20
- **Szyfrowanie WS** (ECDH + HKDF + AES-GCM) jako **jedyny** mechanizm. Zaorane K3/nonce/batch-sig/session_token.

## 0.59–0.60 — 2026-07-19
- **gateway-ping** (hop do własnej bramy, `pub.link_*`). **punch-trace UDP** przez dziurę NAT (`traceroute_run_udp` + conntrack). Fix `net_loss` (martwe peery zatruwały loss ~20%). Wyjątek SSRF dla bramy.

## 0.57–0.58 — 2026-07-14/15
- **checknow**: zwraca IP celu widziane przez noda (GeoDNS/CDN — dowód realności; lookup z cache lwIP po udanym HTTP). Fazy **DNS** i **TCP connect** mierzone osobno.

## 0.56 — 2026-07-14
- **checknow**: jednorazowa sonda HTTP z podpisanej komendy BE (trzeci klient net_workera). WiFi **fuzzy match** (bez spacji/case po BSSID), próba ukrytego SSID bez spacji z zapisem poprawki. Target OTA **esp32s3-n16r8** (octal-PSRAM) od 0.56.

## 0.51–0.55 — 2026-07-11/12  (saga WiFi)
- 0.55: SSID robustness — trim SSID + connect do AP widzianego w skanie (exact bytes + BSSID); koniec sagi „GladiLANtor " z ukrytą spacją.
- 0.54: skan diagnostyczny przeniesiony PRZED connect (post-fail scan zwracał fałszywe 0 → fałszywy „martwy radio").
- 0.53: `NimBLEDevice::deinit()` przed reset — czysty handoff BLE→WiFi (inaczej WiFi RX wstawał martwy).
- 0.52: WiFi country '01' ch 1–13 (hotspoty EU na ch12/13 były niewidoczne → NO_AP_FOUND). Wariant build `esp32s3-n16r8`.
- 0.51: diagnostyka błędu connect (reason code ESP-IDF + skan APek: widoczne / target obecny + RSSI).

## 0.50 — 2026-07-11
- `NATIVE_MAX` 32→40 (katalog 37 encji — `grid_v`/`pv_power`/`load_power` wracają). OTA loguje wynik do `node_log` (diagnoza bez seriala).

## 0.45–0.49 — 2026-07-09
- 0.49: audyt RAM (~25 KB więcej wolnego heapu w trybie noda).
- 0.48: `set_device_id` przemianowuje BLE na `SENSMOS-<new id>` (fix restore/atestacji).
- 0.46–0.47: override `device_id` — przywracanie tożsamości noda po reflashu; `ble_mac` w `/info` (cofnięte).
- 0.45: WS `deleted` → BLE onboarding (soft-delete właściciela).

## 0.41–0.43 — 2026-07-09
- 0.43: **UDP hole punch** (realny pomiar E2E peer) + globalny cooldown trace.
- 0.42: trace do 30 hopów + walidacja geo ostatniego hopa (rDNS na nodzie).
- 0.41: **async network worker („wór")** + metryki kolejki + wznawialne skrypty.

## 0.35–0.38 — 2026-07-07
- OTA rollout (partycje min_spiffs, 2 sloty; NimBLE zmieścił app). Fix ceremonii BLE na klasycznym ESP32. Obsługa komend BLE w `loop()` zamiast w callbacku NimBLE. Chip/firmware w identify (raz na połączenie). Optymalizacje RAM.

## 0.30–0.34 — 2026-07-06
- Migracja na **NimBLE**. Baner wersji z `FW_VERSION` (był zahardkodowany 0.33). Boot / tożsamość.

## 0.21–0.29 — 2026-07-02/05
- Wczesne wersje: podstawy checknet / traceroute / monitorów, naprawy krytyczne z pierwszego przeglądu.
