#include "src/identity.h"
#include "src/ble_config.h"
#include "src/wifi_manager.h"
#include "src/http_server.h"
#include "src/node_integration.h"
#include "src/script_async.h"
#include "src/entity_store.h"
#include "src/message_router.h"
#include "src/ws_client.h"
#include "src/data_sender.h"
#include "src/script_engine.h"
#include "src/ntp_time.h"
#include "src/serial_cmd.h"
#include "src/subscription_map.h"
#include "src/checknet.h"
#include "src/monitors.h"
#include "src/config.h"
#include <Preferences.h>

bool node_running = false;

// Flaga w NVS — przeżywa ESP.restart() (RTC_DATA_ATTR zawodzi po SW reset).
// Ustawiana gdy WiFi nie połączyło: następny boot idzie prosto w BLE z czystym
// stosem (BLEDevice::init crashuje przy aktywnym WiFi → bta_sys_init OOM).
static bool boot_force_ble_get() {
    Preferences p; p.begin("sensmos", true);
    bool v = p.getBool("force_ble", false); p.end();
    return v;
}
static void boot_force_ble_set(bool v) {
    Preferences p; p.begin("sensmos", false);
    p.putBool("force_ble", v); p.end();
}

// ── Przycisk serwisowy (GPIO0) ────────────────────────────────
// Przytrzymaj 3s → tryb BLE serwisowy; 10s → factory reset.
// wallet_bak (kopia portfela) NIE jest czyszczona — przeżywa reset.
static unsigned long s_btn_down_ms = 0;
static bool          s_btn_down    = false;
static int           s_btn_stage   = 0;  // 0 brak, 1 zapowiedź BLE, 2 zapowiedź reset

static void button_tick() {
    bool down = (digitalRead(SERVICE_BUTTON_PIN) == LOW);
    unsigned long now = millis();

    if (down && !s_btn_down) {
        s_btn_down = true; s_btn_down_ms = now; s_btn_stage = 0;
    } else if (down && s_btn_down) {
        unsigned long held = now - s_btn_down_ms;
        if (held >= SERVICE_BTN_RESET_MS && s_btn_stage < 2) {
            s_btn_stage = 2;
            Serial.println("[BTN] >=10s — puść aby FACTORY RESET");
        } else if (held >= SERVICE_BTN_BLE_MS && s_btn_stage < 1) {
            s_btn_stage = 1;
            Serial.println("[BTN] >=3s — puść aby tryb BLE");
        }
    } else if (!down && s_btn_down) {
        unsigned long held = now - s_btn_down_ms;
        s_btn_down = false;
        if (held >= SERVICE_BTN_RESET_MS) {
            Serial.println("[BTN] FACTORY RESET");
            Preferences p;
            p.begin("sensmos",      false); p.clear(); p.end();
            p.begin("sensmos_wifi", false); p.clear(); p.end();
            p.begin("sensmos_api",  false); p.clear(); p.end();
            // wallet_bak NIE czyszczone — kopia portfela przeżywa reset
            delay(300); ESP.restart();
        } else if (held >= SERVICE_BTN_BLE_MS) {
            Serial.println("[BTN] Tryb BLE serwisowy");
            boot_force_ble_set(true);
            delay(300); ESP.restart();
        }
    }
}

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("=== SENSMOS SmartNode v0.30 ===");

    pinMode(SERVICE_BUTTON_PIN, INPUT_PULLUP);

    if (!identity_init()) {
        Serial.println("[FATAL] Blad tozsamosci!"); while (true) delay(1000);
    }
    ble_load_config();  // wczytaj backend_url, owner itp. przed WiFi
    entity_store_init();
    sub_map_init();
    serial_cmd_init();
    ble_set_wifi_ready_cb(nullptr);  // nie używamy callbacku — restart zamiast

    // Wymuszony BLE po nieudanym WiFi — czysty boot, pełna pamięć dla BLE
    if (boot_force_ble_get()) {
        boot_force_ble_set(false);
        Serial.println("[Boot] Wymuszony BLE (poprzednia proba WiFi nieudana)");
        ble_start();
        return;
    }

    if (wifi_has_config()) {
        if (wifi_init()) {
            Serial.println("[Boot] WiFi OK");
            data_sender_init();  // startuje skan WiFi — tylko gdy WiFi aktywne (inaczej koliduje z BLE)
            http_server_init();
            ntp_init();
            ws_client_init();
            if (ntp_synced()) data_sender_fetch_entities();
            script_engine_init();
            node_integration_init();
            script_async_init();
            message_router_init();
            checknet_init();
            monitors_init();
            Serial.printf("[Heap] po init: free=%u largest=%u\n", ESP.getFreeHeap(), ESP.getMaxAllocHeap());
            node_running = true;
            watchdog_start();  // nieaktywny jeśli node_confirmed=true w NVS
        } else {
            // WiFi nie działa (złe creds / router down) — restart w czysty tryb BLE.
            // NIE wołać ble_start() tu: stos WiFi już aktywny → crash bta_sys_init.
            Serial.println("[Boot] WiFi blad — restart w tryb BLE");
            boot_force_ble_set(true);
            delay(1000);
            ESP.restart();
        }
    } else {
        Serial.println("[Boot] Nowe urzadzenie — BLE");
        ble_start();
    }
}

void loop() {
    serial_cmd_tick();
    button_tick();
    watchdog_tick();
    if (node_running) {
        http_server_handle();
        ws_client_tick();
        ntp_tick();
        script_engine_tick();
        node_integration_update();
        script_async_update();
        data_sender_tick();
        checknet_update();
        monitors_update();
    }
    if (g_ble_active) ble_tick();
    delay(10);
}
