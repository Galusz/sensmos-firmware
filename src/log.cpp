#include "log.h"
#include "ws_client.h"
#include "monitors.h"
#include "net_worker.h"
#include "checknet.h"
#include <WiFi.h>

static uint32_t s_min_largest = 0xFFFFFFFF;

void log_heap_sample() {
    uint32_t b = ESP.getMaxAllocHeap();
    if (b < s_min_largest) s_min_largest = b;
}

uint32_t log_heap_min() { return s_min_largest == 0xFFFFFFFF ? 0 : s_min_largest; }

void log_health() {
    // free/largest now, min largest since boot (fragmentation floor), link + subsystems.
    LOGI("health",
         "up=%lus heap=%uk blk=%uk min=%uk rssi=%d ws=%s mon=%u lag=%.2f busy=%u%% cn=%s",
         (unsigned long)(millis() / 1000),
         (unsigned)(ESP.getFreeHeap()      / 1024),
         (unsigned)(ESP.getMaxAllocHeap()  / 1024),
         (unsigned)(log_heap_min()         / 1024),
         WiFi.RSSI(),
         ws_client_connected() ? "up" : "down",
         (unsigned)monitors_count(),
         monitors_qlag(),
         (unsigned)net_worker_last_busy(),
         checknet_busy() ? "run" : "idle");
}
