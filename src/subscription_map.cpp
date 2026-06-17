#include "subscription_map.h"
#include <Preferences.h>

struct SubEntry {
    char target[67];
    char prefix[16];
};

static SubEntry _map[SUB_MAP_MAX];
static int _head  = 0;   // następny slot do nadpisania (ring)
static int _count = 0;

static void nvsSave() {
    Preferences p; p.begin("submap", false);
    p.putInt("head", _head);
    p.putInt("count", _count);
    char k[8];
    for (int i = 0; i < SUB_MAP_MAX; i++) {
        snprintf(k,sizeof(k),"t%d",i); p.putString(k, _map[i].target);
        snprintf(k,sizeof(k),"p%d",i); p.putString(k, _map[i].prefix);
    }
    p.end();
}

void sub_map_init() {
    memset(_map, 0, sizeof(_map));
    Preferences p; p.begin("submap", true);
    _head  = p.getInt("head", 0);
    _count = p.getInt("count", 0);
    char k[8];
    for (int i = 0; i < SUB_MAP_MAX; i++) {
        snprintf(k,sizeof(k),"t%d",i); strncpy(_map[i].target, p.getString(k,"").c_str(), sizeof(_map[i].target)-1);
        snprintf(k,sizeof(k),"p%d",i); strncpy(_map[i].prefix, p.getString(k,"").c_str(), sizeof(_map[i].prefix)-1);
    }
    p.end();
}

static int find_slot(const char* target_id) {
    for (int i = 0; i < SUB_MAP_MAX; i++)
        if (_map[i].target[0] && strcmp(_map[i].target, target_id) == 0) return i;
    return -1;
}

void sub_map_set(const char* target_id, const char* prefix) {
    if (!target_id || !*target_id) return;
    int slot = find_slot(target_id);
    if (slot < 0) {
        slot = _head;                          // nadpisz najstarszy
        _head = (_head + 1) % SUB_MAP_MAX;
        if (_count < SUB_MAP_MAX) _count++;
    }
    strncpy(_map[slot].target, target_id, sizeof(_map[slot].target)-1);
    _map[slot].target[sizeof(_map[slot].target)-1] = '\0';
    strncpy(_map[slot].prefix, prefix, sizeof(_map[slot].prefix)-1);
    _map[slot].prefix[sizeof(_map[slot].prefix)-1] = '\0';
    nvsSave();
}

bool sub_map_get(const char* target_id, char* out, size_t out_len) {
    int slot = find_slot(target_id);
    if (slot < 0) return false;
    strncpy(out, _map[slot].prefix, out_len-1);
    out[out_len-1] = '\0';
    return true;
}
