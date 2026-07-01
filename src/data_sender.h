#pragma once
#include <Arduino.h>

#define FW_VERSION "0.7"

void data_sender_init();
void data_sender_tick();
void data_sender_trigger();
void data_sender_update_basics();  // stub — zachowane dla kompatybilności
void data_sender_fetch_entities(); // stub — entities przez WS
