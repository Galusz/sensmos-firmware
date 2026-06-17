#pragma once
#include <Arduino.h>

// Async kolejka dla BE script akcji które mogą blokować (fetch, ping, aggregate)
// Wysyłana z loop() z throttle — nie blokuje pętli głównej

#define SCRIPT_ASYNC_QUEUE_SIZE 6

void script_async_init();
void script_async_update();  // wywołaj z loop()

// Dodaj do kolejki
void script_async_push_fetch(const char* script_id, const char* url, const char* store, const char* path);
void script_async_push_ping(const char* script_id, const char* host, int timeout_ms, const char* store);
void script_async_push_aggregate(const char* script_id, const char* entity,
                                  const char* func, float* samples, int count, const char* store);
