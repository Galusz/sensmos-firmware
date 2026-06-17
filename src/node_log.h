#pragma once
#include <Arduino.h>

// Ring buffer ostatnich zdarzeń noda (batch|message_recv|message_sent|sub|script|config|error).
void node_log_push(const char* type, const char* detail, bool ok);
void handle_node_log();   // GET /node/log
