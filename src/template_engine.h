#pragma once
#include <Arduino.h>

// json_ctx=true: niepodstawiony placeholder → "__UNSET__" (valid JSON, bare owijany w cudzysłowy)
// json_ctx=false (push/plain): → __UNSET__ bez cudzysłowów
void fill_template(const char* tmpl, char* out, size_t out_len,
                   const char* from_id = nullptr,
                   const char* payload_str = nullptr,
                   bool json_ctx = false);
