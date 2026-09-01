#pragma once

int http_post_json(const char* url, const char* body, int timeout_ms);
int http_get_simple(const char* url, int timeout_ms);   // GET bez body (webhooki typu UniFi)
