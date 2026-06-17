#pragma once
#include <Arduino.h>

void   push_init();
void   push_set_token(const char* token);
String push_get_token();
bool   push_available();
