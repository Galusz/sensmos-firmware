#pragma once
#include <ArduinoJson.h>

// Check-now (UpFromWhere): jednorazowa sonda HTTP z podpisanej komendy BE
// {type:"check", id, url}. Cienki trzeci klient net_workera (obok checknet/monitors):
// zero schedulera, jeden slot w locie, wynik wraca WS {type:"checknow_result"}.
struct NetResult;   // net_worker.h (fwd — unikamy cyklu include)

void checknow_on_cmd(JsonDocument& doc);            // z ws_client (po weryfikacji podpisu BE)
void checknow_on_net_result(const NetResult& nr);   // wynik sondy z net_worker (dispatch w loop)
