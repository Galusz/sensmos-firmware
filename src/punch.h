#pragma once
#include <Arduino.h>
#include <ArduinoJson.h>

// UDP hole punch (v0.43) — E2E pomiar node↔node koordynowany przez BE.
// Peer to nasz własny node: zamiast pingować jego router z zewnątrz (ICMP często
// zablokowane), oba nody strzelają do siebie UDP jednocześnie — NAT-y otwierają flow
// i mierzymy PRAWDZIWE rtt/jitter/loss dom↔dom (oba last-mile w pomiarze).
// Przebieg: BE→WS cn_stun {host,port,token} → node wysyła token UDP do BE (BE poznaje
// publiczny endpoint noda; socket zostaje otwarty = mapowanie NAT żyje). Gdy BE ma oba
// endpointy: BE→WS cn_punch {ip,port,token,peer_token,dur_ms,host,to_*} do obu naraz →
// wymiana probe/echo w oknie dur_ms → raport WS check_result kind=punch.
// Pakiety: "SM1 <tok>" (STUN), "SP1 <tok> <seq> <ms>" (probe), "SP2 <tok> <seq> <ms>" (echo).
struct NetJob; struct NetResult;

void punch_on_stun(JsonDocument& doc);                   // WS cn_stun → job "stun" na wór (hi)
void punch_on_punch(JsonDocument& doc);                  // WS cn_punch → job "punch" na wór (hi)
void punch_exec_stun(const NetJob& j, NetResult& out);   // wór: STUN do BE (socket zostaje)
void punch_exec_punch(const NetJob& j, NetResult& out);  // wór: wymiana punch z peerem
void punch_on_net_result(const NetResult& nr);           // loop: raport WS (single-writer)
bool punch_gate_active();  // między STUN a punch wór nie bierze lo-jobów (okno NAT, max 10s)
