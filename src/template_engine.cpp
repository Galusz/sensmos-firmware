#include "template_engine.h"
#include "entity_store.h"
#include <ArduinoJson.h>

void fill_template(const char* tmpl, char* out, size_t out_len,
                   const char* from_id, const char* payload_str, bool json_ctx) {
    strncpy(out, tmpl, out_len - 1);
    out[out_len - 1] = '\0';

    JsonDocument pd;
    bool has_payload = payload_str && *payload_str && !deserializeJson(pd, payload_str);

    char* pos = out;
    while ((pos = strchr(pos, '{')) != nullptr) {
        char* end = strchr(pos, '}');
        if (!end) break;
        int klen = end - pos - 1;
        if (klen <= 0 || klen > 48) { pos++; continue; }

        char key[49] = {0};
        strncpy(key, pos + 1, klen);

        // Klucz placeholdera tylko [a-zA-Z0-9_.] — inaczej to klamra JSON-a,
        // przesuń o 1 by trafić na zagnieżdżony {placeholder}
        bool valid = true;
        for (int k = 0; key[k]; k++)
            if (!isalnum((unsigned char)key[k]) && key[k] != '_' && key[k] != '.') { valid = false; break; }
        if (!valid) { pos++; continue; }

        char rep[64] = "";

        if (from_id && strcmp(key, "from") == 0) {
            snprintf(rep, sizeof(rep), "%.8s", from_id);
        } else if (payload_str && strcmp(key, "payload") == 0) {
            snprintf(rep, sizeof(rep), "%.30s", payload_str);
        } else if (strncmp(key, "pub.", 4) == 0 || strncmp(key, "own.", 4) == 0 ||
                   strncmp(key, "sub.", 4) == 0 || strncmp(key, "tmp.", 4) == 0 ||
                   strncmp(key, "msg.", 4) == 0) {
            entity_get_string(key, rep, sizeof(rep));
        } else if (has_payload) {
            if (pd[key].is<const char*>())
                strncpy(rep, pd[key].as<const char*>(), sizeof(rep) - 1);
            else if (pd[key].is<float>() || pd[key].is<int>()) {
                float fv = pd[key].as<float>();
                (fv == (int)fv) ? snprintf(rep, sizeof(rep), "%d", (int)fv)
                                : snprintf(rep, sizeof(rep), "%.1f", fv);
            }
        }

        const char* ins = rep;
        if (!*rep) {
            // niepodstawiony placeholder → marker __UNSET__
            if (!json_ctx)
                ins = "__UNSET__";                       // push/plain — bez cudzysłowów
            else {
                bool in_str = (pos > out && pos[-1] == '"' && *(end + 1) == '"');
                ins = in_str ? "__UNSET__" : "\"__UNSET__\"";  // JSON — bare owijany
            }
        }
        char before[256], after[256];
        int blen = pos - out;
        strncpy(before, out, blen); before[blen] = '\0';
        strncpy(after, end + 1, sizeof(after) - 1); after[sizeof(after) - 1] = '\0';
        snprintf(out, out_len, "%s%s%s", before, ins, after);
        pos = out + blen + strlen(ins);
    }
}
