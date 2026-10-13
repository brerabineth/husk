/* util.c — verdict names, machine names, small helpers */
#include "husk.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

const char *husk_verdict_str(int v)
{
    switch (v) {
    case HV_CLEAN:      return "clean";
    case HV_SUSPICIOUS: return "suspicious";
    case HV_MALICIOUS:  return "malicious";
    case HV_CRITICAL:   return "critical";
    case HV_NOTELF:     return "not-elf";
    default:            return "unknown";
    }
}

int husk_band(int score)
{
    if (score >= 75) return HV_CRITICAL;
    if (score >= 45) return HV_MALICIOUS;
    if (score >= 15) return HV_SUSPICIOUS;
    return HV_CLEAN;
}

const char *husk_typename(int t)
{
    switch (t) {
    case 0:  return "none";
    case 1:  return "rel";
    case 2:  return "exec";
    case 3:  return "dyn";
    case 4:  return "core";
    default: return "odd";
    }
}

const char *husk_machname(int m)
{
    switch (m) {
    case 2:   return "sparc";
    case 3:   return "x86";
    case 8:   return "mips";
    case 20:  return "ppc";
    case 40:  return "arm";
    case 62:  return "x86-64";
    case 183: return "aarch64";
    case 243: return "riscv";
    case 22:  return "s390";
    case 50:  return "ia64";
    default:  return "unknown";
    }
}

char *husk_json_escape(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    size_t i;
    if (!in) in = "";
    for (i = 0; in[i] != '\0' && o + 7 < outsz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            out[o++] = '\\'; out[o++] = (char)c;
        } else if (c < 0x20) {
            o += (size_t)snprintf(out + o, outsz - o, "\\u%04x", (unsigned)c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
    return out;
}

void husk_add_finding(hreport_t *r, const char *id, const char *title,
                      const char *sev, int weight, const char *mitre,
                      const char *fmt, ...)
{
    hfinding_t *f;
    va_list ap;
    if (r->n_findings >= HUSK_MAX_FINDINGS) return;
    f = &r->findings[r->n_findings++];
    memset(f, 0, sizeof(*f));
    snprintf(f->id, sizeof(f->id), "%s", id);
    snprintf(f->title, sizeof(f->title), "%s", title);
    snprintf(f->severity, sizeof(f->severity), "%s", sev);
    f->weight = weight;
    snprintf(f->mitre, sizeof(f->mitre), "%s", mitre ? mitre : "-");
    va_start(ap, fmt);
    vsnprintf(f->detail, sizeof(f->detail), fmt, ap);
    va_end(ap);
}
