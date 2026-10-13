/* report.c — terminal (ANSI) and json renderers */
#include "husk.h"
#include <stdio.h>
#include <string.h>

#define ANSI_DIM    "\x1b[2m"
#define ANSI_RESET  "\x1b[0m"
#define ANSI_RED    "\x1b[31m"
#define ANSI_GREEN  "\x1b[32m"
#define ANSI_YELLOW "\x1b[33m"
#define ANSI_BOLD   "\x1b[1m"
#define ANSI_CYAN   "\x1b[36m"

static const char *BANNER = NULL;  /* kept for ABI symmetry; header is textual */

void husk_print_header(int use_ansi)
{
    const char *dim = use_ansi ? "\x1b[2m" : "";
    const char *rc  = use_ansi ? "\x1b[0m" : "";
    (void)BANNER;
    printf("%shusk %s%s — first-hour triage for elf binaries\n",
           dim, HUSK_VERSION, rc);
    printf("%snothing executes. husk only reads.%s\n\n", dim, rc);
}

static const char *sev_color(const char *sev, int use_ansi)
{
    if (!use_ansi) return "";
    if (strcmp(sev, "high") == 0 || strcmp(sev, "crit") == 0) return ANSI_RED;
    if (strcmp(sev, "med") == 0) return ANSI_YELLOW;
    return ANSI_DIM;
}

static const char *verdict_color(int v, int use_ansi)
{
    if (!use_ansi) return "";
    switch (v) {
    case HV_CRITICAL:
    case HV_MALICIOUS:  return ANSI_RED;
    case HV_SUSPICIOUS: return ANSI_YELLOW;
    case HV_CLEAN:      return ANSI_GREEN;
    default:            return ANSI_DIM;
    }
}

void husk_print_term(const hreport_t *r, int use_ansi, int verbose)
{
    const char *vc = verdict_color(r->verdict, use_ansi);
    const char *rc = use_ansi ? ANSI_RESET : "";
    const char *dc = use_ansi ? ANSI_DIM : "";
    int i;

    if (r->err[0]) {
        printf("  %s%s%s%s  %s\n", vc, husk_verdict_str(r->verdict),
               rc, dc, r->err);
        return;
    }

    printf("  %s", r->path);
    printf("%s [%zu bytes]%s\n", dc, r->size, rc);
    printf("  %s%s%s %s%3d/100%s   %s%s %s %s",
           vc, husk_verdict_str(r->verdict), rc,
           dc, r->score, rc,
           (r->cls == 64) ? "elf64" : "elf32",
           husk_machname(r->e_machine),
           husk_typename(r->e_type),
           (r->endian == 2) ? "be" : "le");

    if (r->needed.n > 0) {
        int k;
        printf("  needs");
        for (k = 0; k < r->needed.n && k < 3; k++)
            printf(" %s", r->needed.name[k]);
        if (r->needed.n > 3) printf(" +more");
    }
    printf("\n");

    printf("  %sent %.2f%s", dc, r->ent_overall, rc);
    if (verbose && r->ent_max > 0.0)
        printf("%s (%s %.2f)%s", dc, r->ent_max_name, r->ent_max, rc);
    printf("%s hardening:%s%s%s%s%s\n", dc,
           r->pie ? " pie" : " no-pie",
           r->nx ? " nx" : "",
           r->relro ? (r->bind_now ? " relro-full" : " relro") : " no-relro",
           r->canary ? " canary" : "",
           rc);

    if (r->n_findings == 0) {
        printf("  %sno indicators%s\n", dc, rc);
    } else {
        for (i = 0; i < r->n_findings; i++) {
            const hfinding_t *f = &r->findings[i];
            printf("  %s%-7s%s %s%-34s%s %s[%s]%s %s%2d%s  %s\n",
                   dc, f->id, rc,
                   use_ansi ? ANSI_BOLD : "", f->title, rc,
                   sev_color(f->severity, use_ansi), f->severity, rc,
                   dc, f->weight, rc,
                   f->detail);
        }
    }
    printf("\n");
}

void husk_print_json(const hreport_t *r)
{
    char esc[HUSK_MAX_PATH * 2];
    int i;

    printf("{\"path\":\"%s\"", husk_json_escape(r->path, esc, sizeof(esc)));
    if (r->err[0]) {
        printf(",\"error\":\"%s\",\"verdict\":\"%s\"}\n",
               husk_json_escape(r->err, esc, sizeof(esc)),
               husk_verdict_str(r->verdict));
        return;
    }
    printf(",\"size\":%lu", (unsigned long)r->size);
    printf(",\"class\":\"elf%d\"", r->cls);
    printf(",\"endian\":\"%s\"", (r->endian == 2) ? "be" : "le");
    printf(",\"type\":\"%s\"", husk_typename(r->e_type));
    printf(",\"machine\":\"%s\"", husk_machname(r->e_machine));
    printf(",\"entry\":%llu", (unsigned long long)r->e_entry);
    printf(",\"entropy\":{\"overall\":%.3f", r->ent_overall);
    if (r->ent_max > 0.0)
        printf(",\"max\":%.3f,\"max_section\":\"%s\"",
               r->ent_max,
               husk_json_escape(r->ent_max_name, esc, sizeof(esc)));
    printf("}");

    printf(",\"hardening\":{\"pie\":%s,\"nx\":%s,\"relro\":%s,\"bind_now\":%s,\"canary\":%s}",
           r->pie ? "true" : "false",
           r->nx ? "true" : "false",
           r->relro ? "true" : "false",
           r->bind_now ? "true" : "false",
           r->canary ? "true" : "false");

    printf(",\"interp\":");
    if (r->interp[0])
        printf("\"%s\"", husk_json_escape(r->interp, esc, sizeof(esc)));
    else
        printf("null");

    printf(",\"needed\":[");
    for (i = 0; i < r->needed.n; i++)
        printf("%s\"%s\"", i ? "," : "",
               husk_json_escape(r->needed.name[i], esc, sizeof(esc)));
    printf("]");

    printf(",\"imports\":[");
    for (i = 0; i < r->imports.n && i < 96; i++)
        printf("%s\"%s\"", i ? "," : "",
               husk_json_escape(r->imports.name[i], esc, sizeof(esc)));
    printf("],\"imports_total\":%d,\"imports_truncated\":%s",
           r->imports.n, r->imports_trunc ? "true" : "false");

    printf(",\"findings\":[");
    for (i = 0; i < r->n_findings; i++) {
        const hfinding_t *f = &r->findings[i];
        char e1[576], e2[576], e3[576], e5[576], e6[576];
        printf("%s{\"id\":\"%s\",\"rule\":\"%s\",\"severity\":\"%s\","
               "\"weight\":%d,\"mitre\":\"%s\",\"detail\":\"%s\"}",
               i ? "," : "",
               husk_json_escape(f->id, e1, sizeof(e1)),
               husk_json_escape(f->title, e2, sizeof(e2)),
               husk_json_escape(f->severity, e3, sizeof(e3)),
               f->weight,
               husk_json_escape(f->mitre, e5, sizeof(e5)),
               husk_json_escape(f->detail, e6, sizeof(e6)));
    }
    printf("]");
    printf(",\"score\":%d,\"verdict\":\"%s\"}\n", r->score,
           husk_verdict_str(r->verdict));
}
