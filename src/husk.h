/* husk — first-hour static triage for ELF binaries.
 * reads corpses. executes nothing.
 */
#ifndef HUSK_H
#define HUSK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define HUSK_VERSION   "0.1.0"
#define HUSK_MAX_PATH  1024
#define HUSK_MAX_NEEDED   16
#define HUSK_MAX_IMPORTS  512
#define HUSK_MAX_FINDINGS 64
#define HUSK_MAX_SECS     96
#define HUSK_MAX_SEGS     32
#define HUSK_MAX_SEGSTR   64

/* verdicts (also used as exit codes) */
enum { HV_CLEAN = 0, HV_SUSPICIOUS = 1, HV_MALICIOUS = 2, HV_CRITICAL = 3, HV_NOTELF = -1 };

typedef struct {
    uint32_t name_off, type;
    uint64_t flags, addr, offset, size;
    int      data_ok;          /* section bytes lie inside the file */
    char     name[72];
} hsec_t;

typedef struct {
    uint32_t type, flags;
    uint64_t offset, vaddr, filesz, memsz;
} hseg_t;

typedef struct {
    int n;
    char name[HUSK_MAX_NEEDED][96];
} hstrlist_t;

typedef struct {
    int n;
    char name[HUSK_MAX_IMPORTS][96];
} himplist_t;

typedef struct {
    char id[12];
    char title[64];
    char severity[12];
    int  weight;
    char mitre[16];
    char detail[288];
} hfinding_t;

typedef struct {
    char     path[HUSK_MAX_PATH];
    size_t   size;
    int      cls;              /* 32 / 64, 0 = unknown */
    int      endian;           /* 1 = LE, 2 = BE */
    int      e_type, e_machine;
    uint64_t e_entry;
    int      has_sht, has_dyn, has_interp;
    char     interp[160];
    hstrlist_t needed;
    char     rpath[240], runpath[240];
    himplist_t imports;
    int      imports_trunc;
    hsec_t   secs[HUSK_MAX_SECS];
    int      n_secs;
    hseg_t   segs[HUSK_MAX_SEGS];
    int      n_segs;
    /* hardening */
    int pie, nx, canary, relro, bind_now;
    int gnu_stack;         /* PT_GNU_STACK present */
    int nx_shstrndx;       /* shstrndx out of range */
    /* entropy */
    double ent_overall, ent_max, ent_text;
    char   ent_max_name[72];
    /* results */
    hfinding_t findings[HUSK_MAX_FINDINGS];
    int n_findings;
    int score, verdict;
    char err[192];
} hreport_t;

/* elf.c */
int  husk_load(const char *path, hreport_t *r, uint8_t **map_out);
     /* 0 ok, -1 error (r->err set). if map_out != NULL, the caller
      * receives ownership of the file image (free() when done). */
void husk_free(hreport_t *r);

/* entropy.c */
double husk_entropy(const uint8_t *p, size_t n);

/* rules.c */
void husk_rules_run(hreport_t *r, const uint8_t *map, size_t mapsz);
void husk_print_rulelist(void);

/* report.c */
void husk_print_term(const hreport_t *r, int use_ansi, int verbose);
void husk_print_json(const hreport_t *r);
void husk_print_header(int use_ansi);

/* util.c */
const char *husk_verdict_str(int v);
const char *husk_machname(int m);
const char *husk_typename(int t);
int   husk_band(int score);
char *husk_json_escape(const char *in, char *out, size_t outsz);
void  husk_add_finding(hreport_t *r, const char *id, const char *title,
                       const char *sev, int weight, const char *mitre,
                       const char *fmt, ...);

#endif /* HUSK_H */
