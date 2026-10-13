/* rules.c — weighted indicator engine.
 * structure (H-1xx), imports (H-2xx), strings (H-3xx).
 * static analysis only: nothing here executes the subject.
 */
#include "husk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* rule registry                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *id;
    const char *title;
    const char *sev;
    int   weight;
    const char *mitre;
} hrule_t;

static const hrule_t RULES[] = {
    /* structure */
    { "H-101", "section header table absent",        "high",   18, "T1027"     },
    { "H-102", "entry point outside exec segment",   "high",   22, "T1059"     },
    { "H-103", "writable+executable load segment",   "med",    15, "T1059"     },
    { "H-104", "rwx stack / gnu_stack missing",      "med",     8, "T1059"     },
    { "H-105", "irregular section names",            "med",    12, "T1027"     },
    { "H-106", "upx packer magic",                   "high",   20, "T1027.002" },
    { "H-107", "high .text entropy",                 "med",    15, "T1027"     },
    { "H-108", "high overall entropy, tiny imports", "high",   18, "T1027"     },
    { "H-109", "dynamic libs but no interpreter",    "med",    10, "T1129"     },
    { "H-110", "rpath/runpath into /tmp or relative","med",    12, "T1574"     },
    { "H-111", "interpreter outside /lib",           "med",    10, "T1574"     },
    { "H-112", "opaque: no symtab and no dynsym",    "info",    6, "T1027"     },
    { "H-113", "shstrtab zeroed / names missing",    "med",    15, "T1027"     },
    { "H-114", "section header geometry off",        "low",     8, "T1027"     },
    /* imports */
    { "H-201", "ptrace import",                      "med",    14, "T1620"     },
    { "H-202", "process_vm_* cross-process read",    "high",   16, "T1055"     },
    { "H-203", "io_uring setup imports",             "high",   20, "T1106"     },
    { "H-204", "dlopen-only import profile",         "med",    12, "T1129"     },
    { "H-205", "setuid/privilege pivot imports",     "med",    10, "T1548"     },
    { "H-206", "socket+dup2+exec bind/reverse kit",  "high",   18, "T1059.004" },
    /* strings */
    { "H-301", "anti-debug strings",                 "med",    14, "T1620"     },
    { "H-302", "anti-vm / sandbox strings",          "med",    10, "T1497"     },
    { "H-303", "cron persistence paths",             "med",    10, "T1053"     },
    { "H-304", "boot/service persistence paths",     "med",    10, "T1543"     },
    { "H-305", "ssh key planting paths",             "high",   14, "T1098"     },
    { "H-306", "process masquerade names",           "med",    12, "T1036"     },
    { "H-307", "privilege file targets",             "low",     8, "T1548"     },
    { "H-308", "kernel module loader strings",       "med",    12, "T1547"     },
    { "H-309", "/dev/tcp reverse shell grammar",     "high",   20, "T1059"     },
    { "H-310", "crypto miner markers",               "high",   16, "T1496"     },
    { "H-311", "ransom note markers",                "high",   14, "T1486"     },
    { "H-312", "onion endpoint strings",             "med",    10, "T1090.003" },
    { "H-313", "credential store paths",             "med",    10, "T1555"     },
    { "H-314", "fetch-and-execute chain",            "high",   14, "T1105"     },
    { "H-315", "base64 command blob",                "high",   16, "T1140"     },
    { "H-316", "dga-like domain cluster",            "med",     8, "T1568"     },
    { "H-317", "hardcoded c2 ip list",               "med",     8, "T1071"     },
    { "H-318", "edr/av kill list",                   "high",   16, "T1562"     },
    { "H-319", "ld_preload manipulation",            "med",    10, "T1574.006" },
    { "H-320", "/etc/ld.so.preload rootkit vector",  "high",   16, "T1574.006" },
    { "H-321", "history/env tamper strings",         "low",     8, "T1070"     },
    { "H-322", "wallet address strings",             "info",    4, "T1657"     }
};

#define N_RULES ((int)(sizeof(RULES) / sizeof(RULES[0])))

void husk_print_rulelist(void)
{
    int i;
    printf("%-7s %-38s %-9s %5s  %s\n", "id", "rule", "severity", "weight", "mitre");
    for (i = 0; i < N_RULES; i++)
        printf("%-7s %-38s %-9s %5d  %s\n",
               RULES[i].id, RULES[i].title, RULES[i].sev,
               RULES[i].weight, RULES[i].mitre);
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

#define MAX_STRINGS 6000
#define MAX_SCAN    (24u << 20)
#define MIN_STRLEN  4

typedef struct { uint32_t off, len; } sstr_t;

typedef struct {
    sstr_t s[MAX_STRINGS];
    int n;
} strpool_t;

static void strpool_build(strpool_t *sp, const uint8_t *map, size_t mapsz)
{
    size_t limit = mapsz < MAX_SCAN ? mapsz : MAX_SCAN;
    size_t i = 0, run = 0;
    sp->n = 0;
    while (i < limit) {
        uint8_t c = map[i];
        if (c >= 0x20 && c < 0x7f) {
            run++;
        } else {
            if (run >= MIN_STRLEN && sp->n < MAX_STRINGS) {
                sp->s[sp->n].off = (uint32_t)(i - run);
                sp->s[sp->n].len = (uint32_t)(run > 511 ? 511 : run);
                sp->n++;
            }
            run = 0;
        }
        i++;
    }
    if (run >= MIN_STRLEN && sp->n < MAX_STRINGS) {
        sp->s[sp->n].off = (uint32_t)(i - run);
        sp->s[sp->n].len = (uint32_t)(run > 511 ? 511 : run);
        sp->n++;
    }
}

/* copy string to lowercase buffer; returns length or -1 if too long */
static int sstr_lower(const uint8_t *map, sstr_t s, char *out, size_t outsz)
{
    uint32_t i;
    if ((size_t)s.len + 1 > outsz) return -1;
    for (i = 0; i < s.len; i++)
        out[i] = (char)tolower(map[s.off + i]);
    out[i] = '\0';
    return (int)i;
}

static int contains_n(const char *hay, const char *const *needles, int n,
                      char hits[3][40], int *nhits)
{
    int i, found = 0;
    *nhits = 0;
    for (i = 0; i < n; i++) {
        if (strstr(hay, needles[i])) {
            found++;
            if (*nhits < 3) {
                snprintf(hits[*nhits], 40, "%s", needles[i]);
                (*nhits)++;
            }
        }
    }
    return found;
}

static void join_hits(char *detail, size_t dsz, char hits[3][40], int nhits)
{
    int i;
    if (dsz > 0) detail[0] = '\0';
    for (i = 0; i < nhits && i < 3; i++) {
        if (i) strncat(detail, ", ", dsz - strlen(detail) - 1);
        strncat(detail, hits[i], dsz - strlen(detail) - 1);
    }
}

/* ------------------------------------------------------------------ */
/* structure rules                                                     */
/* ------------------------------------------------------------------ */

static void rules_structure(hreport_t *r)
{
    int have_exec = 0, entry_in_exec = 0, i;
    int n_load = 0, n_imports = r->imports.n;

    for (i = 0; i < r->n_segs; i++) {
        const hseg_t *s = &r->segs[i];
        if (s->type != 1u /* PT_LOAD */) continue;
        n_load++;
        if (s->flags & 0x1u) {
            have_exec = 1;
            if (r->e_entry >= s->vaddr && r->e_entry < s->vaddr + s->filesz)
                entry_in_exec = 1;
        }
        if ((s->flags & 0x3u) == 0x3u)
            husk_add_finding(r, RULES[2].id, RULES[2].title, RULES[2].sev,
                             RULES[2].weight, RULES[2].mitre,
                             "load segment %d mapped w+x", i);
    }

    if (have_exec && !entry_in_exec && r->e_entry != 0)
        husk_add_finding(r, RULES[1].id, RULES[1].title, RULES[1].sev,
                         RULES[1].weight, RULES[1].mitre,
                         "entry 0x%llx lands in no executable load segment",
                         (unsigned long long)r->e_entry);

    if (r->gnu_stack && !r->nx)
        husk_add_finding(r, RULES[3].id, RULES[3].title, RULES[3].sev,
                         RULES[3].weight, RULES[3].mitre,
                         "pt_gnu_stack mapped rwx");

    if (!r->has_sht)
        husk_add_finding(r, RULES[0].id, RULES[0].title, RULES[0].sev,
                         RULES[0].weight, RULES[0].mitre,
                         r->has_dyn ? "dynamic object stripped of its section map"
                                    : "section map absent entirely");

    /* an exec that needs libs but carries no interpreter cannot load */
    if (r->e_type == 2 && r->needed.n > 0 && !r->has_interp)
        husk_add_finding(r, RULES[8].id, RULES[8].title, RULES[8].sev,
                         RULES[8].weight, RULES[8].mitre,
                         "%d needed libs, no pt_interp", r->needed.n);

    if (r->interp[0] && strncmp(r->interp, "/lib", 4) != 0)
        husk_add_finding(r, RULES[10].id, RULES[10].title, RULES[10].sev,
                         RULES[10].weight, RULES[10].mitre,
                         "interp = %s", r->interp);

    if (strstr(r->rpath, "/tmp") || strstr(r->rpath, "./") ||
        strstr(r->runpath, "/tmp") || strstr(r->runpath, "./"))
        husk_add_finding(r, RULES[9].id, RULES[9].title, RULES[9].sev,
                         RULES[9].weight, RULES[9].mitre,
                         "rpath=%s runpath=%s",
                         r->rpath[0] ? r->rpath : "-",
                         r->runpath[0] ? r->runpath : "-");

    /* section name geometry */
    {
        int unnamed = 0, nonstd = 0;
        char odd[3][40];
        for (i = 0; i < 3; i++) odd[i][0] = '\0';
        for (i = 0; i < r->n_secs; i++) {
            const char *nm = r->secs[i].name;
            if (nm[0] == '\0') { unnamed++; continue; }
            if (nm[0] != '.') {
                nonstd++;
                if (nonstd <= 3) snprintf(odd[nonstd - 1], 40, "%s", nm);
            }
        }
        if (r->has_sht && r->nx_shstrndx)
            husk_add_finding(r, RULES[13].id, RULES[13].title, RULES[13].sev,
                             RULES[13].weight, RULES[13].mitre,
                             "shstrndx out of range");
        if (r->has_sht && r->n_secs > 0 && unnamed >= r->n_secs / 2)
            husk_add_finding(r, RULES[12].id, RULES[12].title, RULES[12].sev,
                             RULES[12].weight, RULES[12].mitre,
                             "%d of %d section names empty", unnamed, r->n_secs);
        if (nonstd >= 3)
            husk_add_finding(r, RULES[4].id, RULES[4].title, RULES[4].sev,
                             RULES[4].weight, RULES[4].mitre,
                             "%d nonstd names: %s, %s, %s",
                             nonstd, odd[0], odd[1], odd[2]);
    }

    if (r->has_sht) {
        int has_symtab = 0, has_dynsym = 0;
        for (i = 0; i < r->n_secs; i++) {
            if (r->secs[i].type == 2u /* SHT_SYMTAB */) has_symtab = 1;
            if (r->secs[i].type == 11u /* SHT_DYNSYM */) has_dynsym = 1;
        }
        if (!has_symtab && !has_dynsym)
            husk_add_finding(r, RULES[11].id, RULES[11].title, RULES[11].sev,
                             RULES[11].weight, RULES[11].mitre,
                             "no symbol tables survive");
    }

    /* entropy-driven rules */
    if (r->ent_text >= 7.2)
        husk_add_finding(r, RULES[6].id, RULES[6].title, RULES[6].sev,
                         RULES[6].weight, RULES[6].mitre,
                         ".text entropy %.2f", r->ent_text);
    if (n_load > 0 && n_imports <= 6 &&
        (r->ent_overall >= 7.4 || r->ent_max >= 7.5))
        husk_add_finding(r, RULES[7].id, RULES[7].title, RULES[7].sev,
                         RULES[7].weight, RULES[7].mitre,
                         "overall %.2f / %s %.2f with %d imports",
                         r->ent_overall, r->ent_max_name, r->ent_max,
                         n_imports);
}

/* ------------------------------------------------------------------ */
/* import rules                                                        */
/* ------------------------------------------------------------------ */

static int imports_include(const hreport_t *r, const char *name)
{
    int i;
    for (i = 0; i < r->imports.n; i++)
        if (strcmp(r->imports.name[i], name) == 0) return 1;
    return 0;
}

static int imports_prefix(const hreport_t *r, const char *pre)
{
    int i;
    for (i = 0; i < r->imports.n; i++)
        if (strncmp(r->imports.name[i], pre, strlen(pre)) == 0) return 1;
    return 0;
}

static void rules_imports(hreport_t *r)
{
    if (imports_include(r, "ptrace") || imports_prefix(r, "_ptrace"))
        husk_add_finding(r, RULES[14].id, RULES[14].title, RULES[14].sev,
                         RULES[14].weight, RULES[14].mitre, "ptrace()");

    {
        int pv = 0;
        if (imports_prefix(r, "process_vm_readv")) pv++;
        if (imports_prefix(r, "process_vm_writev")) pv++;
        if (pv)
            husk_add_finding(r, RULES[15].id, RULES[15].title, RULES[15].sev,
                             RULES[15].weight, RULES[15].mitre,
                             "%d process_vm_* imports", pv);
    }
    {
        int io = 0;
        char first[40];
        first[0] = '\0';
        if (imports_include(r, "io_uring_setup")) {
            io++; snprintf(first, sizeof(first), "io_uring_setup");
        }
        if (imports_include(r, "io_uring_enter")) io++;
        if (imports_include(r, "io_uring_register")) io++;
        if (io)
            husk_add_finding(r, RULES[16].id, RULES[16].title, RULES[16].sev,
                             RULES[16].weight, RULES[16].mitre,
                             "%d io_uring call(s), e.g. %s%s", io, first,
                             io > 1 ? ", +more" : "");
    }
    {
        int dl = imports_include(r, "dlopen") || imports_include(r, "dlsym");
        if (dl && r->imports.n <= 6 && r->has_dyn)
            husk_add_finding(r, RULES[17].id, RULES[17].title, RULES[17].sev,
                             RULES[17].weight, RULES[17].mitre,
                             "dlopen/dlsym with only %d imports", r->imports.n);
    }
    {
        int su = imports_include(r, "setuid") || imports_include(r, "setresuid") ||
                 imports_include(r, "seteuid");
        int ex = imports_include(r, "execve") || imports_include(r, "execl") ||
                 imports_include(r, "system");
        if (su && ex)
            husk_add_finding(r, RULES[18].id, RULES[18].title, RULES[18].sev,
                             RULES[18].weight, RULES[18].mitre,
                             "privilege pivot + exec pair");
    }
    {
        int so = imports_include(r, "socket") || imports_include(r, "connect");
        int du = imports_include(r, "dup2");
        int ex = imports_include(r, "execve");
        if (so && du && ex)
            husk_add_finding(r, RULES[19].id, RULES[19].title, RULES[19].sev,
                             RULES[19].weight, RULES[19].mitre,
                             "socket/dup2/execve trident");
    }
}

/* ------------------------------------------------------------------ */
/* string rules                                                        */
/* ------------------------------------------------------------------ */

static int scan_family(hreport_t *r, int rule_idx, strpool_t *sp,
                       const uint8_t *map, const char *const *list, int listn,
                       int minhits)
{
    char hits[3][40];
    char buf[512];
    int i, total = 0, nh = 0;
    for (i = 0; i < sp->n; i++) {
        char h2[3][40];
        int nh2;
        if (sstr_lower(map, sp->s[i], buf, sizeof(buf)) < 0) continue;
        total += contains_n(buf, list, listn, h2, &nh2);
        if (nh2 > 0 && nh < 3) {
            int k;
            for (k = 0; k < nh2 && nh < 3; k++) {
                snprintf(hits[nh], 40, "%.39s", h2[k]);
                nh++;
            }
        }
    }
    if (total >= minhits) {
        char d[240];
        join_hits(d, sizeof(d), hits, nh);
        husk_add_finding(r, RULES[rule_idx].id, RULES[rule_idx].title,
                         RULES[rule_idx].sev, RULES[rule_idx].weight,
                         RULES[rule_idx].mitre, "%s", d);
        return 1;
    }
    return 0;
}

/* parse dotted quad at p; returns 1 on success */
static int parse_ip4(const uint8_t *p, size_t rem, int out[4], int *adv)
{
    int i;
    *adv = 0;
    for (i = 0; i < 4; i++) {
        int val = 0, digits = 0;
        while (digits < 3 && (size_t)(*adv) < rem &&
               p[*adv] >= '0' && p[*adv] <= '9') {
            val = val * 10 + (p[*adv] - '0');
            digits++;
            (*adv)++;
        }
        if (digits == 0) return 0;
        out[i] = val;
        if (i < 3) {
            if ((size_t)(*adv) >= rem || p[*adv] != '.') return 0;
            (*adv)++;
        }
    }
    return 1;
}

static void rules_strings(hreport_t *r, const uint8_t *map, size_t mapsz)
{
    strpool_t sp;
    int i, z;

    static const char *const ANTIDBG[] = {
        "tracerpid", "ptrace_traceme", "/proc/self/mem", "gdb -p"
    };
    static const char *const ANTIVM[] = {
        "vmwarevmware", "xenvmmxenvmm", "kvmkvmkvm", "vboxservice", "/proc/xen"
    };
    static const char *const CRON[] = {
        "/etc/cron", "/var/spool/cron", "crontab"
    };
    static const char *const BOOT[] = {
        "/etc/rc.local", "/etc/init.d", "/etc/systemd", "systemctl",
        "/lib/systemd"
    };
    static const char *const SSHKEY[] = {
        "authorized_keys", "/.ssh/id_", "/root/.ssh"
    };
    static const char *const MASQ[] = {
        "[kworker", "[ksoftirqd", "[migration", "[rcu_", "kthreadd", "sshd: "
    };
    static const char *const PRIV[] = {
        "/etc/shadow", "/etc/passwd", "/etc/sudoers", "pkexec"
    };
    static const char *const KMOD[] = {
        "insmod", "rmmod", "modprobe", "/proc/kallsyms", "/dev/kmem"
    };
    static const char *const REVSH[] = {
        "/dev/tcp/", ">&/dev/tcp", "bash -i", "/bin/sh -i"
    };
    static const char *const MINER[] = {
        "stratum+tcp", "stratum+ssl", "xmrig", "cryptonight", "moneropool"
    };
    static const char *const RANSOM[] = {
        ".encrypted", ".locked", "readme_for_decrypt", "restore-files",
        "your files have been", "recover your files"
    };
    static const char *const STEAL[] = {
        "login data", "web data", "key4.db", "logins.json", "kwallet",
        "tdata", "wallet.dat", "cookies.sqlite", "local state"
    };
    static const char *const FETCH[] = {
        "curl -fs", "curl -o", "wget -o", "| sh", "|sh", "| bash", "|bash",
        "chmod +x /tmp"
    };
    static const char *const EDRKILL[] = {
        "sentinelone", "crowdstrike", "carbonblack", "cbdefense", "symantec",
        "mcafee", "sophos", "kaspersky", "bitdefender", "edrkillswitch"
    };
    static const char *const ENVTAMPER[] = {
        "unset histfile", "histfile=/dev/null", "export histsize=0",
        "history -c"
    };
    static const char *const LDLOAD[] = { "ld_preload" };
    static const char *const PRELOAD[] = { "/etc/ld.so.preload" };

    strpool_build(&sp, map, mapsz);

    scan_family(r, 20, &sp, map, ANTIDBG, 4, 1);      /* H-301 */
    scan_family(r, 21, &sp, map, ANTIVM, 5, 1);       /* H-302 */
    scan_family(r, 22, &sp, map, CRON, 3, 1);         /* H-303 */
    scan_family(r, 23, &sp, map, BOOT, 5, 2);         /* H-304 */
    scan_family(r, 24, &sp, map, SSHKEY, 3, 1);       /* H-305 */
    scan_family(r, 25, &sp, map, MASQ, 6, 1);         /* H-306 */
    scan_family(r, 26, &sp, map, PRIV, 4, 2);         /* H-307 */
    scan_family(r, 27, &sp, map, KMOD, 5, 2);         /* H-308 */
    scan_family(r, 28, &sp, map, REVSH, 4, 1);        /* H-309 */
    scan_family(r, 29, &sp, map, MINER, 5, 1);        /* H-310 */
    scan_family(r, 30, &sp, map, RANSOM, 6, 2);       /* H-311 */
    scan_family(r, 32, &sp, map, STEAL, 9, 2);        /* H-313 */
    scan_family(r, 33, &sp, map, FETCH, 8, 2);        /* H-314 */
    scan_family(r, 40, &sp, map, ENVTAMPER, 4, 1);    /* H-321 */

    /* loader manipulation only matters for binaries that participate
     * in dynamic loading; statically-linked glibc embeds these inertly */
    if (r->has_interp || r->needed.n > 0 || r->imports.n > 0) {
        scan_family(r, 38, &sp, map, LDLOAD, 1, 1);   /* H-319 */
        scan_family(r, 39, &sp, map, PRELOAD, 1, 1);  /* H-320 */
    }

    /* H-312 onion endpoints */
    {
        char buf[512];
        int found = 0;
        for (i = 0; i < sp.n && !found; i++) {
            if (sstr_lower(map, sp.s[i], buf, sizeof(buf)) < 0) continue;
            if (strstr(buf, ".onion") && strlen(buf) >= 22) {
                husk_add_finding(r, RULES[31].id, RULES[31].title,
                                 RULES[31].sev, RULES[31].weight,
                                 RULES[31].mitre, "%.48s", buf);
                found = 1;
            }
        }
    }

    /* H-315 base64 command blobs */
    {
        static const char b64a[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int found = 0;
        for (i = 0; i < sp.n && !found; i++) {
            uint32_t L = sp.s[i].len;
            const uint8_t *p = map + sp.s[i].off;
            uint32_t k;
            uint8_t out[2048];
            size_t no = 0;
            uint32_t acc = 0;
            int nb = 0;
            int ok = 1;
            if (L < 200) continue;
            for (k = 0; k < L; k++) {
                if (p[k] == '=') continue;
                if (!strchr(b64a, (char)p[k])) { ok = 0; break; }
            }
            if (!ok) continue;
            for (k = 0; k < L && no < sizeof(out) - 1; k++) {
                const char *q;
                if (p[k] == '=') break;
                q = strchr(b64a, (char)p[k]);
                acc = (acc << 6) | (uint32_t)(q - b64a);
                nb += 6;
                if (nb >= 8) {
                    nb -= 8;
                    out[no++] = (uint8_t)((acc >> nb) & 0xff);
                }
            }
            out[no] = 0;
            if (no > 12) {
                char low[2048];
                size_t y;
                for (y = 0; y < no && y < sizeof(low) - 1; y++)
                    low[y] = (char)tolower(out[y]);
                low[y] = 0;
                if (strstr(low, "curl") || strstr(low, "wget") ||
                    strstr(low, "sh -c") || strstr(low, "bash -i") ||
                    strstr(low, "|sh") || strstr(low, "| sh") ||
                    strstr(low, "/bin/sh")) {
                    char d[96];
                    for (y = 0; y < no && y < 40; y++)
                        d[y] = (out[y] >= 0x20 && out[y] < 0x7f)
                               ? (char)out[y] : '.';
                    d[y] = 0;
                    if (strstr(d, "http"))
                        for (y = 0; d[y]; y++)
                            if (d[y] == '.') { d[y] = '['; break; }
                    husk_add_finding(r, RULES[34].id, RULES[34].title,
                                     RULES[34].sev, RULES[34].weight,
                                     RULES[34].mitre,
                                     "%d bytes decode to \"%s\"",
                                     (int)no, d);
                    found = 1;
                }
            }
        }
    }

    /* H-316 dga-like domain cluster + H-317 hardcoded ip list */
    {
        char doms[64][72];
        char ips[32][20];
        int nd = 0, nip = 0, synth = 0;
        char buf[512];
        for (i = 0; i < sp.n; i++) {
            if (sstr_lower(map, sp.s[i], buf, sizeof(buf)) < 0) continue;
            {
                size_t k = 0, bl = strlen(buf);
                while (k < bl) {
                    if (buf[k] >= '0' && buf[k] <= '9' &&
                        (k == 0 || (buf[k-1] != '.' && buf[k-1] != '-'))) {
                        int ip[4], adv = 0;
                        if (parse_ip4((const uint8_t *)buf + k,
                                      bl - k, ip, &adv)) {
                            char ipstr[20];
                            int known = 0, z2;
                            snprintf(ipstr, sizeof(ipstr), "%d.%d.%d.%d",
                                     ip[0], ip[1], ip[2], ip[3]);
                            for (z2 = 0; z2 < nip; z2++)
                                if (strcmp(ips[z2], ipstr) == 0) { known = 1; break; }
                            if (!known && nip < 32) {
                                snprintf(ips[nip], 20, "%s", ipstr);
                                nip++;
                                if (ip[0] == 192 && ip[1] == 0 && ip[2] == 2) synth = 1;
                                if (ip[0] == 198 && ip[1] == 51) synth = 1;
                                if (ip[0] == 203 && ip[1] == 0 && ip[2] == 113) synth = 1;
                            }
                            k += (size_t)adv;
                            continue;
                        }
                    }
                    if ((buf[k] >= 'a' && buf[k] <= 'z') ||
                        (buf[k] >= '0' && buf[k] <= '9')) {
                        char tmp[72];
                        size_t tl = 0, m = k;
                        while (m < bl && tl + 1 < sizeof(tmp) &&
                               ((buf[m] >= 'a' && buf[m] <= 'z') ||
                                (buf[m] >= '0' && buf[m] <= '9') ||
                                buf[m] == '-' || buf[m] == '.')) {
                            tmp[tl++] = buf[m]; m++;
                        }
                        tmp[tl] = 0;
                        if (tl >= 6 && strchr(tmp, '.')) {
                            static const char *const TLD[] = {
                                ".com", ".net", ".org", ".info", ".biz",
                                ".xyz", ".top", ".site", ".online", ".cc",
                                ".tk", ".ru", ".su", ".cn"
                            };
                            int hit = 0;
                            for (z = 0; z < 14; z++)
                                if (strstr(tmp, TLD[z])) hit = 1;
                            if (hit && !strstr(tmp, "example") &&
                                !strstr(tmp, "gnu.org") &&
                                !strstr(tmp, "kernel.org") &&
                                !strstr(tmp, "sourceware.org") &&
                                !strstr(tmp, "debian.org")) {
                                int known = 0, z2;
                                for (z2 = 0; z2 < nd; z2++)
                                    if (strcmp(doms[z2], tmp) == 0) { known = 1; break; }
                                if (!known && nd < 64) {
                                    snprintf(doms[nd], 72, "%.60s", tmp);
                                    nd++;
                                }
                            }
                        }
                        k += tl;
                        continue;
                    }
                    k++;
                }
            }
        }
        if (nd >= 6) {
            char d[200];
            snprintf(d, sizeof(d), "%.60s, %.60s, +%d more",
                     doms[0], doms[1], nd - 2);
            husk_add_finding(r, RULES[35].id, RULES[35].title, RULES[35].sev,
                             RULES[35].weight, RULES[35].mitre, "%s", d);
        }
        if (nip >= 3) {
            char d[200];
            snprintf(d, sizeof(d), "%.40s, %.40s, +%d more%s",
                     ips[0], ips[1], nip - 2, synth ? " (doc ranges)" : "");
            husk_add_finding(r, RULES[36].id, RULES[36].title, RULES[36].sev,
                             RULES[36].weight, RULES[36].mitre, "%s", d);
        }
    }

    /* H-318 kill verbs + vendor names */
    {
        static const char *const VERBS[] = { "kill ", "unload ", "bypass ",
                                             "disable " };
        char buf[512];
        int verb = 0;
        int i2;
        for (i2 = 0; i2 < sp.n && !verb; i2++) {
            if (sstr_lower(map, sp.s[i2], buf, sizeof(buf)) < 0) continue;
            for (z = 0; z < 4; z++)
                if (strstr(buf, VERBS[z])) verb = 1;
        }
        if (verb) {
            int found = 0;
            char hits[3][40];
            char d[240];
            int nh = 0;
            for (i2 = 0; i2 < sp.n && !found; i2++) {
                char h2[3][40];
                int nh2;
                if (sstr_lower(map, sp.s[i2], buf, sizeof(buf)) < 0) continue;
                if (contains_n(buf, EDRKILL, 10, h2, &nh2) >= 1) {
                    found = 1;
                    if (nh < 3) {
                        snprintf(hits[nh], 40, "%.39s", h2[0]);
                        nh++;
                    }
                }
            }
            if (found) {
                join_hits(d, sizeof(d), hits, nh);
                husk_add_finding(r, RULES[37].id, RULES[37].title,
                                 RULES[37].sev, RULES[37].weight,
                                 RULES[37].mitre, "%s + kill verbs", d);
            }
        }
    }

    /* H-322 wallet addresses */
    {
        char buf[512];
        int found = 0;
        for (i = 0; i < sp.n && !found; i++) {
            if (sstr_lower(map, sp.s[i], buf, sizeof(buf)) < 0) continue;
            if ((buf[0] == 'b' && buf[1] == 'c' && buf[2] == '1' &&
                 strlen(buf) >= 42) ||
                (buf[0] == '4' && strlen(buf) >= 95)) {
                husk_add_finding(r, RULES[41].id, RULES[41].title,
                                 RULES[41].sev, RULES[41].weight,
                                 RULES[41].mitre, "%.48s", buf);
                found = 1;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* packer                                                              */
/* ------------------------------------------------------------------ */

static void rules_packer(hreport_t *r, const uint8_t *map, size_t mapsz)
{
    size_t i;
    int found = 0;
    size_t limit = mapsz < (2u << 20) ? mapsz : (2u << 20);
    for (i = 0; i + 4 <= limit; i++) {
        if (map[i] == 'U' && map[i+1] == 'P' && map[i+2] == 'X' &&
            map[i+3] == '!') {
            found = 1;
            break;
        }
    }
    if (found)
        husk_add_finding(r, RULES[5].id, RULES[5].title, RULES[5].sev,
                         RULES[5].weight, RULES[5].mitre,
                         "upx signature in first 2 MB");
}

void husk_rules_run(hreport_t *r, const uint8_t *map, size_t mapsz)
{
    int i;
    r->n_findings = 0;
    r->score = 0;

    rules_structure(r);
    rules_imports(r);
    rules_strings(r, map, mapsz);
    rules_packer(r, map, mapsz);

    for (i = 0; i < r->n_findings; i++)
        r->score += r->findings[i].weight;
    if (r->score > 100) r->score = 100;
    r->verdict = husk_band(r->score);
}
