/* main.c — CLI entry: file/dir walking, batch scan, output selection */
#include "husk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#define strdup _strdup
#else
#include <dirent.h>
#endif

#define HUSK_DEPTH_MAX 8

typedef struct {
    int files, dirs, skipped, notelf;
    int n_clean, n_susp, n_mal, n_crit;
} stats_t;

typedef struct {
    int json, plain, quiet, verbose, no_banner;
    stats_t st;
} opts_t;

static void usage(void)
{
    printf("husk %s — first-hour static triage for ELF binaries\n\n",
           HUSK_VERSION);
    printf("usage: husk [options] <path>...\n\n");
    printf("  <path>...   files or directories (recursive)\n");
    printf("  --json      one json object per file + summary line\n");
    printf("  --plain     no ansi, no banner\n");
    printf("  --quiet     verdict lines only\n");
    printf("  --verbose   per-section entropy detail\n");
    printf("  --rules     list the rule registry and exit\n");
    printf("  --no-banner\n");
    printf("  --version   --help\n\n");
    printf("exit codes: 0 clean · 1 suspicious · 2 malicious · 3 critical\n");
    printf("non-elf inputs are skipped, never counted.\n\n");
    printf("nothing executes. husk only reads.\n");
}

static int path_is_dir(const char *p)
{
    struct stat st;
    if (stat(p, &st) != 0) return 0;
    return (st.st_mode & S_IFMT) == S_IFDIR ? 1 : 0;
}

static int path_exists(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0;
}

static void scan_one(const char *path, opts_t *o)
{
    hreport_t *r;
    uint8_t *map = NULL;

    r = (hreport_t *)malloc(sizeof(hreport_t));
    if (!r) return;

    if (husk_load(path, r, &map) != 0) {
        char esc[384];
        if (strstr(r->err, "not an elf")) {
            o->st.notelf++;
            if (o->json)
                printf("{\"path\":\"%s\",\"verdict\":\"not-elf\"}\n",
                       husk_json_escape(path, esc, sizeof(esc)));
        } else {
            o->st.skipped++;
            if (o->json)
                printf("{\"path\":\"%s\",\"error\":\"%s\"}\n",
                       husk_json_escape(path, esc, sizeof(esc)),
                       husk_json_escape(r->err, esc, sizeof(esc)));
            else if (!o->quiet)
                printf("  %-46s skip  %s\n", path, r->err);
        }
        free(r);
        return;
    }

    husk_rules_run(r, map, r->size);
    free(map);

    switch (r->verdict) {
    case HV_CLEAN:      o->st.n_clean++; break;
    case HV_SUSPICIOUS: o->st.n_susp++; break;
    case HV_MALICIOUS:  o->st.n_mal++; break;
    case HV_CRITICAL:   o->st.n_crit++; break;
    default: break;
    }
    o->st.files++;

    if (o->json) {
        husk_print_json(r);
    } else if (!o->quiet) {
        husk_print_term(r, o->plain ? 0 : 1, o->verbose);
    } else {
        printf("%-46s %s %d/100\n", r->path,
               husk_verdict_str(r->verdict), r->score);
    }

    free(r);
}

#ifndef _WIN32

typedef struct {
    char **items;
    int count, cap;
} pathlist_t;

static void collect_cb(const char *p, void *ud)
{
    pathlist_t *pl = (pathlist_t *)ud;
    if (pl->count >= pl->cap) return;
    pl->items[pl->count] = strdup(p);
    if (pl->items[pl->count]) pl->count++;
}

static void walk(const char *dir, int depth,
                 void (*cb)(const char *, void *), void *ud)
{
    DIR *d;
    struct dirent *e;
    if (depth > HUSK_DEPTH_MAX) return;
    d = opendir(dir);
    if (!d) return;
    while ((e = readdir(d)) != NULL) {
        char sub[1024];
        struct stat st;
        size_t dl;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        dl = strlen(dir);
        if (dl > 0 && dir[dl - 1] == '/')
            snprintf(sub, sizeof(sub), "%s%s", dir, e->d_name);
        else
            snprintf(sub, sizeof(sub), "%s/%s", dir, e->d_name);
        if (lstat(sub, &st) != 0) continue;      /* broken link: skip */
        if (S_ISLNK(st.st_mode)) continue;       /* never follow links */
        if (S_ISDIR(st.st_mode))
            walk(sub, depth + 1, cb, ud);
        else if (S_ISREG(st.st_mode))
            cb(sub, ud);
    }
    closedir(d);
}

static void scan_path(const char *path, opts_t *o)
{
    if (!path_exists(path)) {
        fprintf(stderr, "husk: %s: no such file or directory\n", path);
        o->st.skipped++;
        return;
    }
    if (path_is_dir(path)) {
        pathlist_t pl;
        int i;
        o->st.dirs++;
        /* collect first, scan after: stable output order, open dirs once */
        pl.count = 0;
        pl.cap = 100000;
        pl.items = (char **)malloc(sizeof(char *) * (size_t)pl.cap);
        if (!pl.items) return;
        walk(path, 0, collect_cb, &pl);
        for (i = 0; i < pl.count; i++) {
            scan_one(pl.items[i], o);
            free(pl.items[i]);
        }
        free(pl.items);
    } else {
        scan_one(path, o);
    }
}

#else  /* _WIN32 */

static void win_walk(const char *dir, int depth, opts_t *o)
{
    char pattern[1024];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    if (depth > HUSK_DEPTH_MAX) return;
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        char sub[1024];
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;                            /* never follow links */
        snprintf(sub, sizeof(sub), "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            win_walk(sub, depth + 1, o);
        else
            scan_one(sub, o);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static void scan_path(const char *path, opts_t *o)
{
    if (!path_exists(path)) {
        fprintf(stderr, "husk: %s: no such file or directory\n", path);
        o->st.skipped++;
        return;
    }
    if (path_is_dir(path)) {
        o->st.dirs++;
        win_walk(path, 0, o);
    } else {
        scan_one(path, o);
    }
}

#endif /* _WIN32 */

int main(int argc, char **argv)
{
    opts_t o;
    int i, argn = 0, maxv = 0;
    char **args;

    memset(&o, 0, sizeof(o));

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) o.json = 1;
        else if (strcmp(argv[i], "--plain") == 0) o.plain = 1;
        else if (strcmp(argv[i], "--quiet") == 0) o.quiet = 1;
        else if (strcmp(argv[i], "--verbose") == 0) o.verbose = 1;
        else if (strcmp(argv[i], "--no-banner") == 0) o.no_banner = 1;
        else if (strcmp(argv[i], "--rules") == 0) {
            husk_print_rulelist();
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("husk %s\n", HUSK_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            usage();
            return 0;
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fprintf(stderr, "husk: unknown option %s\n", argv[i]);
            usage();
            return 64;
        } else {
            argn++;
        }
    }

    if (argn == 0) {
        usage();
        return 64;
    }

    args = (char **)malloc(sizeof(char *) * (size_t)argn);
    if (!args) return 64;
    argn = 0;
    for (i = 1; i < argc; i++)
        if (!(argv[i][0] == '-' && argv[i][1] != '\0'))
            args[argn++] = argv[i];

    if (!o.json && !o.plain && !o.quiet && !o.no_banner)
        husk_print_header(1);

    for (i = 0; i < argn; i++)
        scan_path(args[i], &o);

    if (o.json) {
        printf("{\"summary\":{\"files\":%d,\"clean\":%d,\"suspicious\":%d,"
               "\"malicious\":%d,\"critical\":%d,\"skipped\":%d,"
               "\"not_elf\":%d}}\n",
               o.st.files, o.st.n_clean, o.st.n_susp, o.st.n_mal,
               o.st.n_crit, o.st.skipped, o.st.notelf);
    } else if (!o.quiet) {
        printf("%s%d files · %d clean · %d suspicious · %d malicious · "
               "%d critical · %d skipped%s\n",
               o.plain ? "" : "\x1b[2m",
               o.st.files, o.st.n_clean, o.st.n_susp, o.st.n_mal,
               o.st.n_crit, o.st.skipped + o.st.notelf,
               o.plain ? "" : "\x1b[0m");
    } else {
        printf("%d files · %d clean · %d suspicious · %d malicious · "
               "%d critical · %d skipped\n",
               o.st.files, o.st.n_clean, o.st.n_susp, o.st.n_mal,
               o.st.n_crit, o.st.skipped + o.st.notelf);
    }

    if (o.st.n_susp > 0) maxv = 1;
    if (o.st.n_mal > 0) maxv = 2;
    if (o.st.n_crit > 0) maxv = 3;

    free(args);
    return maxv;
}
