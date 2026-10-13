/* test_main.c — husk unit + fixture + fuzz harness.
 * no dependencies: hand-rolled assertions, deterministic vectors.
 * run from the repository root: ./build/test_main
 */
#include "../src/husk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (cond) { g_pass++; }                                            \
        else {                                                             \
            g_fail++;                                                      \
            printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);       \
        }                                                                  \
    } while (0)

static void mktmpdir(void)
{
#ifdef _WIN32
    system("if not exist test_tmp mkdir test_tmp");
#else
    system("mkdir -p test_tmp");
#endif
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (len && fwrite(data, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long n;
    uint8_t *b;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    b = (uint8_t *)malloc((size_t)n + 1);
    if (!b) { fclose(f); return NULL; }
    if (n > 0 && fread(b, 1, (size_t)n, f) != (size_t)n) {
        free(b); fclose(f); return NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return b;
}

static int has_finding(const hreport_t *r, const char *id)
{
    int i;
    for (i = 0; i < r->n_findings; i++)
        if (strcmp(r->findings[i].id, id) == 0) return 1;
    return 0;
}

static int imports_has(const hreport_t *r, const char *name)
{
    int i;
    for (i = 0; i < r->imports.n; i++)
        if (strcmp(r->imports.name[i], name) == 0) return 1;
    return 0;
}

static void test_entropy(void)
{
    uint8_t zeros[512];
    uint8_t alt[512];
    uint8_t all[256];
    memset(zeros, 0, sizeof(zeros));
    for (size_t i = 0; i < sizeof(alt); i++) alt[i] = (i & 1) ? 0xff : 0x00;
    for (size_t i = 0; i < 256; i++) all[i] = (uint8_t)i;

    CHECK(husk_entropy(zeros, sizeof(zeros)) < 0.0001);
    CHECK(husk_entropy(NULL, 10) == 0.0);
    CHECK(husk_entropy(alt, sizeof(alt)) > 0.99 && husk_entropy(alt, sizeof(alt)) < 1.01);
    CHECK(husk_entropy(all, sizeof(all)) > 7.99);
}

static void test_bands(void)
{
    CHECK(husk_band(0) == HV_CLEAN);
    CHECK(husk_band(14) == HV_CLEAN);
    CHECK(husk_band(15) == HV_SUSPICIOUS);
    CHECK(husk_band(44) == HV_SUSPICIOUS);
    CHECK(husk_band(45) == HV_MALICIOUS);
    CHECK(husk_band(74) == HV_MALICIOUS);
    CHECK(husk_band(75) == HV_CRITICAL);
    CHECK(husk_band(100) == HV_CRITICAL);
}

static void scan_fixture(const char *name, hreport_t *r, uint8_t **map)
{
    char path[256];
    snprintf(path, sizeof(path), "fixtures/bin/%s", name);
    CHECK(husk_load(path, r, map) == 0);
    if (*map) husk_rules_run(r, *map, r->size);
}

static void test_benign(void)
{
    hreport_t *r = (hreport_t *)malloc(sizeof(hreport_t));
    uint8_t *map = NULL;
    scan_fixture("benign.elf", r, &map);
    CHECK(r->cls == 64);
    CHECK(r->endian == 1);
    CHECK(r->e_machine == 62);          /* x86-64 */
    CHECK(r->pie == 1);
    CHECK(r->nx == 1);
    CHECK(r->relro == 1);
    CHECK(r->canary == 1);
    CHECK(r->needed.n >= 1);
    CHECK(strstr(r->needed.name[0], "libc.so.6") != NULL);
    CHECK(imports_has(r, "printf"));
    CHECK(r->n_findings == 0);
    CHECK(r->verdict == HV_CLEAN && r->score == 0);
    CHECK(r->ent_overall > 0.5 && r->ent_overall < 7.0);
    free(map);
    free(r);
}

static void test_imposter(void)
{
    hreport_t *r = (hreport_t *)malloc(sizeof(hreport_t));
    uint8_t *map = NULL;
    scan_fixture("imposter.elf", r, &map);
    CHECK(imports_has(r, "io_uring_setup"));
    CHECK(imports_has(r, "ptrace"));
    CHECK(imports_has(r, "process_vm_readv"));
    CHECK(has_finding(r, "H-203"));
    CHECK(has_finding(r, "H-201"));
    CHECK(has_finding(r, "H-202"));
    CHECK(has_finding(r, "H-305"));
    CHECK(has_finding(r, "H-315"));
    CHECK(r->verdict == HV_CRITICAL);
    CHECK(r->score >= 75);
    free(map);
    free(r);
}

static void test_matrix(void)
{
    struct { const char *file; int verdict; } cases[] = {
        { "ioring.elf",   HV_SUSPICIOUS },
        { "hollower.elf", HV_SUSPICIOUS },
        { "shrouded.elf", HV_SUSPICIOUS },
        { "packed.elf",   HV_MALICIOUS  },
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        hreport_t *r = (hreport_t *)malloc(sizeof(hreport_t));
        uint8_t *map = NULL;
        scan_fixture(cases[i].file, r, &map);
        if (r->verdict != cases[i].verdict) {
            int k;
            printf("  note: %s -> %s %d/100 via",
                   cases[i].file, husk_verdict_str(r->verdict), r->score);
            for (k = 0; k < r->n_findings; k++)
                printf(" %s", r->findings[k].id);
            printf("\n");
        }
        CHECK(r->verdict == cases[i].verdict);
        free(map);
        free(r);
    }
}

static void test_hollower_opacity(void)
{
    hreport_t *r = (hreport_t *)malloc(sizeof(hreport_t));
    uint8_t *map = NULL;
    scan_fixture("hollower.elf", r, &map);
    CHECK(r->has_sht == 0);
    CHECK(r->has_dyn == 1);
    CHECK(r->needed.n >= 1);            /* dynamic segment still parses */
    CHECK(has_finding(r, "H-101"));
    free(map);
    free(r);
}

static void test_packed_entropy(void)
{
    hreport_t *r = (hreport_t *)malloc(sizeof(hreport_t));
    uint8_t *map = NULL;
    scan_fixture("packed.elf", r, &map);
    CHECK(r->ent_max > 7.5);
    CHECK(has_finding(r, "H-106"));
    CHECK(has_finding(r, "H-108"));
    free(map);
    free(r);
}

/* minimal ELF32 big-endian, mips: ehdr + 1 load phdr, no sections */
static void test_elf32_be(void)
{
    uint8_t e[200];
    hreport_t *r;
    uint8_t *map;
    memset(e, 0, sizeof(e));
    e[0] = 0x7f; e[1] = 'E'; e[2] = 'L'; e[3] = 'F';
    e[4] = 1;                    /* elf32 */
    e[5] = 2;                    /* big endian */
    e[6] = 1;                    /* ev current */
    /* e_type exec @0x10, machine mips(8) @0x12 */
    e[0x10] = 0x00; e[0x11] = 2;
    e[0x12] = 0x00; e[0x13] = 8;
    /* e_entry @0x18 = 0x1000 */
    e[0x18] = 0x00; e[0x19] = 0x00; e[0x1a] = 0x10; e[0x1b] = 0x00;
    /* e_phoff @0x1c = 0x34 */
    e[0x1f] = 0x34;
    /* e_phentsize @0x2a = 32 */
    e[0x2b] = 32;
    /* e_phnum @0x2c = 1 */
    e[0x2d] = 1;
    /* phdr: p_type load(1) @0x34, p_offset @0x38=0, p_vaddr @0x3c=0x1000 */
    e[0x37] = 1;
    e[0x3f] = 0x10;
    /* p_filesz @0x44 = 200 (whole file) */
    e[0x47] = 200 & 0xff; e[0x46] = 200 >> 8;
    r = (hreport_t *)malloc(sizeof(hreport_t));
    CHECK(write_file("test_tmp/mips32be.elf", e, sizeof(e)) == 0);
    CHECK(husk_load("test_tmp/mips32be.elf", r, &map) == 0);
    CHECK(r->cls == 32);
    CHECK(r->endian == 2);
    CHECK(r->e_machine == 8);
    CHECK(strcmp(husk_machname(r->e_machine), "mips") == 0);
    CHECK(r->e_entry == 0x1000);
    CHECK(r->has_sht == 0);
    husk_rules_run(r, map, r->size);
    CHECK(r->verdict == HV_SUSPICIOUS);   /* H-101 */
    CHECK(has_finding(r, "H-101"));
    free(map);
    free(r);
}

static void test_truncation_fuzz(void)
{
    size_t src_len;
    uint8_t *src = slurp("fixtures/bin/imposter.elf", &src_len);
    size_t cuts[14] = { 0, 1, 4, 8, 16, 17, 32, 52, 53, 64, 100,
                        0x200, 0x1000, 0 };
    size_t i;
    CHECK(src != NULL);
    if (!src) return;
    cuts[13] = src_len / 2;
    for (i = 0; i < sizeof(cuts) / sizeof(cuts[0]); i++) {
        char path[64];
        hreport_t *r = (hreport_t *)malloc(sizeof(hreport_t));
        uint8_t *map = NULL;
        snprintf(path, sizeof(path), "test_tmp/trunc_%02zu.elf", i);
        CHECK(write_file(path, src, cuts[i] > src_len ? src_len : cuts[i]) == 0);
        if (husk_load(path, r, &map) == 0)
            husk_rules_run(r, map, r->size);
        else
            CHECK(r->err[0] != '\0');
        free(map);
        free(r);
    }
    /* random byte flips across the file — parser must survive all */
    {
        uint32_t seed = 0x1234;
        for (i = 0; i < 300; i++) {
            char path[64];
            hreport_t *r = (hreport_t *)malloc(sizeof(hreport_t));
            uint8_t *map = NULL;
            uint8_t *copy = (uint8_t *)malloc(src_len);
            int flips, k;
            memcpy(copy, src, src_len);
            for (flips = 0; flips < 8; flips++) {
                seed = seed * 1103515245u + 12345u;
                k = (int)((seed >> 16) % (uint32_t)src_len);
                copy[k] = (uint8_t)(seed >> 8);
            }
            snprintf(path, sizeof(path), "test_tmp/flip_%03zu.elf", i);
            write_file(path, copy, src_len);
            if (husk_load(path, r, &map) == 0)
                husk_rules_run(r, map, r->size);
            free(map);
            free(r);
            free(copy);
        }
    }
    /* pure garbage with elf magic prefix */
    {
        uint32_t seed = 0xbeef;
        for (i = 0; i < 200; i++) {
            char path[64];
            hreport_t *r = (hreport_t *)malloc(sizeof(hreport_t));
            uint8_t *map = NULL;
            uint8_t buf[4096];
            size_t len = (i % 900) + 16;
            size_t k;
            buf[0] = 0x7f; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
            for (k = 4; k < len; k++) {
                seed = seed * 1103515245u + 12345u;
                buf[k] = (uint8_t)(seed >> 16);
            }
            snprintf(path, sizeof(path), "test_tmp/garb_%03zu.elf", i);
            write_file(path, buf, len);
            if (husk_load(path, r, &map) == 0)
                husk_rules_run(r, map, r->size);
            free(map);
            free(r);
        }
    }
    free(src);
    CHECK(g_fail == 0);   /* reaching here alive is the point */
}

static void test_notelf(void)
{
    hreport_t *r = (hreport_t *)malloc(sizeof(hreport_t));
    uint8_t *map = NULL;
    CHECK(write_file("test_tmp/plain.txt",
                     (const uint8_t *)"not an elf", 10) == 0);
    CHECK(husk_load("test_tmp/plain.txt", r, &map) != 0);
    CHECK(strstr(r->err, "not an elf") != NULL);
    CHECK(r->verdict == HV_NOTELF);
    free(r);
}

int main(void)
{
    mktmpdir();
    printf("husk %s unit tests\n", HUSK_VERSION);

    test_entropy();
    test_bands();
    test_benign();
    test_imposter();
    test_matrix();
    test_hollower_opacity();
    test_packed_entropy();
    test_elf32_be();
    test_notelf();
    test_truncation_fuzz();

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
