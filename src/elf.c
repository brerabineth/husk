/* elf.c — bounds-checked ELF32/ELF64 parser, little and big endian.
 * every read is guarded: the input is hostile until proven otherwise.
 */
#include "husk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HUSK_FILE_MAX (512u * 1024u * 1024u)   /* refuse > 512 MB */
#define PT_LOAD       1u
#define PT_DYNAMIC    2u
#define PT_INTERP     3u
#define PT_GNU_STACK  0x6474e551u
#define PT_GNU_RELRO  0x6474e552u
#define SHT_SYMTAB    2u
#define SHT_NOBITS    8u
#define SHT_DYNSYM    11u
#define DT_NULL       0u
#define DT_NEEDED     1u
#define DT_STRTAB     5u
#define DT_RPATH      15u
#define DT_RUNPATH    29u
#define DT_FLAGS      30u
#define DF_BIND_NOW   0x40u
#define DT_FLAGS_1    0x6ffffffbu
#define DF_1_NOW      0x8u

static uint16_t rd16(const uint8_t *p, int be)
{
    return be ? (uint16_t)(((uint16_t)p[0] << 8) | p[1])
              : (uint16_t)(((uint16_t)p[1] << 8) | p[0]);
}

static uint32_t rd32(const uint8_t *p, int be)
{
    if (be) return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                   ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8)  | (uint32_t)p[0];
}

static uint64_t rd64(const uint8_t *p, int be)
{
    uint64_t hi = rd32(p, be);
    uint64_t lo = rd32(p + 4, be);
    return be ? (hi << 32) | lo : (lo << 32) | hi;
}

static int in_range(size_t off, size_t len, size_t total)
{
    return off <= total && len <= total - off;
}

void husk_free(hreport_t *r)
{
    (void)r; /* reports are self-contained value types */
}

/* map a virtual address to a file offset through PT_LOAD segments */
static int vaddr_to_off(const hreport_t *r, uint64_t vaddr, uint64_t *out)
{
    int i;
    for (i = 0; i < r->n_segs; i++) {
        const hseg_t *s = &r->segs[i];
        if (s->type != PT_LOAD) continue;
        if (vaddr >= s->vaddr && s->filesz > 0 &&
            (vaddr - s->vaddr) < s->filesz) {
            *out = s->offset + (vaddr - s->vaddr);
            return 1;
        }
    }
    return 0;
}

/* copy a NUL-terminated string from the file map, bounded */
static void safe_copy_str(const uint8_t *map, size_t mapsz, size_t off,
                          char *out, size_t outsz)
{
    size_t i = 0;
    if (outsz == 0) return;
    if (off >= mapsz) { out[0] = '\0'; return; }
    while (i + 1 < outsz && off + i < mapsz && map[off + i] != 0) {
        out[i] = (char)map[off + i];
        i++;
    }
    out[i] = '\0';
}

static int strlist_add(hstrlist_t *l, const char *s)
{
    int i;
    if (l->n >= HUSK_MAX_NEEDED || !s || !s[0]) return 0;
    for (i = 0; i < l->n; i++)
        if (strcmp(l->name[i], s) == 0) return 1;
    snprintf(l->name[l->n], sizeof(l->name[0]), "%s", s);
    l->n++;
    return 1;
}

static void parse_dynamic(hreport_t *r, const uint8_t *map, size_t mapsz,
                          const hseg_t *seg)
{
    size_t esz = (r->cls == 64) ? 16 : 8;
    size_t i, count;
    uint64_t strtab_vaddr = 0;
    size_t strtab_off = 0;
    int have_strtab = 0;
    int be = (r->endian == 2);

    if (seg->offset >= mapsz || seg->filesz == 0) return;
    if (!in_range(seg->offset, seg->filesz, mapsz)) {
        /* truncated dynamic segment: parse what is there */
        count = (mapsz - seg->offset) / esz;
    } else {
        count = seg->filesz / esz;
    }
    if (count > 8192) count = 8192;

    /* first pass: find DT_STRTAB */
    for (i = 0; i < count; i++) {
        const uint8_t *e = map + seg->offset + i * esz;
        uint64_t tag = (r->cls == 64) ? rd64(e, be) : rd32(e, be);
        if (tag == DT_NULL) break;
        if (tag == DT_STRTAB) {
            strtab_vaddr = (r->cls == 64) ? rd64(e + 8, be) : rd32(e + 8, be);
            have_strtab = 1;
            break;
        }
    }
    if (have_strtab) have_strtab = vaddr_to_off(r, strtab_vaddr, &strtab_off);

    /* second pass: entries */
    for (i = 0; i < count; i++) {
        const uint8_t *e = map + seg->offset + i * esz;
        uint64_t tag, val;
        if (r->cls == 64) { tag = rd64(e, be); val = rd64(e + 8, be); }
        else              { tag = rd32(e, be); val = rd32(e + 8, be); }
        if (tag == DT_NULL) break;

        if (tag == DT_NEEDED && have_strtab) {
            char name[96];
            if (val < mapsz && in_range(strtab_off, (size_t)1, mapsz))
                safe_copy_str(map, mapsz, strtab_off + (size_t)val,
                              name, sizeof(name));
            else
                name[0] = '\0';
            strlist_add(&r->needed, name);
        } else if (tag == DT_RPATH && have_strtab && r->rpath[0] == '\0') {
            if (val < mapsz)
                safe_copy_str(map, mapsz, strtab_off + (size_t)val,
                              r->rpath, sizeof(r->rpath));
        } else if (tag == DT_RUNPATH && have_strtab && r->runpath[0] == '\0') {
            if (val < mapsz)
                safe_copy_str(map, mapsz, strtab_off + (size_t)val,
                              r->runpath, sizeof(r->runpath));
        } else if (tag == DT_FLAGS) {
            if (val & DF_BIND_NOW) r->bind_now = 1;
        } else if (tag == DT_FLAGS_1) {
            if (val & DF_1_NOW) r->bind_now = 1;
        }
    }
    r->has_dyn = 1;
}

static void parse_program_headers(hreport_t *r, const uint8_t *map,
                                  size_t mapsz, uint64_t phoff,
                                  uint32_t phnum, uint32_t phentsize)
{
    int be = (r->endian == 2);
    uint32_t i;
    size_t esz = (r->cls == 64) ? 56 : 32;
    if (phoff == 0 || phnum == 0) return;
    if (phentsize != esz) return;               /* malformed: skip phdrs */
    if (phoff >= mapsz) return;

    for (i = 0; i < phnum && r->n_segs < HUSK_MAX_SEGS; i++) {
        size_t base = (size_t)phoff + (size_t)i * esz;
        hseg_t *s;
        if (!in_range(base, esz, mapsz)) break;
        s = &r->segs[r->n_segs];
        memset(s, 0, sizeof(*s));
        if (r->cls == 64) {
            s->type   = rd32(map + base, be);
            s->flags  = rd32(map + base + 4, be);
            s->offset = rd64(map + base + 8, be);
            s->vaddr  = rd64(map + base + 16, be);
            s->filesz = rd64(map + base + 32, be);
            s->memsz  = rd64(map + base + 40, be);
        } else {
            s->type   = rd32(map + base, be);
            s->offset = rd32(map + base + 4, be);
            s->vaddr  = rd32(map + base + 8, be);
            s->filesz = rd32(map + base + 16, be);
            s->memsz  = rd32(map + base + 20, be);
            s->flags  = rd32(map + base + 24, be);
        }
        if (s->type == PT_INTERP) {
            size_t off = (size_t)s->offset;
            size_t len = (size_t)s->filesz;
            if (off < mapsz && in_range(off, len, mapsz) && len > 1) {
                size_t lim = len - 1;
                if (lim >= sizeof(r->interp)) lim = sizeof(r->interp) - 1;
                memcpy(r->interp, map + off, lim);
                r->interp[lim] = '\0';
                r->has_interp = 1;
            }
        } else if (s->type == PT_DYNAMIC) {
            /* parse after all phdrs are known (strtab vaddr resolution) */
        }
        r->n_segs++;
    }

    /* dynamic segment needs the full load map, so parse it last */
    for (i = 0; i < (uint32_t)r->n_segs; i++) {
        if (r->segs[i].type == PT_DYNAMIC)
            parse_dynamic(r, map, mapsz, &r->segs[i]);
    }
}

static void resolve_secname(hreport_t *r, const uint8_t *map, size_t mapsz,
                            size_t strtab_off, size_t strtab_size,
                            uint32_t name_off, char *out, size_t outsz)
{
    if (r->n_secs == 0) { out[0] = '\0'; return; }
    if (strtab_size == 0 || name_off >= strtab_size) { out[0] = '\0'; return; }
    safe_copy_str(map, mapsz, strtab_off + name_off, out, outsz);
}

static void parse_section_headers(hreport_t *r, const uint8_t *map,
                                  size_t mapsz, uint64_t shoff,
                                  uint32_t shnum0, uint32_t shentsize,
                                  uint32_t shstrndx_in)
{
    int be = (r->endian == 2);
    size_t esz = (r->cls == 64) ? 64 : 40;
    uint32_t shnum = shnum0, shstrndx = shstrndx_in;
    uint32_t i;
    size_t str_off = 0, str_size = 0;
    int have_str = 0;

    if (shoff == 0) return;
    if (shoff >= mapsz) return;

    if (shentsize != esz) return;

    /* extended numbering: real counts live in section 0 */
    if (shnum == 0 || shstrndx == 0xffffu) {
        uint64_t s0_size = 0, s0_link = 0;
        if (!in_range((size_t)shoff, esz, mapsz)) return;
        if (r->cls == 64) {
            s0_size = rd64(map + shoff + 32, be);
            s0_link = rd32(map + shoff + 40, be);
        } else {
            s0_size = rd32(map + shoff + 20, be);
            s0_link = rd32(map + shoff + 24, be);
        }
        if (shnum == 0) {
            if (s0_size > 65535) return;
            shnum = (uint32_t)s0_size;
        }
        if (shstrndx == 0xffffu) shstrndx = (uint32_t)s0_link;
    }
    if (shnum == 0) return;

    for (i = 0; i < shnum && r->n_secs < HUSK_MAX_SECS; i++) {
        size_t base = (size_t)shoff + (size_t)i * esz;
        hsec_t *s;
        if (!in_range(base, esz, mapsz)) break;
        s = &r->secs[r->n_secs];
        memset(s, 0, sizeof(*s));
        s->name_off = rd32(map + base, be);
        s->type     = rd32(map + base + 4, be);
        if (r->cls == 64) {
            s->flags   = rd64(map + base + 8, be);
            s->addr    = rd64(map + base + 16, be);
            s->offset  = rd64(map + base + 24, be);
            s->size    = rd64(map + base + 32, be);
        } else {
            s->flags   = rd32(map + base + 8, be);
            s->addr    = rd32(map + base + 12, be);
            s->offset  = rd32(map + base + 16, be);
            s->size    = rd32(map + base + 20, be);
        }
        if (in_range((size_t)s->offset, (size_t)s->size, mapsz) &&
            s->type != SHT_NOBITS && s->size > 0)
            s->data_ok = 1;
        r->n_secs++;
    }
    r->has_sht = 1;

    if (shstrndx >= (uint32_t)r->n_secs) return;
    {
        const hsec_t *st = &r->secs[shstrndx];
        if (st->offset < mapsz && st->size > 0 &&
            in_range((size_t)st->offset, (size_t)st->size, mapsz)) {
            str_off = (size_t)st->offset;
            str_size = (size_t)st->size;
            have_str = 1;
        }
    }
    if (!have_str) return;
    for (i = 0; i < (uint32_t)r->n_secs; i++)
        resolve_secname(r, map, mapsz, str_off, str_size,
                        r->secs[i].name_off, r->secs[i].name,
                        sizeof(r->secs[i].name));
}

static void parse_dynsym(hreport_t *r, const uint8_t *map, size_t mapsz)
{
    int be = (r->endian == 2);
    int si, i;
    size_t esz = (r->cls == 64) ? 24 : 16;

    if (!r->has_sht) return;
    for (si = 0; si < r->n_secs; si++) {
        if (r->secs[si].type == SHT_DYNSYM) break;
    }
    if (si >= r->n_secs) return;
    {
        const hsec_t *sym = &r->secs[si];
        size_t base, count, j;
        size_t stroff = 0, strsize = 0;
        if (!sym->data_ok || sym->size < esz) return;

        /* dynstr: the string section named ".dynstr" */
        for (i = 0; i < r->n_secs; i++) {
            if (strcmp(r->secs[i].name, ".dynstr") == 0 && r->secs[i].data_ok) {
                stroff = (size_t)r->secs[i].offset;
                strsize = (size_t)r->secs[i].size;
                break;
            }
        }
        if (strsize == 0) return;

        base = (size_t)sym->offset;
        count = (size_t)sym->size / esz;
        if (count > 65536) count = 65536;
        for (j = 0; j < count; j++) {
            size_t e = base + j * esz;
            uint32_t st_name;
            uint16_t st_shndx;
            uint8_t st_info;
            char nm[96];
            if (!in_range(e, esz, mapsz)) break;
            if (r->cls == 64) {
                st_name  = rd32(map + e, be);
                st_info  = map[e + 4];
                st_shndx = rd16(map + e + 6, be);
            } else {
                st_name  = rd32(map + e, be);
                st_info  = map[e + 12];
                st_shndx = rd16(map + e + 14, be);
            }
            if (st_name == 0 || st_shndx != 0) continue;
            if ((st_info >> 4) == 0) continue;       /* local bind: skip */
            if (st_name >= strsize) continue;
            safe_copy_str(map, mapsz, stroff + st_name, nm, sizeof(nm));
            if (!nm[0]) continue;
            if (r->imports.n >= HUSK_MAX_IMPORTS) {
                r->imports_trunc = 1;
                break;
            }
            snprintf(r->imports.name[r->imports.n],
                     sizeof(r->imports.name[0]), "%s", nm);
            r->imports.n++;
        }
    }
}

int husk_load(const char *path, hreport_t *r, uint8_t **map_out)
{
    FILE *fp;
    long fsz;
    uint8_t *map;
    const uint8_t *p;
    int be;
    size_t mapsz, sample;
    int i;

    memset(r, 0, sizeof(*r));
    if (map_out) *map_out = NULL;
    snprintf(r->path, sizeof(r->path), "%s", path);
    r->verdict = HV_NOTELF;

    fp = fopen(path, "rb");
    if (!fp) {
        snprintf(r->err, sizeof(r->err), "cannot open");
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0 || (fsz = ftell(fp)) < 0) {
        snprintf(r->err, sizeof(r->err), "cannot size");
        fclose(fp);
        return -1;
    }
    if ((uint64_t)fsz > HUSK_FILE_MAX) {
        snprintf(r->err, sizeof(r->err), "file exceeds cap (%ld bytes)", fsz);
        fclose(fp);
        return -1;
    }
    mapsz = (size_t)fsz;
    r->size = mapsz;
    map = (uint8_t *)malloc(mapsz ? mapsz : 1);
    if (!map) {
        snprintf(r->err, sizeof(r->err), "out of memory");
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0 ||
        fread(map, 1, mapsz, fp) != mapsz) {
        snprintf(r->err, sizeof(r->err), "read failed");
        free(map);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (mapsz < 16 || map[0] != 0x7f || map[1] != 'E' ||
        map[2] != 'L' || map[3] != 'F') {
        snprintf(r->err, sizeof(r->err), "not an elf object");
        free(map);
        return -1;
    }
    r->cls = (map[4] == 1) ? 32 : (map[4] == 2) ? 64 : 0;
    r->endian = (map[5] == 1) ? 1 : (map[5] == 2) ? 2 : 0;
    if (r->cls == 0 || r->endian == 0) {
        snprintf(r->err, sizeof(r->err), "elf ident malformed");
        free(map);
        return -1;
    }
    be = (r->endian == 2);
    p = map;

    if (r->cls == 64) {
        if (mapsz < 64) {
            snprintf(r->err, sizeof(r->err), "truncated elf64 header");
            free(map);
            return -1;
        }
        r->e_type      = rd16(p + 0x10, be);
        r->e_machine   = rd16(p + 0x12, be);
        r->e_entry     = rd64(p + 0x18, be);
        {
            uint64_t phoff = rd64(p + 0x20, be);
            uint64_t shoff = rd64(p + 0x28, be);
            uint32_t phnum = rd16(p + 0x38, be);
            uint32_t shnum = rd16(p + 0x3c, be);
            uint32_t phentsize = rd16(p + 0x36, be);
            uint32_t shentsize = rd16(p + 0x3a, be);
            uint32_t shstrndx = rd16(p + 0x3e, be);
            parse_program_headers(r, map, mapsz, phoff, phnum, phentsize);
            parse_section_headers(r, map, mapsz, shoff, shnum, shentsize,
                                  shstrndx);
            if (shnum != 0 && shstrndx >= (uint32_t)r->n_secs && r->has_sht)
                r->nx_shstrndx = 1;
        }
    } else {
        if (mapsz < 52) {
            snprintf(r->err, sizeof(r->err), "truncated elf32 header");
            free(map);
            return -1;
        }
        r->e_type      = rd16(p + 0x10, be);
        r->e_machine   = rd16(p + 0x12, be);
        r->e_entry     = rd32(p + 0x18, be);
        {
            uint32_t phoff = rd32(p + 0x1c, be);
            uint32_t shoff = rd32(p + 0x20, be);
            uint32_t phnum = rd16(p + 0x2c, be);
            uint32_t shnum = rd16(p + 0x30, be);
            uint32_t phentsize = rd16(p + 0x2a, be);
            uint32_t shentsize = rd16(p + 0x2e, be);
            uint32_t shstrndx = rd16(p + 0x32, be);
            parse_program_headers(r, map, mapsz, phoff, phnum, phentsize);
            parse_section_headers(r, map, mapsz, shoff, shnum, shentsize,
                                  shstrndx);
            if (shnum != 0 && shstrndx >= (uint32_t)r->n_secs && r->has_sht)
                r->nx_shstrndx = 1;
        }
    }

    parse_dynsym(r, map, mapsz);

    /* hardening side-notes */
    r->pie = (r->e_type == 3);
    for (i = 0; i < r->n_segs; i++) {
        if (r->segs[i].type == PT_GNU_STACK) {
            r->gnu_stack = 1;
            r->nx = (r->segs[i].flags & 0x1) ? 0 : 1;   /* X flag off = nx */
        } else if (r->segs[i].type == PT_GNU_RELRO) {
            r->relro = 1;
        }
    }
    for (i = 0; i < r->imports.n; i++) {
        if (strncmp(r->imports.name[i], "__stack_chk", 11) == 0) {
            r->canary = 1;
            break;
        }
    }

    /* entropy */
    sample = mapsz < (4u << 20) ? mapsz : (4u << 20);
    r->ent_overall = husk_entropy(map, sample);
    {
        double best = 0.0;
        const char *bestname = "";
        double text_ent = -1.0;
        for (i = 0; i < r->n_secs; i++) {
            const hsec_t *s = &r->secs[i];
            if (!s->data_ok || s->size < 256) continue;
            if (strcmp(s->name, ".text") == 0) {
                size_t lim = s->size < (2u << 20) ? (size_t)s->size : (2u << 20);
                text_ent = husk_entropy(map + s->offset, lim);
            }
            {
                size_t lim = s->size < (2u << 20) ? (size_t)s->size : (2u << 20);
                double e = husk_entropy(map + s->offset, lim);
                if (e > best) { best = e; bestname = s->name; }
            }
        }
        r->ent_max = best;
        snprintf(r->ent_max_name, sizeof(r->ent_max_name), "%s", bestname);
        r->ent_text = text_ent;
    }

    r->verdict = HV_CLEAN;   /* neutral until rules decide */
    if (map_out) *map_out = map;
    else free(map);
    return 0;
}
