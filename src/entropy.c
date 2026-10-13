/* entropy.c — shannon entropy over bounded byte ranges */
#include "husk.h"
#include <math.h>
#include <string.h>

double husk_entropy(const uint8_t *p, size_t n)
{
    uint32_t counts[256];
    double ent = 0.0;
    size_t i;
    if (!p || n == 0) return 0.0;
    memset(counts, 0, sizeof(counts));
    for (i = 0; i < n; i++) counts[p[i]]++;
    for (i = 0; i < 256; i++) {
        double f;
        if (counts[i] == 0) continue;
        f = (double)counts[i] / (double)n;
        ent += f * log(f);
    }
    return -ent / log(2.0);
}
