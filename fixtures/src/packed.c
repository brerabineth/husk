/* packed.c — entropy fixture, shared object.
 * carries a large deterministic random blob and an upx-shaped magic
 * so husk's packing heuristics have something to bite. harmless.
 */
#include <stddef.h>

#include "packed_blob.h"

/* upx magic lookalike stored as data (not a real packed image) */
const char husk_pack_magic[8] = { 'U', 'P', 'X', '!', 0x00, 0x01, 0x02, 0x03 };

int husk_blob_sum(void)
{
    int s = 0;
    size_t i;
    for (i = 0; i < PACKED_BLOB_LEN; i++)
        s += husk_blob_data[i];
    return s;
}
