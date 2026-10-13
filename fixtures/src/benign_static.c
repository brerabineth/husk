/* benign_static.c — same as benign, linked static.
 * tests that a static binary with no loader surface stays clean.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char p[64];
    char pad[48];
    strcpy(p, "manifest checked. crate sealed.");
    memset(pad, 0, sizeof(pad));
    pad[0] = 'x';
    printf("%d %s %s\n", (int)strlen(p), p, pad);
    return 0;
}
