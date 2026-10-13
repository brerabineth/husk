/* benign.c — honest binary. ships with husk fixtures so analysts can
 * see what a clean verdict looks like.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char pad[48];
    char *p = (char *)malloc(64);
    if (!p) return 1;
    memset(pad, 0, sizeof(pad));
    pad[0] = 'x';
    strcpy(p, "manifest checked. crate sealed.");
    printf("%d %s %s\n", (int)strlen(p), p, pad);
    free(p);
    return 0;
}
