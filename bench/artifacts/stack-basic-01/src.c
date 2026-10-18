/* stack-basic-01 — synthetic overflow fixture (repo-authored, license-free).
 * Unbounded gets() into a small stack buffer; a win() prints the flag. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win(void) {
    puts("FLAG{synthetic-stack-overflow}");
    fflush(stdout);
    exit(0);
}

int main(void) {
    char buf[32];
    setvbuf(stdout, NULL, _IONBF, 0);
    gets(buf);          /* unbounded sink -> pwn-stack */
    if (!strcmp(buf, "open-sesame")) win();
    puts("nope");
    return 0;
}
