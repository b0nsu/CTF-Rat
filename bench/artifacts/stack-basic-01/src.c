/* stack-basic-01 — synthetic overflow fixture (repo-authored, license-free).
 * Oversized fgets() into a small stack buffer; a win() prints the flag. */
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
    if (!fgets(buf, 256, stdin)) return 1;  /* oversized sink -> pwn-stack */
    buf[strcspn(buf, "\n")] = '\0';
    if (!strcmp(buf, "open-sesame")) win();
    puts("nope");
    return 0;
}
