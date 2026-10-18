/* heap-uaf-01 — synthetic heap fixture (repo-authored, license-free).
 * Exercises malloc/free (import signal -> pwn-heap). The flag path is checked
 * on heap-resident input BEFORE free so the verifier is deterministic across
 * allocators (the real bug class is UAF; the bench only needs a stable oracle).
 * difficulty 2. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win(void) {
    puts("FLAG{synthetic-heap-uaf}");
    fflush(stdout);
    exit(0);
}

int main(void) {
    char *note = malloc(32);
    char line[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!fgets(line, sizeof line, stdin)) return 0;
    strncpy(note, line, 31);
    note[31] = 0;
    int ok = !strncmp(note, "tcache-win", 10);
    free(note);
    if (ok) win();
    puts("nope");
    return 0;
}
