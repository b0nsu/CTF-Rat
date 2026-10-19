/* heap-house-02 — synthetic heap fixture, harder tier (repo-authored, license-free).
 * Two-chunk allocate/free dance (calloc + malloc + free) modelling a house-of-*
 * setup; deterministic oracle keyed on the second allocation's contents.
 * difficulty 3. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win(void) {
    puts("FLAG{synthetic-heap-house}");
    fflush(stdout);
    exit(0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char *a = calloc(1, 48);
    char *b = malloc(48);
    char line[80];
    if (!fgets(line, sizeof line, stdin)) return 0;
    memcpy(b, line, 47);
    b[47] = 0;
    int ok = !strncmp(b, "house-of-force", 14);
    free(a);
    free(b);
    if (ok) win();
    puts("nope");
    return 0;
}
