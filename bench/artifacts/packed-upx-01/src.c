/* packed-upx-01 — synthetic packed-binary fixture (repo-authored, license-free).
 * The route fixture (route.json) carries the UPX packer-section evasion signal so
 * routing must land on rev-packed; this source is the *unpacked* payload the
 * verifier compiles and runs (a plain input->flag check), so Mode A stays
 * deterministic without shipping a real UPX-compressed binary. difficulty 2. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void win(void) {
    puts("FLAG{synthetic-packed}");
    fflush(stdout);
    exit(0);
}

int main(void) {
    char line[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    if (!strcmp(line, "unpack-me")) win();
    puts("nope");
    return 0;
}
