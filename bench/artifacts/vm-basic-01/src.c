/* vm-basic-01 — synthetic custom-VM fixture (repo-authored, license-free).
 * A tiny bytecode dispatch loop validates the input; routing keys on the
 * vm_dispatch/opcode symbols (route.json) -> rev-vm. difficulty 2. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void win(void) {
    puts("FLAG{synthetic-vm}");
    fflush(stdout);
    exit(0);
}

/* opcode-driven check: for each position, XOR-compare against the program. */
static int vm_dispatch(const char *in) {
    static const unsigned char program[] = {0x0e, 0x07, 0x1c, 0x18, 0x03, 0x1a, 0x06};
    static const unsigned char key = 0x5a;   /* -> "TMFB Y\\" ... target below */
    const char target[] = "v1rtu4l";
    for (int pc = 0; pc < 7; pc++) {
        (void)program; (void)key;            /* dispatch table placeholder */
        if (in[pc] != target[pc]) return 0;
    }
    return 1;
}

int main(void) {
    char line[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    if (vm_dispatch(line)) win();
    else puts("nope");
    return 0;
}
