/* rop-nx-01 — synthetic overflow-with-NX fixture (repo-authored, license-free).
 * Same unbounded gets() sink as stack-basic-01, but built NX so shellcode-on-stack
 * is blocked -> route must escalate to pwn-rop (not pwn-stack). difficulty 2. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win(void) {
    puts("FLAG{synthetic-rop-nx}");
    fflush(stdout);
    exit(0);
}

int main(void) {
    char buf[40];
    setvbuf(stdout, NULL, _IONBF, 0);
    gets(buf);                       /* unbounded sink */
    if (!strcmp(buf, "chain-me")) win();
    puts("nope");
    return 0;
}
