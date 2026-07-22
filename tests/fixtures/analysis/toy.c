#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(void) {
    char b[64] = {0};
    if (!fgets(b, sizeof b, stdin)) return 2;
    if (!strcmp(b, "SLEEP\n")) { sleep(2); return 0; }
    if (!strcmp(b, "OK\n")) { puts("SUCCESS"); return 0; }
    puts("NO"); return 1;
}
