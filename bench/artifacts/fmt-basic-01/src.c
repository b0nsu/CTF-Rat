/* fmt-basic-01 — synthetic format-string fixture (repo-authored, license-free).
 * Reads input then passes it straight to printf as the format argument. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if (n <= 0) return 1;
    buf[n] = 0;
    printf(buf);        /* format-string sink + read input -> pwn-format */
    return 0;
}
