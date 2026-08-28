/* checker-basic-01 — synthetic rev checker fixture (repo-authored, license-free).
 * Direct memcmp of stdin against a fixed literal; prints the flag on match. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char buf[32] = {0};
    if (read(0, buf, 11) < 0) return 1;
    if (memcmp(buf, "s3cr3t_p4ss", 11) == 0)   /* compare-call -> rev-checker */
        puts("FLAG{synthetic-checker-ok}");
    else
        puts("Wrong");
    return 0;
}
