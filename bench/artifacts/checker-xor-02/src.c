/* checker-xor-02 — synthetic keygen/checker fixture, XOR tier (repo-authored,
 * license-free). Reads a fixed-length input, XOR-decodes and compares to an
 * embedded constant, then prints Correct/Wrong. angr (symsolve --find-str)
 * recovers the input; the bench verifies the recovered secret. difficulty 2. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    unsigned char in[6];
    if (read(0, in, 6) != 6) { puts("Wrong"); return 1; }
    /* enc[i] == password[i] ^ 0x5a ; password == "x0rz42" */
    static const unsigned char enc[6] = {0x22, 0x6a, 0x28, 0x20, 0x6e, 0x68};
    int ok = 1;
    for (int i = 0; i < 6; i++)
        if ((unsigned char)(in[i] ^ 0x5a) != enc[i]) ok = 0;
    if (ok) puts("Correct: FLAG{synthetic-xor-checker}");
    else puts("Wrong");
    return 0;
}
