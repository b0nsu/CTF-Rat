#include <stddef.h>
#include <string.h>

__attribute__((noinline)) int check(const unsigned char *a, const unsigned char *b) {
    volatile int first = memcmp(a, b, 4);
    volatile int second = memcmp(a + 4, b + 4, 4);
    return first | second;
}

__attribute__((noinline)) int branch_lengths(const unsigned char *a, const unsigned char *b, int branch) {
    if (branch)
        return memcmp(a, b, 3);
    return memcmp(a, b, 7);
}

__attribute__((noinline)) int input_length(const unsigned char *a, const unsigned char *b, size_t n) {
    return memcmp(a, b, n);
}

__attribute__((noinline)) int no_length_argument(const char *a, const char *b) {
    return strcmp(a, b);
}

int main(int argc, char **argv) {
    const unsigned char *a = (const unsigned char *)(argc > 1 ? argv[1] : "abcdefgh");
    return check(a, (const unsigned char *)"abcdefgh") |
           branch_lengths(a, (const unsigned char *)"abcdefgh", argc & 1) |
           input_length(a, (const unsigned char *)"abcdefgh", (size_t)argc) |
           no_length_argument((const char *)a, "abcdefgh");
}
