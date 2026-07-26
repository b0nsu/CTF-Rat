#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static uint64_t mix(uint64_t value) {
    value ^= 0x6a09e667f3bcc909ULL;
    value = (value << 17) | (value >> 47);
    return value + 0x9e3779b97f4a7c15ULL;
}

int main(void) {
    char input[40];
    puts("Enter 64-bit access code in hexadecimal:");
    if (!fgets(input, sizeof(input), stdin)) return 1;
    uint64_t value = strtoull(input, NULL, 16);
    if (mix(value) != 0x98a0d998f7b85a51ULL) {
        puts("access denied");
        return 1;
    }
    puts("validation-path-confirmed");
    return system("/bin/cat flag") == 0 ? 0 : 1;
}
