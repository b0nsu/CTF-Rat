#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char buf[32];

int main(int argc, char *argv[]) {
    if (argc < 2) {
        puts("pass argv[1] a number");
        return 0;
    }
    int fd = atoi(argv[1]) - 0x1234;
    if (read(fd, buf, sizeof(buf)) < 0) {
        perror("read");
        return 1;
    }
    if (!strcmp("LETMEWIN\n", buf)) {
        puts("good job :)");
        return system("/bin/cat flag") == 0 ? 0 : 1;
    }
    puts("learn about Linux file IO");
    return 0;
}
