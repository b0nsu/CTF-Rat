#include <stdio.h>
#include <stdlib.h>

static void win(void) {
    puts("control-flow-confirmed");
    system("/bin/cat flag");
}

int main(void) {
    char buffer[48];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Jersey training service: send one line");
    gets(buffer);
    puts("normal exit");
    return 0;
}
