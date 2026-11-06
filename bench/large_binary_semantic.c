/* Small, repository-authored fixture for revq string/xref/oracle comparisons. */
#include <stdio.h>
#include <string.h>

static int check(const char *input) {
    return strcmp(input, "open-sesame") == 0;
}

int main(void) {
    char input[64];
    if (!fgets(input, sizeof input, stdin)) return 1;
    input[strcspn(input, "\n")] = 0;
    if (check(input)) puts("Correct");
    else puts("Wrong");
    return 0;
}
