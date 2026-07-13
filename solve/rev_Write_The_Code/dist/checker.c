#include <stdio.h>
#include <string.h>

/* Our build system links this from the internal audit library. */
extern int audit(const char *answer);

int main(void)
{
    char answer[128];
    puts("Build provenance check");
    fputs("receipt: ", stdout);
    if (!fgets(answer, sizeof answer, stdin))
        return 1;
    answer[strcspn(answer, "\n")] = 0;
    puts(audit(answer) ? "accepted" : "rejected");
    return 0;
}
