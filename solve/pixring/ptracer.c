#define _GNU_SOURCE
#include <sys/prctl.h>

__attribute__((constructor)) static void allow_debugger(void) {
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
}
