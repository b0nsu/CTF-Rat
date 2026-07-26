#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    (void)attr;
    const char *path = getenv("THREAD_LOG");
    if (path) {
        FILE *log = fopen(path, "a");
        if (log) {
            uintptr_t vtable = arg ? *(uintptr_t *)arg : 0;
            uintptr_t slot0 = vtable ? *(uintptr_t *)vtable : 0;
            uintptr_t slot1 = vtable ? *((uintptr_t *)vtable + 1) : 0;
            uintptr_t slot2 = vtable ? *((uintptr_t *)vtable + 2) : 0;
            Dl_info info = {0};
            dladdr((void *)slot2, &info);
            fprintf(log, "start=%p arg=%p vtable=%#lx slots=%#lx,%#lx,%#lx base=%p off=%#lx\n",
                    (void *)start_routine, arg, (unsigned long)vtable,
                    (unsigned long)slot0, (unsigned long)slot1, (unsigned long)slot2,
                    info.dli_fbase, (unsigned long)(slot2 - (uintptr_t)info.dli_fbase));
            fclose(log);
        }
    }
    if (thread) *thread = (pthread_t)1;
    start_routine(arg);
    return 0;
}

int pthread_join(pthread_t thread, void **retval) {
    (void)thread;
    if (retval) *retval = NULL;
    return 0;
}
