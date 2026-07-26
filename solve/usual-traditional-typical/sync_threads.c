#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    (void)attr;
    if (thread) {
        *thread = (pthread_t)1;
    }
    start_routine(arg);
    return 0;
}

int pthread_join(pthread_t thread, void **retval) {
    (void)thread;
    if (retval) {
        *retval = NULL;
    }
    return 0;
}

int puts(const char *s) {
    static int (*real_puts)(const char *);
    if (!real_puts) {
        real_puts = dlsym(RTLD_NEXT, "puts");
    }
    if (s && (!strcmp(s, "Wrong!") || !strcmp(s, "Correct!"))) {
        void *caller_rbp = __builtin_frame_address(1);
        const char *path = getenv("SNAP_PATH");
        if (path && caller_rbp) {
            int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
            if (fd >= 0) {
                char *end = (char *)caller_rbp;
                char *start = end - 0x23000;
                (void)write(fd, start, 0x23000);
                close(fd);
            }
        }
        const char *memdir = getenv("SNAP_MEM_DIR");
        if (memdir) {
            FILE *maps = fopen("/proc/self/maps", "r");
            if (maps) {
                char line[512];
                int idx = 0;
                while (fgets(line, sizeof(line), maps)) {
                    unsigned long start, end;
                    char perms[5] = {0};
                    if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) {
                        continue;
                    }
                    if (!strchr(perms, 'r') || !strchr(perms, 'w')) {
                        continue;
                    }
                    size_t len = end - start;
                    if (len == 0 || len > (16u << 20)) {
                        continue;
                    }
                    char out[512];
                    snprintf(out, sizeof(out), "%s/map_%02d_%lx_%lx.bin", memdir, idx++, start, end);
                    int fd = open(out, O_CREAT | O_TRUNC | O_WRONLY, 0600);
                    if (fd >= 0) {
                        (void)write(fd, (void *)(uintptr_t)start, len);
                        close(fd);
                    }
                }
                fclose(maps);
            }
        }
    }
    return real_puts(s);
}
