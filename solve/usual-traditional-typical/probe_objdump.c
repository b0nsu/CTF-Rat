#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uintptr_t base_addr;

static int find_base(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    if (info->dlpi_name && strstr(info->dlpi_name, "target_obf")) {
        base_addr = info->dlpi_addr;
        return 1;
    }
    if ((!info->dlpi_name || !info->dlpi_name[0]) && !base_addr) {
        base_addr = info->dlpi_addr;
    }
    return 0;
}

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
        if (!base_addr) {
            dl_iterate_phdr(find_base, NULL);
        }
        uint8_t *caller_rbp = __builtin_frame_address(1);
        uint8_t *obj = caller_rbp - 0x90;
        uint64_t mask80 = *(uint64_t *)(obj + 0x80);
        uint64_t hash = 0;
        uint64_t (*hfn)(void *) = NULL;
        if (base_addr) {
            hfn = (uint64_t(*)(void *))(base_addr + 0x110ce0);
            hash = hfn(obj);
        }
        const char *log_path = getenv("PROBE_LOG");
        if (log_path) {
            FILE *f = fopen(log_path, "a");
            if (f) {
                fprintf(f, "%s base=%#lx mask80=%#lx hash=%#lx xor=%#lx\n",
                        s, (unsigned long)base_addr, (unsigned long)mask80,
                        (unsigned long)hash,
                        (unsigned long)(hash ^ 0x68d1b78a3109d714ULL));
                fclose(f);
            }
        }
        const char *dump_path = getenv("PROBE_DUMP");
        if (dump_path) {
            FILE *f = fopen(dump_path, "wb");
            if (f) {
                fwrite(obj, 1, 0x90, f);
                fclose(f);
            }
        }
        const char *infl_path = getenv("PROBE_INFLUENCE");
        if (infl_path && hfn) {
            FILE *f = fopen(infl_path, "w");
            if (f) {
                for (size_t i = 0; i < 0x88; i++) {
                    uint8_t old = obj[i];
                    obj[i] = old ^ 1;
                    uint64_t h2 = hfn(obj);
                    obj[i] = old;
                    if (h2 != hash) {
                        fprintf(f, "%#zx %#lx\n", i, (unsigned long)(h2 ^ hash));
                    }
                }
                fclose(f);
            }
        }
    }
    return real_puts(s);
}
