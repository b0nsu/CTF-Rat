#define _GNU_SOURCE
#include <link.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

static uintptr_t base_addr;
static int cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size; (void)data;
    if (info->dlpi_name && strstr(info->dlpi_name, "target_obf")) {
        base_addr = info->dlpi_addr;
        return 1;
    }
    if ((!info->dlpi_name || !info->dlpi_name[0]) && !base_addr) base_addr = info->dlpi_addr;
    return 0;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
    (void)attr; if (thread) *thread=(pthread_t)1; start_routine(arg); return 0;
}
int pthread_join(pthread_t thread, void **retval) { (void)thread; if (retval) *retval=NULL; return 0; }

int puts(const char *s) {
    static int (*real_puts)(const char *);
    if (!real_puts) real_puts = dlsym(RTLD_NEXT, "puts");
    if (s && (!strcmp(s,"Wrong!") || !strcmp(s,"Correct!"))) {
        if (!base_addr) dl_iterate_phdr(cb, NULL);
        uint8_t *rbp = __builtin_frame_address(1);
        uint8_t *obj = rbp - 0x90;
        uint64_t mask80 = *(uint64_t *)(obj + 0x80);
        uint64_t hash = 0;
        if (base_addr) {
            uint64_t (*hfn)(void*) = (uint64_t(*)(void*))(base_addr + 0x110ce0);
            hash = hfn(obj);
        }
        const char *path=getenv("PROBE_PATH");
        if (path) {
            FILE *f=fopen(path,"w");
            if (f) { fprintf(f,"%s base=%#lx mask80=%#lx hash=%#lx xor=%#lx\n", s,(unsigned long)base_addr,(unsigned long)mask80,(unsigned long)hash,(unsigned long)(hash^0x68d1b78a3109d714ULL)); fclose(f); }
        }
    }
    return real_puts(s);
}
