#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
static uint64_t mix(uint64_t x) { x ^= 0x9e3779b97f4a7c1aULL; return ((x<<13)|(x>>51))+0x6a09e667f3bcc90eULL; }
int main(void) { char b[48]; if(!fgets(b,sizeof(b),stdin)) return 1; if(mix(strtoull(b,0,16)) != 0xbad0c0ffee123456ULL) { puts("invalid"); return 1; } puts("validation-confirmed"); return system("/bin/cat flag"); }
