#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
static uint64_t mix(uint64_t x) { x ^= 0x9e3779b97f4a7c19ULL; return ((x<<13)|(x>>51))+0x6a09e667f3bcc90dULL; }
int main(void) { char b[48]; if(!fgets(b,sizeof(b),stdin)) return 1; if(mix(strtoull(b,0,16)) != 0x2134abcd9012ef77ULL) { puts("invalid"); return 1; } puts("validation-confirmed"); return system("/bin/cat flag"); }
