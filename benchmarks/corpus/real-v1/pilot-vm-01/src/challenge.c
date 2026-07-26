#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
int main(void) { unsigned char x[4]; if (fread(x,1,4,stdin)!=4) return 1; unsigned char code[]={3,1,4,1,5,9}; for(int i=0;i<6;i++) x[i&3]=(unsigned char)((x[i&3]^code[i])+i); if (((uint32_t)x[0]|((uint32_t)x[1]<<8)|((uint32_t)x[2]<<16)|((uint32_t)x[3]<<24)) != 0x51424344U) { puts("invalid"); return 1; } puts("vm-confirmed"); return system("/bin/cat flag"); }
