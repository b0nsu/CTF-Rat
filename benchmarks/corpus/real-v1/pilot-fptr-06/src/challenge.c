#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct state { char buffer[96]; void (*callback)(void); };
static void normal(void) { puts("normal path"); }
static void win(void) { puts("control-flow-confirmed"); system("/bin/cat flag"); }
int main(void) { struct state s = {.callback=normal}; read(0, s.buffer, sizeof(s)); s.callback(); return 0; }
