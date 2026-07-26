#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
	char* args[] = {"/usr/bin/setarch", "linux32", "-R", "/home/note_pwn/note", 0};
	execve(args[0], args, 0);
	printf("execve failed!. tell admin\n");
	return 0;
}

