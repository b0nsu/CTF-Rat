make lib:
	gcc -fPIC -c chal.c
	gcc -shared -Wl,-soname,libchal.so.1 -o libchal.so chal.o
	strip --strip-all libchal.so