#include <unistd.h>

int main(void) {
    char buffer[64];
    return (int)read(0, buffer, 512);
}
