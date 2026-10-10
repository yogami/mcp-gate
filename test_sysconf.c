#include <stdio.h>
#include <unistd.h>
int main() {
    printf("%ld\n", sysconf(_SC_OPEN_MAX));
    return 0;
}
