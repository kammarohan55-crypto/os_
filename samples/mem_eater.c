#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
    printf("Starting Memory Eater...\n");
    size_t chunk = 1024 * 1024 * 10; // 10MB chunks
    while(1) {
        void *p = malloc(chunk);
        if (!p) {
            printf("Malloc failed!\n");
            break;
        }
        memset(p, 0, chunk); // Touch memory to force allocation
        printf("Allocated 10MB\n");
        usleep(100000);
    }
    return 0;
}
