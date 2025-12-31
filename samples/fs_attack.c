#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int main() {
    printf("Attempting to open /etc/shadow...\n");
    int fd = open("/etc/shadow", O_RDONLY);
    if (fd < 0) {
        perror("Open failed");
    } else {
        printf("CRITICAL ERROR: Opened /etc/shadow!\n");
        close(fd);
    }

    printf("Attempting to write to root directory...\n");
    int fd2 = open("/hacked", O_CREAT | O_RDWR, 0644);
    if (fd2 < 0) {
        perror("Write failed");
    } else {
        printf("CRITICAL ERROR: Wrote to /hacked!\n");
        close(fd2);
    }
    return 0;
}
