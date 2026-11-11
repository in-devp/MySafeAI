#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 2) {
        pid_t child = fork();
        if (child == 0) {
            pid_t grandchild = fork();
            if (grandchild > 0) {
                FILE *file = fopen(argv[1], "w");
                if (!file) return 1;
                fprintf(file, "%d %d\n", getpid(), grandchild);
                fclose(file);
            }
        }
    }
    for (;;) pause();
}
