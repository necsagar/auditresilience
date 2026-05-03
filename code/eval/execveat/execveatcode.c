#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    long long loops;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <loops>\n", argv[0]);
        return 1;
    }

    loops = atoll(argv[1]);
    if (loops <= 0) return 1;

    static char *const tiny_argv[] = { "x", NULL };
    static char *const tiny_envp[] = { NULL };

    const char *bad_path = (const char *)1;  // -EFAULT (fast)

    for (long long i = 0; i < loops; i++) {
        (void)syscall(SYS_execveat,
                      -1,                // dirfd
                      bad_path,           // pathname -> EFAULT
                      tiny_argv,
                      tiny_envp,
                      0);                // flags
    }
    return 0;
}