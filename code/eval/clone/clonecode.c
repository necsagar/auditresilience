#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>

#define STACK_SIZE  (64 * 1024)

int main(int argc, char **argv) {
    long long loops, i;
    char *stack;
    char *stack_top;

    if (argc != 2) return 1;
    
    loops = atoll(argv[1]);
    if (loops <= 0) return 0;

    /* Ignore SIGCHLD so kernel automatically reaps children.
       This lets us skip waitpid() entirely for max throughput. */
    signal(SIGCHLD, SIG_IGN);

    stack = malloc(STACK_SIZE);
    if (!stack) return 1;
    
    stack_top = stack + STACK_SIZE;

    for (i = 0; i < loops; i++) {
        pid_t pid = (pid_t)syscall(SYS_clone, SIGCHLD, stack_top, NULL, NULL, NULL);
        if (pid < 0) break;
        if (pid == 0) _exit(0);
    }

    free(stack);
    return 0;
}
