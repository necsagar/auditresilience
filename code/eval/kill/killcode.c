#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    long long loops, i;
    pid_t child;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <loops>\n", argv[0]);
        return 1;
    }

    loops = atoll(argv[1]);
    if (loops <= 0) {
        fprintf(stderr, "loops must be > 0\n");
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        /* Block SIGUSR1 so the child is never awakened by it. */
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        if (sigprocmask(SIG_BLOCK, &set, NULL) < 0) {
            perror("sigprocmask");
            _exit(1);
        }
        for (;;) pause(); /* SIGUSR1 is blocked, so pause won't return for it */
    }
    /* Parent: tight loop of kill(child, SIGUSR1) */
    for (i = 0; i < loops; i++) {
        (void)syscall(SYS_kill, child, SIGUSR1);
    }
    /* Clean up child */
    (void)kill(child, SIGKILL);
    (void)waitpid(child, NULL, 0);
    return 0;
}