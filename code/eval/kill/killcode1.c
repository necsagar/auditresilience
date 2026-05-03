#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>

/*
 * killcode: high-rate sys_kill generator.
 *
 * Usage: killcode <loops>
 *
 *  - Forks a child that ignores SIGUSR1 and sleeps.
 *  - Parent performs <loops> calls to kill(child, SIGUSR1) via SYS_kill.
 *  - Then kills the child and exits.
 *
 * This should:
 *   - Hit sys_enter_kill / sys_exit_kill tracepoints.
 *   - Use sig > 0 (SIGUSR1), so it passes your args->sig > 0 filter.
 */

static void sigusr1_handler(int signo) {
    (void)signo;
    /* Ignore SIGUSR1, just return to pause() */
}

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
        /* Child: install SIGUSR1 handler and sleep forever. */
        struct sigaction sa;
        sa.sa_handler = sigusr1_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGUSR1, &sa, NULL) < 0) {
            perror("sigaction");
            _exit(1);
        }

        for (;;) {
            pause();
        }
    }

    /* Parent: tight loop of kill(child, SIGUSR1) */
    for (i = 0; i < loops; i++) {
        syscall(SYS_kill, child, SIGUSR1);
    }

    /* Clean up child */
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    return 0;
}
