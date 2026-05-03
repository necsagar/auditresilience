#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/syscall.h>
/*
 * kill_invalidcode: high-rate *invalid* kill() generator.
 *
 * Usage: kill_invalidcode <loops>
 *
 *  - Picks a PID that almost certainly does not exist.
 *  - For each loop:
 *        kill(bad_pid, SIGUSR1);
 *    which returns -1 in userspace, errno = ESRCH.
 *
 * From your eBPF side:
 *   - sys_enter_kill sees pid = bad_pid, sig = SIGUSR1 (>0, so it is logged).
 *   - sys_exit_kill sees ret = -ESRCH (i.e., -3).
 */

int main(int argc, char **argv) {
    long long loops, i;
    pid_t bad_pid;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <loops>\n", argv[0]);
        return 1;
    }

    loops = atoll(argv[1]);
    if (loops <= 0) {
        fprintf(stderr, "loops must be > 0\n");
        return 1;
    }

    /*
     * Choose a PID that is almost surely invalid.
     * On typical systems pid_max is << 1,000,000, so this won't exist.
     */
    bad_pid = 1410065408;  /* 1e8 */

    for (i = 0; i < loops; i++) {
        (void)syscall(SYS_kill, bad_pid, SIGUSR1);
        // int ret = kill(bad_pid, SIGUSR1);
        // (void)ret;   /* your eBPF sees ret = -ESRCH on sys_exit_kill */
    }

    return 0;
}
