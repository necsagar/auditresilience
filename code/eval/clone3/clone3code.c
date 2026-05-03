#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/sched.h>   /* struct clone_args */

/*
 * clone3code: high-rate *failing* sys_clone3 generator.
 *
 * Usage: clone3code <loops>
 *
 *  - Prepares clone_args with invalid flags (e.g., -1).
 *  - For each loop:
 *        clone3(&args, sizeof(args))  -> -EINVAL
 *
 * No child is ever created; the kernel just validates args and bails.
 * Your eBPF sees sys_enter_clone3 / sys_exit_clone3 with ret < 0.
 */

int main(int argc, char **argv) {
    long long loops, i;
    struct clone_args args;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <loops>\n", argv[0]);
        return 1;
    }

    loops = atoll(argv[1]);
    if (loops <= 0) {
        fprintf(stderr, "loops must be > 0\n");
        return 1;
    }

    /* Zero everything, then set invalid flags */
    memset(&args, 0, sizeof(args));
    args.flags = (unsigned long long)-1;  /* intentionally invalid */

    for (i = 0; i < loops; i++) {
        long ret = syscall(SYS_clone3, &args, sizeof(args));
        (void)ret;  /* your logger sees ret on sys_exit_clone3 */
    }

    return 0;
}
