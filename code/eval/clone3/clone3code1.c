#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

/*
 * Test: clone creates child successfully, but the child fails.
 *
 * Behavior:
 *  - Parent:
 *      ret = child_tid (> 0) from clone()
 *      waitpid() sees child terminated by SIGSEGV.
 *  - Child:
 *      ret = 0 from clone()
 *      then intentionally segfaults.
 *
 * From eBPF tracepoints:
 *  - sys_exit_clone (parent): args->ret = child_tid (> 0)
 *  - sys_exit_clone (child):  args->ret = 0
 *  - later: child exit / signal handling is visible separately.
 */

int main(void) {
    long ret;
    pid_t child;
    int status;

    printf("[parent] calling clone() via raw syscall\n");

    /*
     * Raw clone syscall:
     *   long clone(unsigned long flags,
     *              void *child_stack,
     *              void *parent_tid,
     *              void *child_tid,
     *              unsigned long tls);
     *
     * Using flags = SIGCHLD and child_stack = 0 is effectively fork()-like
     * on x86_64: a separate process with its own stack, child returns 0,
     * parent returns child PID.
     */
    ret = syscall(SYS_clone,
                  SIGCHLD,   /* flags */
                  0,         /* child_stack (0 => use copy of current stack) */
                  NULL,      /* parent_tidptr */
                  NULL,      /* child_tidptr */
                  0);        /* tls */

    if (ret == -1) {
        perror("[parent] clone failed");
        exit(1);
    }

    if (ret == 0) {
        /* Child context: clone() returned 0 here. */
        printf("[child] clone() returned 0, now I will fail intentionally...\n");
        fflush(stdout);

        /* Fail hard: cause a SIGSEGV. */
        volatile int *p = (int *)0x1;
        *p = 42;  /* boom */

        /* Should never reach here. */
        _exit(2);
    }

    /* Parent context: ret > 0, this is the child PID/TID. */
    child = (pid_t)ret;
    printf("[parent] clone() returned child pid=%d\n", child);

    /* Wait for the child and see how it died. */
    if (waitpid(child, &status, 0) == -1) {
        perror("[parent] waitpid failed");
        exit(1);
    }

    if (WIFEXITED(status)) {
        printf("[parent] child exited normally with status=%d\n",
               WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("[parent] child was terminated by signal %d (%s)\n",
               WTERMSIG(status),
               strsignal(WTERMSIG(status)));
    } else {
        printf("[parent] child ended in unexpected state (status=0x%x)\n",
               status);
    }

    return 0;
}
