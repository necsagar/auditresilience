#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

/*
 * mprotectcode: mprotect storm with valid ("ok") and invalid ("fail") modes,
 *               tuned to hit your PROT_EXEC-based filter.
 *
 * Usage: mprotectcode <loops> <mode>
 *   mode = "ok"   -> valid mprotect() on a real, page-aligned mapping,
 *                    always with PROT_EXEC set
 *   mode = "fail" -> mprotect() with intentionally invalid arguments
 *                    (unaligned addr), but still PROT_EXEC so it is logged.
 *
 * OK MODE:
 *   - mmap() one page of anonymous memory: PROT_READ | PROT_WRITE | PROT_EXEC
 *   - For each loop:
 *       mprotect(base, pagesz, PROT_READ | PROT_EXEC);
 *       mprotect(base, pagesz, PROT_READ | PROT_WRITE | PROT_EXEC);
 *
 * FAIL MODE:
 *   - mmap() one page same as ok mode
 *   - Use base+1 as address (not page-aligned) with same length
 *   - For each loop:
 *       mprotect(bad_addr, pagesz, PROT_READ | PROT_EXEC);
 *   - This should return -1 in userspace with errno == EINVAL,
 *     and your sys_exit_mprotect sees ret == -EINVAL (-22).
 */

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char **argv) {
    long long loops, i;
    int is_fail = 0;
    long pagesz;
    void *base;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <loops> <mode>\n", argv[0]);
        fprintf(stderr, "  mode = ok | fail\n");
        return 1;
    }

    loops = atoll(argv[1]);
    if (loops <= 0) {
        fprintf(stderr, "loops must be > 0\n");
        return 1;
    }

    if (strcmp(argv[2], "fail") == 0) {
        is_fail = 1;
    } else if (strcmp(argv[2], "ok") == 0) {
        is_fail = 0;
    } else {
        fprintf(stderr, "Invalid mode: %s (expected ok|fail)\n", argv[2]);
        return 1;
    }

    pagesz = sysconf(_SC_PAGESIZE);
    if (pagesz <= 0) {
        die("sysconf(_SC_PAGESIZE)");
    }

    /* Map one page of anonymous memory, including PROT_EXEC so that
     * later mprotect calls with EXEC perms are meaningful. */
    base = mmap(NULL, pagesz,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0);
    if (base == MAP_FAILED) {
        die("mmap");
    }

    if (!is_fail) {
        /* OK MODE: flip exec-related protections on a valid mapping. */

        for (i = 0; i < loops; i++) {
            if (mprotect(base, pagesz, PROT_READ | PROT_EXEC) != 0)
                die("mprotect READ|EXEC");

            if (mprotect(base, pagesz,
                         PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
                die("mprotect READ|WRITE|EXEC");
        }

    } else {
        /* FAIL MODE: use an unaligned address; mprotect requires page alignment.
         * Still include PROT_EXEC so sys_enter_mprotect logs it. */

        char *bad_addr = (char *)base + 1;  /* definitely not page-aligned */

        for (i = 0; i < loops; i++) {
            int ret = mprotect(bad_addr, pagesz, PROT_READ | PROT_EXEC);
            (void)ret;  /* your eBPF sees ret = -EINVAL (-22) on exit */
        }
    }

    munmap(base, pagesz);
    return 0;
}
