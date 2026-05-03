#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/stat.h>

/*
 * renamecode: rename storm with two modes.
 *
 * Usage: renamecode <loops> <mode>
 *   mode = "ok"   -> fast *valid* rename() in a tmp directory
 *   mode = "fail" -> fast-fail renameat2() with invalid dirfd (-1)
 *
 * OK mode:
 *   - Creates a temp dir ./rndir_xxxxx
 *   - Creates files a and b inside it
 *   - For each loop:
 *       rename(a_path, b_path);
 *       rename(b_path, a_path);
 *   - All renames succeed; directory is valid.
 *
 * FAIL mode:
 *   - For each loop:
 *       renameat2(-1, "x", -1, "y", 0)  -> -EBADF
 *   - Very cheap error path, still fully logged.
 */

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char **argv) {
    long long loops, i;
    int is_fail = 0;

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

    if (is_fail) {
        /* FAIL MODE: fast-fail renameat2 with invalid dirfd. */

        static const char *oldname = "x";
        static const char *newname = "y";

        for (i = 0; i < loops; i++) {
            long ret = syscall(SYS_renameat2,
                               -1, oldname,   /* invalid dirfd -> EBADF */
                               -1, newname,
                               0);
            (void)ret;  /* your logger sees ret on sys_exit_renameat2 */
        }

        return 0;
    }

    /* OK MODE: valid directory, real renames. */

    char dirname[] = "./rndir_XXXXXX";
    if (!mkdtemp(dirname)) {
        die("mkdtemp");
    }

    char a_path[256], b_path[256];
    snprintf(a_path, sizeof(a_path), "%s/a", dirname);
    snprintf(b_path, sizeof(b_path), "%s/b", dirname);

    /* Create two small files in that directory. */
    int fd;

    fd = open(a_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) die("open a");
    if (write(fd, "x", 1) < 0) die("write a");
    close(fd);

    fd = open(b_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) die("open b");
    if (write(fd, "y", 1) < 0) die("write b");
    close(fd);

    /* Now repeatedly rename within a valid directory. */
    for (i = 0; i < loops; i++) {
        if (rename(a_path, b_path) < 0) die("rename a->b");
        if (rename(b_path, a_path) < 0) die("rename b->a");
    }

    /* Cleanup (optional; the logger already saw the work). */
    unlink(a_path);
    unlink(b_path);
    rmdir(dirname);

    return 0;
}
