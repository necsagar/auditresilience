#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/*
 * chmodcode: chmod storm with two modes.
 *
 * Usage: chmodcode <loops> <mode>
 *   mode = "ok"   -> valid chmod() on a real file (flip modes back and forth)
 *   mode = "fail" -> chmod() on nonexistent path -> -ENOENT
 *
 * OK MODE:
 *   - Creates a temp dir ./chmoddir_XXXXXX
 *   - Creates file "f" inside it
 *   - For each loop:
 *       chmod(file, 0600);
 *       chmod(file, 0644);
 *
 * FAIL MODE:
 *   - For each loop:
 *       chmod("/does/not/exist_chmod_target", 0600); -> -ENOENT
 *
 * In both cases, your eBPF sees sys_enter_chmod / sys_exit_chmod
 * with full args and return values. FAIL mode gives a fast error path.
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
        /* FAIL MODE: chmod on a nonexistent path -> -ENOENT (fast-ish error). */

        const char *bad_path = "/does/not/exist_chmod_target";

        for (i = 0; i < loops; i++) {
            int ret = chmod(bad_path, 0600);
            (void)ret;  /* your logger sees ret on sys_exit_chmod */
        }

        return 0;
    }

    /* OK MODE: real directory + real file, flip permissions back and forth. */

    char dirname[] = "./chmoddir_XXXXXX";
    if (!mkdtemp(dirname)) {
        die("mkdtemp");
    }

    char file_path[256];
    snprintf(file_path, sizeof(file_path), "%s/f", dirname);

    /* Create a small file */
    int fd = open(file_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) die("open file");
    if (write(fd, "x", 1) < 0) die("write file");
    close(fd);

    mode_t mode1 = 0600;
    mode_t mode2 = 0644;

    for (i = 0; i < loops; i++) {
        if (chmod(file_path, mode1) < 0) die("chmod mode1");
       // if (chmod(file_path, mode2) < 0) die("chmod mode2");
    }

    /* Cleanup (optional, logger already saw all actions). */
    unlink(file_path);
    rmdir(dirname);

    return 0;
}
