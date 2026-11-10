/*
 * printspool-submit: copies a user's file into the print spool.
 * Installed setuid root so it can write into /var/spool/print.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SPOOL_DIR "/var/spool/print"

int main(int argc, char **argv)
{
    char out_path[256];
    char buf[4096];
    ssize_t n;

    if (argc != 2) {
        fprintf(stderr, "usage: %s FILE\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];

    /* Make sure the invoking user is allowed to read the file. */
    if (access(path, R_OK) != 0) { /* @@VULN@@ */
        perror("access");
        return 1;
    }

    int in = open(path, O_RDONLY); /* @@VULN@@ */
    if (in < 0) {
        perror("open");
        return 1;
    }

    snprintf(out_path, sizeof(out_path), SPOOL_DIR "/job-%d-%ld", (int)getuid(), (long)getpid());
    int out = open(out_path, O_WRONLY | O_CREAT | O_EXCL, 0640);
    if (out < 0) {
        perror("open spool");
        close(in);
        return 1;
    }

    while ((n = read(in, buf, sizeof(buf))) > 0) {
        if (write(out, buf, (size_t)n) != n) {
            perror("write");
            break;
        }
    }
    close(in);
    close(out);
    printf("queued as %s\n", out_path);
    return 0;
}
