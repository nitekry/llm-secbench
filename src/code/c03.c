#include <stdio.h>
#include <string.h>
#include <time.h>

static FILE *log_fp;

static void log_event(const char *level, const char *msg)
{
    char stamp[32];
    time_t now = time(NULL);

    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(log_fp, "%s [%s] ", stamp, level);
    fprintf(log_fp, msg); /* @@VULN@@ */
    fputc('\n', log_fp);
    fflush(log_fp);
}

/* Reads protocol lines from the client on stdin (inetd style). */
int main(void)
{
    char line[512];

    log_fp = fopen("/var/log/kiosk.log", "a");
    if (log_fp == NULL)
        log_fp = stderr;

    while (fgets(line, sizeof(line), stdin) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';

        if (strncmp(line, "HELLO ", 6) == 0) {
            log_event("INFO", line + 6);
            puts("OK");
        } else if (strcmp(line, "PING") == 0) {
            puts("PONG");
        } else if (strcmp(line, "QUIT") == 0) {
            puts("BYE");
            break;
        } else {
            puts("ERR unknown command");
        }
        fflush(stdout);
    }
    return 0;
}
