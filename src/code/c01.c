#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME_LEN 32
#define MAX_USERS 128

struct user_record {
    char name[NAME_LEN];
    int  uid;
    int  flags;
};

static struct user_record users[MAX_USERS];
static int user_count;

/* Parses "name:uid" lines from the account export. */
static int parse_line(const char *line, struct user_record *rec)
{
    const char *sep = strchr(line, ':');
    if (sep == NULL)
        return -1;

    char field[256];
    size_t n = (size_t)(sep - line);
    if (n == 0 || n >= sizeof(field))
        return -1;
    memcpy(field, line, n);
    field[n] = '\0';

    strcpy(rec->name, field); /* @@VULN@@ */
    rec->uid = atoi(sep + 1);
    rec->flags = 0;
    return 0;
}

int main(void)
{
    char line[512];

    while (fgets(line, sizeof(line), stdin) != NULL && user_count < MAX_USERS) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0')
            continue;
        if (parse_line(line, &users[user_count]) == 0)
            user_count++;
        else
            fprintf(stderr, "skipping malformed line\n");
    }

    for (int i = 0; i < user_count; i++)
        printf("%-32s %6d\n", users[i].name, users[i].uid);
    return 0;
}
