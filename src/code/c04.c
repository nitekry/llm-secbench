#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct session {
    int    id;
    char  *buf;
    size_t len;
};

static struct session *open_session(int id)
{
    struct session *s = calloc(1, sizeof(*s));
    if (s != NULL)
        s->id = id;
    return s;
}

static void close_session(struct session *s)
{
    free(s->buf);
    free(s);
}

static int append(struct session *s, const char *data, size_t n)
{
    char *tmp = realloc(s->buf, s->len + n);
    if (tmp == NULL)
        return -1;
    s->buf = tmp;
    memcpy(s->buf + s->len, data, n);
    s->len += n;
    return 0;
}

/* Returns 0 on success; on error the session is closed and must not be reused. */
int process_chunk(struct session *s, const char *data, size_t n)
{
    if (n == 0 || n > 4096) {
        close_session(s);
        fprintf(stderr, "session %d: bad chunk size %zu\n", s->id, n); /* @@VULN@@ */
        return -1;
    }
    if (append(s, data, n) != 0) {
        fprintf(stderr, "session %d: out of memory\n", s->id);
        close_session(s);
        return -1;
    }
    return 0;
}

int main(void)
{
    char chunk[8192];
    size_t n;
    struct session *s = open_session(1);

    if (s == NULL)
        return 1;
    while ((n = fread(chunk, 1, sizeof(chunk), stdin)) > 0) {
        if (process_chunk(s, chunk, n) != 0)
            return 1;
    }
    printf("received %zu bytes\n", s->len);
    close_session(s);
    return 0;
}
