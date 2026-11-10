#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define TOKEN_LEN 16

struct order {
    char ticker[TOKEN_LEN];
    int  quantity;
};

/* Copies the leading alphanumeric run of src into dst, upper-cased.
 * dst must have room for TOKEN_LEN bytes. Returns chars copied. */
static int normalize_token(char dst[TOKEN_LEN], const char *src)
{
    int i;
    for (i = 0; src[i] != '\0' && i < TOKEN_LEN; i++) { /* @@VULN@@ */
        if (!isalnum((unsigned char)src[i]))
            break;
        dst[i] = (char)toupper((unsigned char)src[i]);
    }
    dst[i] = '\0'; /* @@VULN@@ */
    return i;
}

int main(int argc, char **argv)
{
    struct order o;

    if (argc != 3) {
        fprintf(stderr, "usage: %s TICKER QTY\n", argv[0]);
        return 2;
    }
    if (normalize_token(o.ticker, argv[1]) == 0) {
        fprintf(stderr, "invalid ticker\n");
        return 1;
    }
    if (sscanf(argv[2], "%d", &o.quantity) != 1 || o.quantity <= 0) {
        fprintf(stderr, "invalid quantity\n");
        return 1;
    }
    printf("BUY %s x%d\n", o.ticker, o.quantity);
    return 0;
}
