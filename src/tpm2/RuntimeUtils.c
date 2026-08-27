// SPDX-License-Identifier: BSD-2-Clause

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <RuntimeUtils_fp.h>

/*
 * RuntimeUtilsDedupStrItems does in-place deduplication of comma-separated
 * items in a string. If an item contains '=' (rsa-min-size=) then the part
 * before the '=' is deduplicated. When deduplicating always the later item is
 * kept.
 */
void RuntimeUtilsDedupStrItems(char *input)
{
    char *comma, *equals, *dup, *ncomma;
    char *pos = input;
    size_t slen;
    bool found;
    char exp;

    while (true) {
        comma = strchr(pos, ',');
        if (!comma)
            return;

        /* temporarily terminate string here */
        *comma = '\0';
        equals = strchr(pos, '=');
        if (equals) {
            *equals = '\0';
            exp = '=';
            slen = equals - pos;
        } else {
            exp = ',';
            slen = comma - pos;
        }

        found = false;
        ncomma = comma;
        /* search for string after the comma */
        while (true) {
            dup = strstr(ncomma + 1, pos);
            if (dup) {
                /* ensure 'dup' is a whole token: valid left boundary AND right boundary */
                if ((dup[-1] == ',' || dup[-1] == 0) &&
                    (dup[slen] == exp || dup[slen] == 0)) {
                    memmove(pos, comma + 1, strlen(comma + 1) + 1);
                    /* keep pos as-is */
                    found = true;
                    break;
                }
                /* only a prefix matched; continue search after comma */
                ncomma = strchr(dup, ',');
                if (!ncomma)
                    break;
            } else {
                break;
            }
        }
        if (!found) {
            *comma = ',';
            if (equals)
               *equals = '=';
            pos = comma + 1;
        }
    }
}

#if defined(HAVE_MAIN)
/*
 * gcc src/tpm2/RuntimeUtils.c -DHAVE_MAIN -Isrc/tpm2 -o RuntimeUtils
 */
int main(void)
{
    char buffer[200];
    const char *exp;
    int ret = 0;

    strncpy(buffer,
            "foo=bar,fox=baz,foo=bar,xyz,abc,xyz,xyz,abc,foo,bar,other-foo,bar",
            sizeof(buffer) - 1);
    RuntimeUtilsDedupStrItems(buffer);
    exp = "fox=baz,foo=bar,xyz,abc,foo,other-foo,bar";
    if (strcmp(buffer, exp) != 0) {
        printf("Unexpected result string\nexpected: %s\nactual  : %s\n", exp, buffer);
        ret = 1;
    }
    return ret;
}
#endif
