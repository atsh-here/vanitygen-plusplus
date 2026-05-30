#include <stdio.h>
#include <string.h>

#include "../util.h"

void fdumphex(FILE *fp, const unsigned char *src, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        fprintf(fp, "%02x", src[i]);
    }
    fprintf(fp, "\n");
}

void dumphex(const unsigned char *src, size_t len) {
    fdumphex(stdout, src, len);
}

int hex_dec(void *bin, size_t *binszp, const char *hex, size_t hexsz) {
    unsigned char *out = (unsigned char *) bin;
    size_t out_sz = *binszp;
    size_t i;

    if ((hexsz % 2) != 0) {
        return 0;
    }
    if ((hexsz / 2) > out_sz) {
        return 0;
    }

    for (i = 0; i < hexsz / 2; i++) {
        unsigned int byte = 0;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1) {
            return 0;
        }
        out[i] = (unsigned char) byte;
    }

    *binszp = hexsz / 2;
    if (*binszp < out_sz) {
        memset(out + *binszp, 0, out_sz - *binszp);
    }
    return 1;
}
