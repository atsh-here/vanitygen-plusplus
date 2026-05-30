#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../simplevanitygen.h"

int main(int argc, char **argv) {
    vg_context_simplevanitygen_t ctx;
    char *pattern = (argc > 1) ? argv[1] : "bc1pp";

    memset(&ctx, 0, sizeof(ctx));
    ctx.vc_format = VCF_P2TR;
    ctx.vc_addrtype = 0;
    ctx.vc_privtype = 0;
    ctx.vc_coin = "BTC";
    ctx.vc_hrp = "bc";
    ctx.vc_numpairs = 1;
    ctx.pattern = pattern;
    ctx.match_location = 1;
    ctx.vc_thread_num = 1;
    ctx.vc_start_time = (unsigned long) time(NULL);

    printf("Pattern: %s\n", pattern);
    if (!start_threads_simplevanitygen(&ctx)) {
        fprintf(stderr, "start_threads_simplevanitygen failed\n");
        return 1;
    }

    return 0;
}
