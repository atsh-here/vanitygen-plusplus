#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "segwit_addr.h"

static const unsigned char TAPTWEAK_HASH[32] = {
    0xe8, 0x0f, 0xe1, 0x63, 0x9c, 0x9c, 0xa0, 0x50,
    0xe3, 0xaf, 0x1b, 0x39, 0xc1, 0x43, 0xc6, 0x3e,
    0x42, 0x9c, 0xbc, 0xeb, 0x15, 0xd9, 0x40, 0xfb,
    0xb5, 0xc5, 0xa1, 0xf4, 0xaf, 0x57, 0xc5, 0xe9
};

static const char *SECP256K1_ORDER_HEX =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

typedef enum {
    BACKEND_AUTO = 0,
    BACKEND_CPU,
    BACKEND_GPU
} backend_t;

typedef struct {
    const EC_GROUP *group;
    const BIGNUM *order;
    const char *pattern;
    const char *hrp;
    int stride;
    int mode_split;

    const BIGNUM *base_scalar;
    const EC_POINT *base_internal;

    volatile int stop;
    int found;
    int target;

    pthread_mutex_t lock;
} search_ctx_t;

typedef struct {
    search_ctx_t *ctx;
    int tid;
} worker_arg_t;

static int starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int bn_to_hex32(const BIGNUM *bn, char out[65]) {
    unsigned char tmp[32];
    size_t i;
    if (BN_bn2binpad(bn, tmp, sizeof(tmp)) != (int) sizeof(tmp)) {
        return 0;
    }
    for (i = 0; i < sizeof(tmp); ++i) {
        snprintf(out + i * 2, 3, "%02x", tmp[i]);
    }
    out[64] = '\0';
    return 1;
}

static int parse_hex32(const char *hex, BIGNUM **out) {
    BIGNUM *bn = NULL;
    if (!hex || strlen(hex) != 64) {
        return 0;
    }
    if (!BN_hex2bn(&bn, hex)) {
        return 0;
    }
    *out = bn;
    return 1;
}

static int parse_uncompressed_pubkey_hex(const EC_GROUP *group, const char *hex, EC_POINT *out_point) {
    unsigned char raw[65];
    size_t out_len = sizeof(raw);
    if (!hex || strlen(hex) != 130) {
        return 0;
    }
    if (!OPENSSL_hexstr2buf_ex(raw, sizeof(raw), &out_len, hex, ':')) {
        return 0;
    }
    if (out_len != 65 || raw[0] != 0x04) {
        return 0;
    }
    return EC_POINT_oct2point(group, out_point, raw, out_len, NULL) == 1;
}

static int point_to_uncompressed_hex(const EC_GROUP *group, const EC_POINT *point, char out_hex[131]) {
    unsigned char raw[65];
    size_t i;
    size_t oct_len = EC_POINT_point2oct(group,
                                        point,
                                        POINT_CONVERSION_UNCOMPRESSED,
                                        raw,
                                        sizeof(raw),
                                        NULL);
    if (oct_len != sizeof(raw)) {
        return 0;
    }
    for (i = 0; i < sizeof(raw); ++i) {
        snprintf(out_hex + i * 2, 3, "%02x", raw[i]);
    }
    out_hex[130] = '\0';
    return 1;
}

static int random_nonzero_scalar(const BIGNUM *order, BIGNUM *out_scalar) {
    int tries = 0;
    do {
        if (!BN_priv_rand_range_ex(out_scalar, order, 0, NULL)) {
            return 0;
        }
        tries++;
    } while (BN_is_zero(out_scalar) && tries < 32);
    return !BN_is_zero(out_scalar);
}

static int increment_scalar_mod_order(BIGNUM *scalar, const BIGNUM *order, int delta) {
    if (!BN_add_word(scalar, (BN_ULONG) delta)) {
        return 0;
    }
    while (BN_cmp(scalar, order) >= 0) {
        if (!BN_sub(scalar, scalar, order)) {
            return 0;
        }
    }
    if (BN_is_zero(scalar) && !BN_set_word(scalar, 1)) {
        return 0;
    }
    return 1;
}

static int is_point_odd_y(const EC_GROUP *group, const EC_POINT *point) {
    unsigned char raw[65];
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, raw, sizeof(raw), NULL);
    if (len != sizeof(raw)) {
        return 0;
    }
    return (raw[64] & 1U) != 0U;
}

static int compute_taproot_output_from_internal_point(const EC_GROUP *group,
                                                      const EC_POINT *internal_point,
                                                      const char *hrp,
                                                      char *address,
                                                      unsigned char tweaked_x[32],
                                                      BIGNUM *reuse_tweak_bn,
                                                      EC_POINT *reuse_tweak_pt,
                                                      EC_POINT *reuse_output_pt) {
    unsigned char internal_uncompressed[65];
    unsigned char preimage[96];
    unsigned char tweak_bytes[32];
    unsigned char output_compressed[33];
    size_t len;

    len = EC_POINT_point2oct(group,
                             internal_point,
                             POINT_CONVERSION_UNCOMPRESSED,
                             internal_uncompressed,
                             sizeof(internal_uncompressed),
                             NULL);
    if (len != sizeof(internal_uncompressed)) {
        return 0;
    }

    memcpy(preimage, TAPTWEAK_HASH, 32);
    memcpy(preimage + 32, TAPTWEAK_HASH, 32);
    memcpy(preimage + 64, internal_uncompressed + 1, 32);
    SHA256(preimage, sizeof(preimage), tweak_bytes);

    if (!BN_bin2bn(tweak_bytes, sizeof(tweak_bytes), reuse_tweak_bn)) {
        return 0;
    }

    if (!EC_POINT_mul(group, reuse_tweak_pt, reuse_tweak_bn, NULL, NULL, NULL)) {
        return 0;
    }
    if ((internal_uncompressed[64] & 1U) != 0U) {
        if (!EC_POINT_copy(reuse_output_pt, internal_point)) {
            return 0;
        }
        if (!EC_POINT_invert(group, reuse_output_pt, NULL)) {
            return 0;
        }
        if (!EC_POINT_add(group, reuse_output_pt, reuse_output_pt, reuse_tweak_pt, NULL)) {
            return 0;
        }
    } else {
        if (!EC_POINT_add(group, reuse_output_pt, internal_point, reuse_tweak_pt, NULL)) {
            return 0;
        }
    }

    len = EC_POINT_point2oct(group,
                             reuse_output_pt,
                             POINT_CONVERSION_COMPRESSED,
                             output_compressed,
                             sizeof(output_compressed),
                             NULL);
    if (len != sizeof(output_compressed)) {
        return 0;
    }

    if (tweaked_x) {
        memcpy(tweaked_x, output_compressed + 1, 32);
    }

    return segwit_addr_encode(address, hrp, 1, output_compressed + 1, 32) == 1;
}

static int derive_from_internal_private(const EC_GROUP *group, const BIGNUM *priv, const BIGNUM *order, const char *hrp, char *address) {
    BN_CTX *bn_ctx = NULL;
    EC_POINT *internal = NULL;
    BIGNUM *adj = NULL;
    BIGNUM *tweak = NULL;
    BIGNUM *tweaked = NULL;
    EC_POINT *tmp_tweak = NULL;
    EC_POINT *tmp_output = NULL;
    int ok = 0;

    if (BN_is_zero(priv) || BN_cmp(priv, order) >= 0) {
        return 0;
    }

    bn_ctx = BN_CTX_new();
    internal = EC_POINT_new(group);
    adj = BN_dup(priv);
    tweak = BN_new();
    tweaked = BN_new();
    tmp_tweak = EC_POINT_new(group);
    tmp_output = EC_POINT_new(group);

    if (!bn_ctx || !internal || !adj || !tweak || !tweaked || !tmp_tweak || !tmp_output) {
        goto out;
    }

    if (!EC_POINT_mul(group, internal, adj, NULL, NULL, bn_ctx)) {
        goto out;
    }

    if (is_point_odd_y(group, internal)) {
        if (!BN_sub(adj, order, adj)) {
            goto out;
        }
        if (!EC_POINT_mul(group, internal, adj, NULL, NULL, bn_ctx)) {
            goto out;
        }
    }

    if (!compute_taproot_output_from_internal_point(group, internal, hrp, address, NULL, tweak, tmp_tweak, tmp_output)) {
        goto out;
    }

    if (!BN_mod_add(tweaked, adj, tweak, order, bn_ctx) || BN_is_zero(tweaked)) {
        goto out;
    }

    ok = 1;
out:
    if (tmp_output) EC_POINT_free(tmp_output);
    if (tmp_tweak) EC_POINT_free(tmp_tweak);
    if (tweaked) BN_clear_free(tweaked);
    if (tweak) BN_clear_free(tweak);
    if (adj) BN_clear_free(adj);
    if (internal) EC_POINT_free(internal);
    if (bn_ctx) BN_CTX_free(bn_ctx);
    return ok;
}

static void maybe_record_match(search_ctx_t *ctx,
                               const BIGNUM *scalar,
                               const EC_POINT *internal_point,
                               const char *address) {
    pthread_mutex_lock(&ctx->lock);
    if (!ctx->stop && ctx->found < ctx->target) {
        char scalar_hex[65] = {0};
        BIGNUM *display_scalar = BN_dup(scalar);
        int odd = is_point_odd_y(ctx->group, internal_point);
        if (display_scalar && !ctx->mode_split && odd) {
            if (!BN_sub(display_scalar, ctx->order, scalar)) {
                BN_clear_free(display_scalar);
                display_scalar = NULL;
            }
        }
        if (display_scalar && bn_to_hex32(display_scalar, scalar_hex)) {
            printf("BTC Address: %s\n", address);
            if (ctx->mode_split) {
                char combined_hex[131] = {0};
                EC_POINT *display_point = EC_POINT_dup(internal_point, ctx->group);
                if (display_point && odd) {
                    EC_POINT_invert(ctx->group, display_point, NULL);
                }
                if (display_point && point_to_uncompressed_hex(ctx->group, display_point, combined_hex)) {
                    printf("Bob PrivkeyPart (hex): %s\n", scalar_hex);
                    printf("Combined Internal Pubkey (hex): %s\n", combined_hex);
                }
                if (display_point) {
                    EC_POINT_free(display_point);
                }
            } else {
                printf("BTC Privkey (hex): %s\n", scalar_hex);
            }
            ctx->found++;
            if (ctx->found >= ctx->target) {
                ctx->stop = 1;
            }
        }
        if (display_scalar) {
            BN_clear_free(display_scalar);
        }
    }
    pthread_mutex_unlock(&ctx->lock);
}

static void *worker_loop(void *arg) {
    worker_arg_t *w = (worker_arg_t *) arg;
    search_ctx_t *ctx = w->ctx;
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *scalar = BN_new();
    BIGNUM *tweak_bn = BN_new();
    EC_POINT *internal = EC_POINT_new(ctx->group);
    EC_POINT *stride_point = EC_POINT_new(ctx->group);
    EC_POINT *tmp_tweak = EC_POINT_new(ctx->group);
    EC_POINT *tmp_output = EC_POINT_new(ctx->group);
    EC_POINT *offset = EC_POINT_new(ctx->group);

    if (!bn_ctx || !scalar || !tweak_bn || !internal || !stride_point || !tmp_tweak || !tmp_output || !offset) {
        goto out;
    }

    if (ctx->mode_split) {
        if (!BN_copy(scalar, ctx->base_scalar)) {
            goto out;
        }
        if (!increment_scalar_mod_order(scalar, ctx->order, w->tid)) {
            goto out;
        }

        if (!EC_POINT_copy(internal, ctx->base_internal)) {
            goto out;
        }

        if (w->tid > 0) {
            BIGNUM *tid_bn = BN_new();
            if (!tid_bn) goto out;
            if (!BN_set_word(tid_bn, (BN_ULONG) w->tid)) {
                BN_free(tid_bn);
                goto out;
            }
            if (!EC_POINT_mul(ctx->group, offset, NULL, EC_GROUP_get0_generator(ctx->group), tid_bn, bn_ctx)) {
                BN_free(tid_bn);
                goto out;
            }
            BN_free(tid_bn);
            if (!EC_POINT_add(ctx->group, internal, internal, offset, bn_ctx)) {
                goto out;
            }
        }
    } else {
        if (!random_nonzero_scalar(ctx->order, scalar)) {
            goto out;
        }
        if (!increment_scalar_mod_order(scalar, ctx->order, w->tid)) {
            goto out;
        }
        if (!EC_POINT_mul(ctx->group, internal, scalar, NULL, NULL, bn_ctx)) {
            goto out;
        }
    }

    {
        BIGNUM *stride_bn = BN_new();
        if (!stride_bn) goto out;
        if (!BN_set_word(stride_bn, (BN_ULONG) ctx->stride)) {
            BN_free(stride_bn);
            goto out;
        }
        if (!EC_POINT_mul(ctx->group, stride_point, NULL, EC_GROUP_get0_generator(ctx->group), stride_bn, bn_ctx)) {
            BN_free(stride_bn);
            goto out;
        }
        BN_free(stride_bn);
    }

    while (!ctx->stop) {
        char address[128] = {0};
        if (compute_taproot_output_from_internal_point(ctx->group,
                                                       internal,
                                                       ctx->hrp,
                                                       address,
                                                       NULL,
                                                       tweak_bn,
                                                       tmp_tweak,
                                                       tmp_output)
            && starts_with(address, ctx->pattern)) {
            maybe_record_match(ctx, scalar, internal, address);
        }

        if (ctx->stop) {
            break;
        }

        if (!increment_scalar_mod_order(scalar, ctx->order, ctx->stride)) {
            break;
        }

        if (!EC_POINT_add(ctx->group, internal, internal, stride_point, bn_ctx)) {
            break;
        }
    }

out:
    if (offset) EC_POINT_free(offset);
    if (tmp_output) EC_POINT_free(tmp_output);
    if (tmp_tweak) EC_POINT_free(tmp_tweak);
    if (stride_point) EC_POINT_free(stride_point);
    if (internal) EC_POINT_free(internal);
    if (tweak_bn) BN_clear_free(tweak_bn);
    if (scalar) BN_clear_free(scalar);
    if (bn_ctx) BN_CTX_free(bn_ctx);
    return NULL;
}

static int run_parallel_mine(const EC_GROUP *group,
                             const BIGNUM *order,
                             const char *pattern,
                             int stop_after,
                             const char *hrp,
                             int threads,
                             int mode_split,
                             const BIGNUM *base_scalar,
                             const EC_POINT *base_internal) {
    pthread_t *tids = NULL;
    worker_arg_t *args = NULL;
    search_ctx_t ctx;
    int i;

    memset(&ctx, 0, sizeof(ctx));
    ctx.group = group;
    ctx.order = order;
    ctx.pattern = pattern;
    ctx.hrp = hrp;
    ctx.stride = threads;
    ctx.mode_split = mode_split;
    ctx.target = stop_after;
    ctx.base_scalar = base_scalar;
    ctx.base_internal = base_internal;
    pthread_mutex_init(&ctx.lock, NULL);

    tids = (pthread_t *) calloc((size_t) threads, sizeof(pthread_t));
    args = (worker_arg_t *) calloc((size_t) threads, sizeof(worker_arg_t));
    if (!tids || !args) {
        free(tids);
        free(args);
        pthread_mutex_destroy(&ctx.lock);
        return 0;
    }

    printf("Pattern: %s\n", pattern);

    for (i = 0; i < threads; ++i) {
        args[i].ctx = &ctx;
        args[i].tid = i;
        if (pthread_create(&tids[i], NULL, worker_loop, &args[i]) != 0) {
            ctx.stop = 1;
            break;
        }
    }

    for (i = 0; i < threads; ++i) {
        if (tids[i]) {
            pthread_join(tids[i], NULL);
        }
    }

    free(args);
    free(tids);
    pthread_mutex_destroy(&ctx.lock);
    return ctx.found == stop_after;
}

static int run_alice_keygen(const EC_GROUP *group, const BIGNUM *order) {
    BN_CTX *bn_ctx = NULL;
    BIGNUM *alice_priv = NULL;
    EC_POINT *alice_pub = NULL;
    char pub_hex[131] = {0};
    char priv_hex[65] = {0};
    int ok = 0;

    bn_ctx = BN_CTX_new();
    alice_priv = BN_new();
    alice_pub = EC_POINT_new(group);
    if (!bn_ctx || !alice_priv || !alice_pub) {
        goto out;
    }

    if (!random_nonzero_scalar(order, alice_priv)) {
        goto out;
    }

    if (!EC_POINT_mul(group, alice_pub, alice_priv, NULL, NULL, bn_ctx)) {
        goto out;
    }

    if (!point_to_uncompressed_hex(group, alice_pub, pub_hex) || !bn_to_hex32(alice_priv, priv_hex)) {
        goto out;
    }

    printf("Alice Pubkey (hex): %s\n", pub_hex);
    printf("Alice Privkey (hex): %s\n", priv_hex);
    ok = 1;
out:
    if (alice_pub) EC_POINT_free(alice_pub);
    if (alice_priv) BN_clear_free(alice_priv);
    if (bn_ctx) BN_CTX_free(bn_ctx);
    return ok;
}

static int run_bob_mine(const EC_GROUP *group,
                        const BIGNUM *order,
                        const char *alice_pub_hex,
                        const char *pattern,
                        int stop_after,
                        const char *hrp,
                        int threads) {
    BN_CTX *bn_ctx = NULL;
    BIGNUM *base_scalar = NULL;
    EC_POINT *alice_pub = NULL;
    EC_POINT *base_bob = NULL;
    EC_POINT *base_internal = NULL;
    int ok = 0;

    bn_ctx = BN_CTX_new();
    base_scalar = BN_new();
    alice_pub = EC_POINT_new(group);
    base_bob = EC_POINT_new(group);
    base_internal = EC_POINT_new(group);

    if (!bn_ctx || !base_scalar || !alice_pub || !base_bob || !base_internal) {
        goto out;
    }

    if (!parse_uncompressed_pubkey_hex(group, alice_pub_hex, alice_pub)) {
        fprintf(stderr, "Invalid Alice pubkey; expected uncompressed 130-hex key\n");
        goto out;
    }

    if (!EC_POINT_is_on_curve(group, alice_pub, bn_ctx)) {
        fprintf(stderr, "Alice pubkey is not on secp256k1\n");
        goto out;
    }

    if (!random_nonzero_scalar(order, base_scalar)) {
        goto out;
    }

    if (!EC_POINT_mul(group, base_bob, base_scalar, NULL, NULL, bn_ctx)) {
        goto out;
    }

    if (!EC_POINT_add(group, base_internal, alice_pub, base_bob, bn_ctx)) {
        goto out;
    }

    ok = run_parallel_mine(group,
                           order,
                           pattern,
                           stop_after,
                           hrp,
                           threads,
                           1,
                           base_scalar,
                           base_internal);
out:
    if (base_internal) EC_POINT_free(base_internal);
    if (base_bob) EC_POINT_free(base_bob);
    if (alice_pub) EC_POINT_free(alice_pub);
    if (base_scalar) BN_clear_free(base_scalar);
    if (bn_ctx) BN_CTX_free(bn_ctx);
    return ok;
}

static int compute_address_from_tweaked_private(const EC_GROUP *group,
                                                const BIGNUM *tweaked_priv,
                                                const char *hrp,
                                                char *address) {
    EC_POINT *output_point = NULL;
    unsigned char output_compressed[33];
    size_t len;
    int ok = 0;

    output_point = EC_POINT_new(group);
    if (!output_point) {
        return 0;
    }

    if (!EC_POINT_mul(group, output_point, tweaked_priv, NULL, NULL, NULL)) {
        goto out;
    }

    len = EC_POINT_point2oct(group,
                             output_point,
                             POINT_CONVERSION_COMPRESSED,
                             output_compressed,
                             sizeof(output_compressed),
                             NULL);
    if (len != sizeof(output_compressed)) {
        goto out;
    }

    if (!segwit_addr_encode(address, hrp, 1, output_compressed + 1, 32)) {
        goto out;
    }

    ok = 1;
out:
    EC_POINT_free(output_point);
    return ok;
}

static int run_combine_and_verify(const EC_GROUP *group,
                                  const BIGNUM *order,
                                  const char *alice_priv_hex,
                                  const char *bob_part_hex,
                                  const char *expected,
                                  const char *hrp) {
    BN_CTX *bn_ctx = NULL;
    BIGNUM *alice = NULL;
    BIGNUM *bob = NULL;
    BIGNUM *internal_scalar = NULL;
    BIGNUM *tweaked_scalar = NULL;
    BIGNUM *tweak_scalar = NULL;
    BIGNUM *negated = NULL;
    EC_POINT *internal_point = NULL;
    EC_POINT *tmp_tweak = NULL;
    EC_POINT *tmp_output = NULL;
    char address[128] = {0};
    char verify_address[128] = {0};
    char internal_hex[65] = {0};
    char tweaked_hex[65] = {0};
    int ok = 0;

    bn_ctx = BN_CTX_new();
    internal_point = EC_POINT_new(group);
    internal_scalar = BN_new();
    tweaked_scalar = BN_new();
    tweak_scalar = BN_new();
    negated = BN_new();
    tmp_tweak = EC_POINT_new(group);
    tmp_output = EC_POINT_new(group);

    if (!bn_ctx || !internal_point || !internal_scalar || !tweaked_scalar || !tweak_scalar || !negated || !tmp_tweak || !tmp_output) {
        goto out;
    }

    if (!parse_hex32(alice_priv_hex, &alice) || BN_is_zero(alice) || BN_cmp(alice, order) >= 0) {
        fprintf(stderr, "Invalid Alice private key\n");
        goto out;
    }
    if (!parse_hex32(bob_part_hex, &bob) || BN_is_zero(bob) || BN_cmp(bob, order) >= 0) {
        fprintf(stderr, "Invalid Bob privkey part\n");
        goto out;
    }

    if (!BN_mod_add(internal_scalar, alice, bob, order, bn_ctx) || BN_is_zero(internal_scalar)) {
        fprintf(stderr, "Combined internal scalar is invalid\n");
        goto out;
    }

    if (!EC_POINT_mul(group, internal_point, internal_scalar, NULL, NULL, bn_ctx)) {
        goto out;
    }

    if (is_point_odd_y(group, internal_point)) {
        if (!BN_sub(negated, order, internal_scalar) || BN_is_zero(negated)) {
            goto out;
        }
        if (!BN_copy(internal_scalar, negated)) {
            goto out;
        }
        if (!EC_POINT_mul(group, internal_point, internal_scalar, NULL, NULL, bn_ctx)) {
            goto out;
        }
    }

    if (!compute_taproot_output_from_internal_point(group,
                                                    internal_point,
                                                    hrp,
                                                    address,
                                                    NULL,
                                                    tweak_scalar,
                                                    tmp_tweak,
                                                    tmp_output)) {
        goto out;
    }

    if (!BN_mod_add(tweaked_scalar, internal_scalar, tweak_scalar, order, bn_ctx) || BN_is_zero(tweaked_scalar)) {
        fprintf(stderr, "Tweaked scalar is invalid\n");
        goto out;
    }

    if (!compute_address_from_tweaked_private(group, tweaked_scalar, hrp, verify_address)) {
        goto out;
    }

    if (!bn_to_hex32(internal_scalar, internal_hex) || !bn_to_hex32(tweaked_scalar, tweaked_hex)) {
        goto out;
    }

    printf("BTC Address: %s\n", address);
    printf("Combined Internal Privkey (hex): %s\n", internal_hex);
    printf("Final Tweaked Privkey (hex): %s\n", tweaked_hex);
    printf("Verification Address: %s\n", verify_address);
    printf("Verification: %s\n", strcmp(address, verify_address) == 0 ? "OK" : "FAILED");

    if (expected && expected[0] != '\0') {
        printf("Expected Address: %s\n", expected);
        if (strcmp(address, expected) != 0) {
            fprintf(stderr, "Expected address mismatch\n");
            goto out;
        }
    }

    if (strcmp(address, verify_address) != 0) {
        goto out;
    }

    ok = 1;
out:
    if (tmp_output) EC_POINT_free(tmp_output);
    if (tmp_tweak) EC_POINT_free(tmp_tweak);
    if (negated) BN_clear_free(negated);
    if (tweak_scalar) BN_clear_free(tweak_scalar);
    if (tweaked_scalar) BN_clear_free(tweaked_scalar);
    if (internal_scalar) BN_clear_free(internal_scalar);
    if (bob) BN_clear_free(bob);
    if (alice) BN_clear_free(alice);
    if (internal_point) EC_POINT_free(internal_point);
    if (bn_ctx) BN_CTX_free(bn_ctx);
    return ok;
}

static void usage(const char *name) {
    fprintf(stderr,
            "Usage:\n"
            "  %s [-1] [-a amount] [--threads N] [--backend auto|cpu|gpu] [pattern]\n"
            "  %s --derive <internal-privkey-hex>\n"
            "  %s derive-internal <internal-privkey-hex>\n"
            "  %s alice-gen\n"
            "  %s bob-mine --alice-pub <uncompressed-pubkey-hex> [-1] [-a amount] [--threads N] [pattern]\n"
            "  %s combine --alice-priv <hex> --bob-part <hex> [--expected <address>]\n",
            name, name, name, name, name, name);
}

static int parse_threads(int requested) {
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    int detected = (cores > 0) ? (int) cores : 1;
    if (detected < 1) {
        detected = 1;
    }
    if (requested > 0) {
        return requested;
    }
    return detected;
}

int main(int argc, char **argv) {
    const char *hrp = "bc";
    const char *pattern = "bc1pp";
    EC_GROUP *group = NULL;
    BIGNUM *order = NULL;
    int ok = 0;

    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    order = BN_new();
    if (!group || !order || !BN_hex2bn(&order, SECP256K1_ORDER_HEX)) {
        fprintf(stderr, "Failed to initialize secp256k1 parameters\n");
        goto out;
    }

    if (argc > 1 && (strcmp(argv[1], "--derive") == 0 || strcmp(argv[1], "derive-internal") == 0)) {
        char address[128] = {0};
        BIGNUM *priv = NULL;
        if (argc != 3) {
            usage(argv[0]);
            goto out;
        }
        if (!parse_hex32(argv[2], &priv) || !derive_from_internal_private(group, priv, order, hrp, address)) {
            fprintf(stderr, "Failed to derive taproot address from internal private key\n");
            if (priv) BN_clear_free(priv);
            goto out;
        }
        printf("BTC Address: %s\n", address);
        BN_clear_free(priv);
        ok = 1;
        goto out;
    }

    if (argc > 1 && strcmp(argv[1], "alice-gen") == 0) {
        ok = run_alice_keygen(group, order);
        goto out;
    }

    if (argc > 1 && strcmp(argv[1], "combine") == 0) {
        const char *alice_priv = NULL;
        const char *bob_part = NULL;
        const char *expected = NULL;
        int i;
        for (i = 2; i < argc; ++i) {
            if (strcmp(argv[i], "--alice-priv") == 0 && (i + 1) < argc) {
                alice_priv = argv[++i];
            } else if (strcmp(argv[i], "--bob-part") == 0 && (i + 1) < argc) {
                bob_part = argv[++i];
            } else if (strcmp(argv[i], "--expected") == 0 && (i + 1) < argc) {
                expected = argv[++i];
            } else {
                usage(argv[0]);
                goto out;
            }
        }
        if (!alice_priv || !bob_part) {
            usage(argv[0]);
            goto out;
        }
        ok = run_combine_and_verify(group, order, alice_priv, bob_part, expected, hrp);
        goto out;
    }

    if (argc > 1 && strcmp(argv[1], "bob-mine") == 0) {
        const char *alice_pub = NULL;
        int stop_after = 1;
        int threads = 0;
        int i;
        for (i = 2; i < argc; ++i) {
            if (strcmp(argv[i], "--alice-pub") == 0 && (i + 1) < argc) {
                alice_pub = argv[++i];
            } else if (strcmp(argv[i], "-1") == 0) {
                stop_after = 1;
            } else if (strcmp(argv[i], "-a") == 0 && (i + 1) < argc) {
                stop_after = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--threads") == 0 && (i + 1) < argc) {
                threads = atoi(argv[++i]);
            } else if (argv[i][0] == '-') {
                usage(argv[0]);
                goto out;
            } else {
                pattern = argv[i];
            }
        }
        if (!alice_pub || stop_after < 1) {
            usage(argv[0]);
            goto out;
        }
        threads = parse_threads(threads);
        printf("Backend: gpu-emulated (%d CPU threads)\n", threads);
        ok = run_bob_mine(group, order, alice_pub, pattern, stop_after, hrp, threads);
        goto out;
    }

    {
        int stop_after = 1;
        int threads = 0;
        backend_t backend = BACKEND_AUTO;
        int i;
        for (i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "-1") == 0) {
                stop_after = 1;
            } else if (strcmp(argv[i], "-a") == 0 && (i + 1) < argc) {
                stop_after = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--threads") == 0 && (i + 1) < argc) {
                threads = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--backend") == 0 && (i + 1) < argc) {
                const char *v = argv[++i];
                if (strcmp(v, "auto") == 0) backend = BACKEND_AUTO;
                else if (strcmp(v, "cpu") == 0) backend = BACKEND_CPU;
                else if (strcmp(v, "gpu") == 0) backend = BACKEND_GPU;
                else {
                    usage(argv[0]);
                    goto out;
                }
            } else if (argv[i][0] == '-') {
                usage(argv[0]);
                goto out;
            } else {
                pattern = argv[i];
            }
        }

        if (stop_after < 1) {
            fprintf(stderr, "Invalid stop amount\n");
            goto out;
        }

        threads = parse_threads(threads);
        if (backend == BACKEND_CPU) {
            threads = 1;
            printf("Backend: cpu\n");
        } else {
            printf("Backend: gpu-emulated (%d CPU threads)\n", threads);
        }

        ok = run_parallel_mine(group,
                               order,
                               pattern,
                               stop_after,
                               hrp,
                               threads,
                               0,
                               NULL,
                               NULL);
    }

out:
    if (order) BN_clear_free(order);
    if (group) EC_GROUP_free(group);
    return ok ? 0 : 1;
}
