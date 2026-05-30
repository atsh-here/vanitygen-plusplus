#include <errno.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "segwit_addr.h"

static const unsigned char TAPTWEAK_HASH[32] = {
    0xe8, 0x0f, 0xe1, 0x63, 0x9c, 0x9c, 0xa0, 0x50,
    0xe3, 0xaf, 0x1b, 0x39, 0xc1, 0x43, 0xc6, 0x3e,
    0x42, 0x9c, 0xbc, 0xeb, 0x15, 0xd9, 0x40, 0xfb,
    0xb5, 0xc5, 0xa1, 0xf4, 0xaf, 0x57, 0xc5, 0xe9
};

static const char *SECP256K1_ORDER_HEX =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

static int starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int bn_to_hex32(const BIGNUM *bn, char out[65]) {
    unsigned char tmp[32];
    if (BN_bn2binpad(bn, tmp, sizeof(tmp)) != (int) sizeof(tmp)) {
        return 0;
    }

    for (size_t i = 0; i < sizeof(tmp); ++i) {
        snprintf(out + i * 2, 3, "%02x", tmp[i]);
    }
    out[64] = '\0';
    return 1;
}

static int parse_hex32(const char *hex, BIGNUM **out) {
    if (!hex || strlen(hex) != 64) {
        return 0;
    }

    BIGNUM *bn = NULL;
    if (!BN_hex2bn(&bn, hex)) {
        return 0;
    }

    *out = bn;
    return 1;
}

static int parse_uncompressed_pubkey_hex(const EC_GROUP *group, const char *hex, EC_POINT *out_point) {
    size_t hex_len;
    unsigned char raw[65];
    size_t out_len = sizeof(raw);

    if (!hex || !group || !out_point) {
        return 0;
    }

    hex_len = strlen(hex);
    if (hex_len != 130) {
        return 0;
    }

    if (!OPENSSL_hexstr2buf_ex(raw, sizeof(raw), &out_len, hex, ':')) {
        return 0;
    }
    if (out_len != 65 || raw[0] != 0x04) {
        return 0;
    }

    if (!EC_POINT_oct2point(group, out_point, raw, out_len, NULL)) {
        return 0;
    }

    return 1;
}

static int point_to_uncompressed_hex(const EC_GROUP *group, const EC_POINT *point, char out_hex[131]) {
    unsigned char raw[65];
    size_t oct_len;

    oct_len = EC_POINT_point2oct(group,
                                 point,
                                 POINT_CONVERSION_UNCOMPRESSED,
                                 raw,
                                 sizeof(raw),
                                 NULL);
    if (oct_len != sizeof(raw)) {
        return 0;
    }

    for (size_t i = 0; i < sizeof(raw); ++i) {
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

static int increment_scalar_mod_order(BIGNUM *scalar, const BIGNUM *order) {
    if (!BN_add_word(scalar, 1)) {
        return 0;
    }

    if (BN_cmp(scalar, order) >= 0) {
        if (!BN_set_word(scalar, 1)) {
            return 0;
        }
    }
    return 1;
}

static int compute_taptweak_scalar(const unsigned char x_only_internal[32], unsigned char tweak_out[32], BIGNUM **tweak_bn) {
    unsigned char preimage[96];

    memcpy(preimage, TAPTWEAK_HASH, 32);
    memcpy(preimage + 32, TAPTWEAK_HASH, 32);
    memcpy(preimage + 64, x_only_internal, 32);
    SHA256(preimage, sizeof(preimage), tweak_out);

    *tweak_bn = BN_bin2bn(tweak_out, 32, NULL);
    return *tweak_bn != NULL;
}

static int compute_taproot_output_from_internal_point(const EC_GROUP *group,
                                                      const EC_POINT *internal_point,
                                                      const char *hrp,
                                                      char *address,
                                                      size_t address_len,
                                                      unsigned char tweaked_x[32],
                                                      BIGNUM **tweak_scalar_out) {
    unsigned char internal_uncompressed[65];
    unsigned char tweak_bytes[32];
    EC_POINT *tweak_point = NULL;
    EC_POINT *output_point = NULL;
    unsigned char output_compressed[33];
    size_t len;
    BIGNUM *tweak_bn = NULL;
    int success = 0;

    (void) address_len;

    len = EC_POINT_point2oct(group,
                             internal_point,
                             POINT_CONVERSION_UNCOMPRESSED,
                             internal_uncompressed,
                             sizeof(internal_uncompressed),
                             NULL);
    if (len != sizeof(internal_uncompressed)) {
        goto out;
    }

    if ((internal_uncompressed[64] & 1U) != 0U) {
        goto out;
    }

    if (!compute_taptweak_scalar(internal_uncompressed + 1, tweak_bytes, &tweak_bn)) {
        goto out;
    }

    tweak_point = EC_POINT_new(group);
    output_point = EC_POINT_new(group);
    if (!tweak_point || !output_point) {
        goto out;
    }

    if (!EC_POINT_mul(group, tweak_point, tweak_bn, NULL, NULL, NULL)) {
        goto out;
    }

    if (!EC_POINT_add(group, output_point, internal_point, tweak_point, NULL)) {
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

    if (tweaked_x) {
        memcpy(tweaked_x, output_compressed + 1, 32);
    }

    if (tweak_scalar_out) {
        *tweak_scalar_out = tweak_bn;
        tweak_bn = NULL;
    }

    success = 1;
out:
    if (tweak_bn) {
        BN_free(tweak_bn);
    }
    if (output_point) {
        EC_POINT_free(output_point);
    }
    if (tweak_point) {
        EC_POINT_free(tweak_point);
    }

    return success;
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

    if (!point_to_uncompressed_hex(group, alice_pub, pub_hex)) {
        goto out;
    }

    if (!bn_to_hex32(alice_priv, priv_hex)) {
        goto out;
    }

    printf("Alice Pubkey (hex): %s\n", pub_hex);
    printf("Alice Privkey (hex): %s\n", priv_hex);
    ok = 1;
out:
    if (alice_pub) {
        EC_POINT_free(alice_pub);
    }
    if (alice_priv) {
        BN_clear_free(alice_priv);
    }
    if (bn_ctx) {
        BN_CTX_free(bn_ctx);
    }
    return ok;
}

static int run_bob_mine(const EC_GROUP *group,
                        const BIGNUM *order,
                        const char *alice_pub_hex,
                        const char *pattern,
                        int stop_after,
                        const char *hrp) {
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bob_scalar = NULL;
    EC_POINT *alice_pub = NULL;
    EC_POINT *bob_pub = NULL;
    EC_POINT *combined_internal = NULL;
    EC_POINT *generator = NULL;
    int found = 0;

    bn_ctx = BN_CTX_new();
    bob_scalar = BN_new();
    alice_pub = EC_POINT_new(group);
    bob_pub = EC_POINT_new(group);
    combined_internal = EC_POINT_new(group);
    generator = EC_POINT_dup(EC_GROUP_get0_generator(group), group);

    if (!bn_ctx || !bob_scalar || !alice_pub || !bob_pub || !combined_internal || !generator) {
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

    if (!random_nonzero_scalar(order, bob_scalar)) {
        goto out;
    }

    if (!EC_POINT_mul(group, bob_pub, bob_scalar, NULL, NULL, bn_ctx)) {
        goto out;
    }

    if (!EC_POINT_add(group, combined_internal, alice_pub, bob_pub, bn_ctx)) {
        goto out;
    }

    printf("Pattern: %s\n", pattern);

    while (found < stop_after) {
        char address[128] = {0};

        if (compute_taproot_output_from_internal_point(group,
                                                       combined_internal,
                                                       hrp,
                                                       address,
                                                       sizeof(address),
                                                       NULL,
                                                       NULL)
            && starts_with(address, pattern)) {
            char bob_hex[65] = {0};
            char combined_hex[131] = {0};

            if (!bn_to_hex32(bob_scalar, bob_hex)) {
                goto out;
            }
            if (!point_to_uncompressed_hex(group, combined_internal, combined_hex)) {
                goto out;
            }

            printf("BTC Address: %s\n", address);
            printf("Bob PrivkeyPart (hex): %s\n", bob_hex);
            printf("Combined Internal Pubkey (hex): %s\n", combined_hex);
            found++;
        }

        if (!increment_scalar_mod_order(bob_scalar, order)) {
            goto out;
        }

        if (!EC_POINT_add(group, bob_pub, bob_pub, generator, bn_ctx)) {
            goto out;
        }
        if (!EC_POINT_add(group, combined_internal, combined_internal, generator, bn_ctx)) {
            goto out;
        }
    }

out:
    if (generator) {
        EC_POINT_free(generator);
    }
    if (combined_internal) {
        EC_POINT_free(combined_internal);
    }
    if (bob_pub) {
        EC_POINT_free(bob_pub);
    }
    if (alice_pub) {
        EC_POINT_free(alice_pub);
    }
    if (bob_scalar) {
        BN_clear_free(bob_scalar);
    }
    if (bn_ctx) {
        BN_CTX_free(bn_ctx);
    }

    return found == stop_after;
}

static int run_internal_derive(const EC_GROUP *group, const char *priv_hex, const char *hrp, char *address) {
    BN_CTX *bn_ctx = NULL;
    BIGNUM *priv = NULL;
    EC_POINT *internal = NULL;
    int ok = 0;

    bn_ctx = BN_CTX_new();
    internal = EC_POINT_new(group);
    if (!bn_ctx || !internal) {
        goto out;
    }

    if (!parse_hex32(priv_hex, &priv) || BN_is_zero(priv)) {
        goto out;
    }

    if (!EC_POINT_mul(group, internal, priv, NULL, NULL, bn_ctx)) {
        goto out;
    }

    ok = compute_taproot_output_from_internal_point(group,
                                                    internal,
                                                    hrp,
                                                    address,
                                                    128,
                                                    NULL,
                                                    NULL);

out:
    if (internal) {
        EC_POINT_free(internal);
    }
    if (priv) {
        BN_clear_free(priv);
    }
    if (bn_ctx) {
        BN_CTX_free(bn_ctx);
    }
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
    EC_POINT *internal_point = NULL;
    unsigned char tweaked_x[32] = {0};
    char address[128] = {0};
    char verify_address[128] = {0};
    char internal_hex[65] = {0};
    char tweaked_hex[65] = {0};
    int ok = 0;

    bn_ctx = BN_CTX_new();
    internal_point = EC_POINT_new(group);
    internal_scalar = BN_new();
    tweaked_scalar = BN_new();
    if (!bn_ctx || !internal_point || !internal_scalar || !tweaked_scalar) {
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

    if (!compute_taproot_output_from_internal_point(group,
                                                    internal_point,
                                                    hrp,
                                                    address,
                                                    sizeof(address),
                                                    tweaked_x,
                                                    &tweak_scalar)) {
        fprintf(stderr, "Combined key produced odd-Y internal point (unsupported in this implementation)\n");
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
    if (tweak_scalar) {
        BN_clear_free(tweak_scalar);
    }
    if (tweaked_scalar) {
        BN_clear_free(tweaked_scalar);
    }
    if (internal_scalar) {
        BN_clear_free(internal_scalar);
    }
    if (bob) {
        BN_clear_free(bob);
    }
    if (alice) {
        BN_clear_free(alice);
    }
    if (internal_point) {
        EC_POINT_free(internal_point);
    }
    if (bn_ctx) {
        BN_CTX_free(bn_ctx);
    }

    return ok;
}

static void usage(const char *name) {
    fprintf(stderr,
            "Usage:\n"
            "  %s [-1] [-a amount] [pattern]\n"
            "  %s derive-internal <privkey-hex>\n"
            "  %s alice-gen\n"
            "  %s bob-mine --alice-pub <uncompressed-pubkey-hex> [-1] [-a amount] [pattern]\n"
            "  %s combine --alice-priv <hex> --bob-part <hex> [--expected <address>]\n",
            name, name, name, name, name);
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

    if (argc > 1 && strcmp(argv[1], "alice-gen") == 0) {
        ok = run_alice_keygen(group, order);
        goto out;
    }

    if (argc > 1 && strcmp(argv[1], "derive-internal") == 0) {
        char address[128] = {0};
        if (argc != 3) {
            usage(argv[0]);
            goto out;
        }
        if (!run_internal_derive(group, argv[2], hrp, address)) {
            fprintf(stderr, "Failed to derive taproot address from internal private key\n");
            goto out;
        }
        printf("BTC Address: %s\n", address);
        ok = 1;
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
        int i;

        for (i = 2; i < argc; ++i) {
            if (strcmp(argv[i], "--alice-pub") == 0 && (i + 1) < argc) {
                alice_pub = argv[++i];
                continue;
            }
            if (strcmp(argv[i], "-1") == 0) {
                stop_after = 1;
                continue;
            }
            if (strcmp(argv[i], "-a") == 0 && (i + 1) < argc) {
                stop_after = atoi(argv[++i]);
                if (stop_after < 1) {
                    fprintf(stderr, "Invalid stop amount\n");
                    goto out;
                }
                continue;
            }
            if (argv[i][0] == '-') {
                usage(argv[0]);
                goto out;
            }
            pattern = argv[i];
        }

        if (!alice_pub) {
            usage(argv[0]);
            goto out;
        }

        ok = run_bob_mine(group, order, alice_pub, pattern, stop_after, hrp);
        goto out;
    }

    {
        BIGNUM *scalar = NULL;
        EC_POINT *internal_point = NULL;
        EC_POINT *generator = NULL;
        BN_CTX *bn_ctx = NULL;
        int stop_after = 1;
        int i;
        int found = 0;

        for (i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "-1") == 0) {
                stop_after = 1;
                continue;
            }
            if (strcmp(argv[i], "-a") == 0 && (i + 1) < argc) {
                stop_after = atoi(argv[++i]);
                if (stop_after < 1) {
                    fprintf(stderr, "Invalid stop amount\n");
                    goto out;
                }
                continue;
            }
            if (argv[i][0] == '-') {
                usage(argv[0]);
                goto out;
            }
            pattern = argv[i];
        }

        scalar = BN_new();
        internal_point = EC_POINT_new(group);
        generator = EC_POINT_dup(EC_GROUP_get0_generator(group), group);
        bn_ctx = BN_CTX_new();
        if (!scalar || !internal_point || !generator || !bn_ctx) {
            if (scalar) BN_clear_free(scalar);
            if (internal_point) EC_POINT_free(internal_point);
            if (generator) EC_POINT_free(generator);
            if (bn_ctx) BN_CTX_free(bn_ctx);
            goto out;
        }

        if (!random_nonzero_scalar(order, scalar)) {
            BN_clear_free(scalar);
            EC_POINT_free(internal_point);
            EC_POINT_free(generator);
            BN_CTX_free(bn_ctx);
            goto out;
        }

        if (!EC_POINT_mul(group, internal_point, scalar, NULL, NULL, bn_ctx)) {
            BN_clear_free(scalar);
            EC_POINT_free(internal_point);
            EC_POINT_free(generator);
            BN_CTX_free(bn_ctx);
            goto out;
        }

        printf("Pattern: %s\n", pattern);

        while (found < stop_after) {
            char address[128] = {0};
            if (compute_taproot_output_from_internal_point(group,
                                                           internal_point,
                                                           hrp,
                                                           address,
                                                           sizeof(address),
                                                           NULL,
                                                           NULL)
                && starts_with(address, pattern)) {
                char scalar_hex[65] = {0};
                if (!bn_to_hex32(scalar, scalar_hex)) {
                    BN_clear_free(scalar);
                    EC_POINT_free(internal_point);
                    EC_POINT_free(generator);
                    BN_CTX_free(bn_ctx);
                    goto out;
                }
                printf("BTC Address: %s\n", address);
                printf("BTC Privkey (hex): %s\n", scalar_hex);
                found++;
            }

            if (!increment_scalar_mod_order(scalar, order)) {
                BN_clear_free(scalar);
                EC_POINT_free(internal_point);
                EC_POINT_free(generator);
                BN_CTX_free(bn_ctx);
                goto out;
            }
            if (!EC_POINT_add(group, internal_point, internal_point, generator, bn_ctx)) {
                BN_clear_free(scalar);
                EC_POINT_free(internal_point);
                EC_POINT_free(generator);
                BN_CTX_free(bn_ctx);
                goto out;
            }
        }

        BN_clear_free(scalar);
        EC_POINT_free(internal_point);
        EC_POINT_free(generator);
        BN_CTX_free(bn_ctx);
        ok = 1;
    }

out:
    if (order) {
        BN_clear_free(order);
    }
    if (group) {
        EC_GROUP_free(group);
    }

    if (!ok) {
        return 1;
    }

    return 0;
}
