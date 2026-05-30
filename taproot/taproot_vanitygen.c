#include <errno.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
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

static int get_public_key(EVP_PKEY *pkey, unsigned char *pub_buf, size_t buf_len, int form, size_t *output_len) {
    int ok = 0;
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        return 0;
    }

    const EC_POINT *ppoint = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP *pgroup = EC_KEY_get0_group(ec_key);
    *output_len = EC_POINT_point2oct(pgroup,
                                     ppoint,
                                     (point_conversion_form_t) form,
                                     pub_buf,
                                     buf_len,
                                     NULL);
    if (*output_len > 0) {
        ok = 1;
    }

    EC_KEY_free(ec_key);
    return ok;
}

static int get_private_key(EVP_PKEY *pkey, unsigned char *priv_buf, size_t priv_buf_len, size_t *output_len) {
    int ok = 0;
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        return 0;
    }

    const BIGNUM *pkbn = EC_KEY_get0_private_key(ec_key);
    if (pkbn && BN_bn2binpad(pkbn, priv_buf, (int) priv_buf_len) == (int) priv_buf_len) {
        *output_len = priv_buf_len;
        ok = 1;
    }

    EC_KEY_free(ec_key);
    return ok;
}

static int compute_taproot_address_from_pubkey(const unsigned char *uncompressed_pubkey,
                                               EVP_PKEY *pkey,
                                               const char *hrp,
                                               char *address,
                                               size_t address_len) {
    unsigned char preimage[96];
    unsigned char tagged_hash[32];
    unsigned char tweaked_pub[65];
    BIGNUM *t = NULL;
    EC_KEY *ec_key = NULL;
    EC_POINT *T = NULL;
    EC_POINT *Q = NULL;
    int success = 0;

    if (address_len < 96) {
        return 0;
    }

    if (uncompressed_pubkey[64] % 2 != 0) {
        return 0;
    }

    memcpy(preimage, TAPTWEAK_HASH, 32);
    memcpy(preimage + 32, TAPTWEAK_HASH, 32);
    memcpy(preimage + 64, uncompressed_pubkey + 1, 32);
    SHA256(preimage, sizeof(preimage), tagged_hash);

    t = BN_bin2bn(tagged_hash, sizeof(tagged_hash), NULL);
    if (!t) {
        goto out;
    }

    ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        goto out;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    const EC_POINT *P = EC_KEY_get0_public_key(ec_key);
    if (!group || !P) {
        goto out;
    }

    T = EC_POINT_new(group);
    Q = EC_POINT_new(group);
    if (!T || !Q) {
        goto out;
    }

    if (!EC_POINT_mul(group, T, t, NULL, NULL, NULL)) {
        goto out;
    }

    if (!EC_POINT_add(group, Q, P, T, NULL)) {
        goto out;
    }

    if (!EC_POINT_point2oct(group, Q, POINT_CONVERSION_COMPRESSED, tweaked_pub, sizeof(tweaked_pub), NULL)) {
        goto out;
    }

    if (!segwit_addr_encode(address, hrp, 1, tweaked_pub + 1, 32)) {
        goto out;
    }

    success = 1;
out:
    if (Q) {
        EC_POINT_free(Q);
    }
    if (T) {
        EC_POINT_free(T);
    }
    if (ec_key) {
        EC_KEY_free(ec_key);
    }
    if (t) {
        BN_free(t);
    }
    return success;
}

static void print_hex(const unsigned char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int derive_address_from_private_key_hex(const char *privhex, const char *hrp, char *address, size_t address_len) {
    EC_KEY *ec_key = NULL;
    BIGNUM *priv = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char uncompressed_pub[128];
    size_t output_len = 0;
    int ok = 0;

    ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        goto out;
    }

    if (!BN_hex2bn(&priv, privhex)) {
        goto out;
    }

    if (!EC_KEY_set_private_key(ec_key, priv)) {
        goto out;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub = EC_POINT_new(group);
    if (!pub) {
        goto out;
    }

    if (!EC_POINT_mul(group, pub, priv, NULL, NULL, NULL)) {
        EC_POINT_free(pub);
        goto out;
    }

    if (!EC_KEY_set_public_key(ec_key, pub)) {
        EC_POINT_free(pub);
        goto out;
    }
    EC_POINT_free(pub);

    pkey = EVP_PKEY_new();
    if (!pkey) {
        goto out;
    }

    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        goto out;
    }
    ec_key = NULL;

    if (!get_public_key(pkey, uncompressed_pub, sizeof(uncompressed_pub), POINT_CONVERSION_UNCOMPRESSED, &output_len)) {
        goto out;
    }

    ok = compute_taproot_address_from_pubkey(uncompressed_pub, pkey, hrp, address, address_len);

out:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (ec_key) {
        EC_KEY_free(ec_key);
    }
    if (priv) {
        BN_free(priv);
    }
    return ok;
}

static void usage(const char *name) {
    fprintf(stderr,
            "Usage:\n"
            "  %s [-1] [-a amount] [pattern]\n"
            "  %s --derive <privkey-hex>\n",
            name, name);
}

int main(int argc, char **argv) {
    const char *pattern = "bc1pp";
    const char *hrp = "bc";
    int stop_after = 0;
    int i;

    if (argc > 1 && strcmp(argv[1], "--derive") == 0) {
        char address[128] = {0};
        if (argc != 3) {
            usage(argv[0]);
            return 1;
        }
        if (!derive_address_from_private_key_hex(argv[2], hrp, address, sizeof(address))) {
            fprintf(stderr, "Failed to derive taproot address from private key\n");
            return 1;
        }
        printf("BTC Address: %s\n", address);
        return 0;
    }

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-1") == 0) {
            stop_after = 1;
            continue;
        }
        if (strcmp(argv[i], "-a") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return 1;
            }
            stop_after = atoi(argv[++i]);
            if (stop_after < 1) {
                fprintf(stderr, "Invalid stop amount\n");
                return 1;
            }
            continue;
        }
        if (argv[i][0] == '-') {
            usage(argv[0]);
            return 1;
        }
        pattern = argv[i];
    }

    if (stop_after == 0) {
        stop_after = 1;
    }

    printf("Pattern: %s\n", pattern);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = NULL;
    unsigned char priv_buf[32];
    unsigned char pub_buf[128];
    size_t output_len = 0;
    int found = 0;

    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_id failed\n");
        return 1;
    }

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        EVP_PKEY_CTX_free(pctx);
        return 1;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, SN_secp256k1, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(pctx, params) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_params failed\n");
        EVP_PKEY_CTX_free(pctx);
        return 1;
    }

    while (found < stop_after) {
        char address[128] = {0};

        if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
            fprintf(stderr, "EVP_PKEY_keygen failed\n");
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }

        if (!get_public_key(pkey, pub_buf, sizeof(pub_buf), POINT_CONVERSION_UNCOMPRESSED, &output_len)) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
            continue;
        }

        if (!compute_taproot_address_from_pubkey(pub_buf, pkey, hrp, address, sizeof(address))) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
            continue;
        }

        if (strncmp(pattern, address, strlen(pattern)) == 0) {
            size_t priv_len = 0;
            if (!get_private_key(pkey, priv_buf, sizeof(priv_buf), &priv_len)) {
                EVP_PKEY_free(pkey);
                pkey = NULL;
                continue;
            }
            printf("BTC Address: %s\n", address);
            printf("BTC Privkey (hex): ");
            print_hex(priv_buf, priv_len);
            found++;
        }

        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;
}
