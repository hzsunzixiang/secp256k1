
#include <stdio.h>
#include "secp256k1.c"
#include "include/secp256k1.h"
#include "testrand_impl.h"

#include "contrib/lax_der_parsing.c"
#include "contrib/lax_der_privatekey_parsing.c"

static int count = 64;
static secp256k1_context *ctx = NULL;

void random_scalar_order_test(secp256k1_scalar *num) {
    do {
        unsigned char b32[32];
        int overflow = 0;
        secp256k1_rand256_test(b32);
        secp256k1_scalar_set_b32(num, b32, &overflow);
        if (overflow || secp256k1_scalar_is_zero(num)) {
            continue;
        }
        break;
    } while(1);
}
void test_ecdsa_end_to_end(void) {
    unsigned char extra[32] = {0x00};
    unsigned char privkey[32];
    unsigned char message[32];
    unsigned char privkey2[32];
    secp256k1_ecdsa_signature signature[6];
    secp256k1_scalar r, s;
    unsigned char sig[74];
    size_t siglen = 74;
    unsigned char pubkeyc[65];
    size_t pubkeyclen = 65;
    secp256k1_pubkey pubkey;
    secp256k1_pubkey pubkey_tmp;
    unsigned char seckey[300];
    size_t seckeylen = 300;

    /* Generate a random key and message. */
    {
        secp256k1_scalar msg, key;
        random_scalar_order_test(&msg);
        random_scalar_order_test(&key);
        secp256k1_scalar_get_b32(privkey, &key);
        secp256k1_scalar_get_b32(message, &msg);
    }

    /* Construct and verify corresponding public key. */
    CHECK(secp256k1_ec_seckey_verify(ctx, privkey) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, privkey) == 1);

    /* Verify exporting and importing public key. */
    CHECK(secp256k1_ec_pubkey_serialize(ctx, pubkeyc, &pubkeyclen, &pubkey, secp256k1_rand_bits(1) == 1 ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED));
    memset(&pubkey, 0, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, pubkeyclen) == 1);

    /* Verify negation changes the key and changes it back */
    memcpy(&pubkey_tmp, &pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_negate(ctx, &pubkey_tmp) == 1);
    CHECK(memcmp(&pubkey_tmp, &pubkey, sizeof(pubkey)) != 0);
    CHECK(secp256k1_ec_pubkey_negate(ctx, &pubkey_tmp) == 1);
    CHECK(memcmp(&pubkey_tmp, &pubkey, sizeof(pubkey)) == 0);

    /* Verify private key import and export. */
    CHECK(ec_privkey_export_der(ctx, seckey, &seckeylen, privkey, secp256k1_rand_bits(1) == 1));
    CHECK(ec_privkey_import_der(ctx, privkey2, seckey, seckeylen) == 1);
    CHECK(memcmp(privkey, privkey2, 32) == 0);

    /* Optionally tweak the keys using addition. */
    if (secp256k1_rand_int(3) == 0) {
        int ret1;
        int ret2;
        unsigned char rnd[32];
        secp256k1_pubkey pubkey2;
        secp256k1_rand256_test(rnd);
        ret1 = secp256k1_ec_privkey_tweak_add(ctx, privkey, rnd);
        ret2 = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, rnd);
        CHECK(ret1 == ret2);
        if (ret1 == 0) {
            return;
        }
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, privkey) == 1);
        CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    }

    /* Optionally tweak the keys using multiplication. */
    if (secp256k1_rand_int(3) == 0) {
        int ret1;
        int ret2;
        unsigned char rnd[32];
        secp256k1_pubkey pubkey2;
        secp256k1_rand256_test(rnd);
        ret1 = secp256k1_ec_privkey_tweak_mul(ctx, privkey, rnd);
        ret2 = secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, rnd);
        CHECK(ret1 == ret2);
        if (ret1 == 0) {
            return;
        }
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, privkey) == 1);
        CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    }

    /* Sign. */
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[0], message, privkey, NULL, NULL) == 1);
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[4], message, privkey, NULL, NULL) == 1);
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[1], message, privkey, NULL, extra) == 1);
    extra[31] = 1;
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[2], message, privkey, NULL, extra) == 1);
    extra[31] = 0;
    extra[0] = 1;
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[3], message, privkey, NULL, extra) == 1);
    CHECK(memcmp(&signature[0], &signature[4], sizeof(signature[0])) == 0);
    CHECK(memcmp(&signature[0], &signature[1], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[0], &signature[2], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[0], &signature[3], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[1], &signature[2], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[1], &signature[3], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[2], &signature[3], sizeof(signature[0])) != 0);
    /* Verify. */
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[1], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[2], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[3], message, &pubkey) == 1);
    /* Test lower-S form, malleate, verify and fail, test again, malleate again */
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature[0]));
    secp256k1_ecdsa_signature_load(ctx, &r, &s, &signature[0]);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_ecdsa_signature_save(&signature[5], &r, &s);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[5], message, &pubkey) == 0);
    CHECK(secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature[5]));
    CHECK(secp256k1_ecdsa_signature_normalize(ctx, &signature[5], &signature[5]));
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature[5]));
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, &signature[5], &signature[5]));
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[5], message, &pubkey) == 1);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_ecdsa_signature_save(&signature[5], &r, &s);
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature[5]));
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[5], message, &pubkey) == 1);
    CHECK(memcmp(&signature[5], &signature[0], 64) == 0);

    /* Serialize/parse DER and verify again */
    CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature[0]) == 1);
    memset(&signature[0], 0, sizeof(signature[0]));
    CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &signature[0], sig, siglen) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);
    /* Serialize/destroy/parse DER and verify again. */
    siglen = 74;
    CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature[0]) == 1);
    sig[secp256k1_rand_int(siglen)] += 1 + secp256k1_rand_int(255);
    CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &signature[0], sig, siglen) == 0 ||
          secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 0);
}

int main(int argc, char **argv) {
    unsigned char seed16[16] = {0};
    unsigned char run32[32] = {0};
    /* find iteration count */
    if (argc > 1) {
        count = strtol(argv[1], NULL, 0);
    }

    /* find random seed */
    if (argc > 2) {
        int pos = 0;
        const char* ch = argv[2];
        while (pos < 16 && ch[0] != 0 && ch[1] != 0) {
            unsigned short sh;
            if (sscanf(ch, "%2hx", &sh)) {
                seed16[pos] = sh;
            } else {
                break;
            }
            ch += 2;
            pos++;
        }
    } else {
        FILE *frand = fopen("/dev/urandom", "r");
        if ((frand == NULL) || fread(&seed16, sizeof(seed16), 1, frand) != sizeof(seed16)) {
            uint64_t t = time(NULL) * (uint64_t)1337;
            seed16[0] ^= t;
            seed16[1] ^= t >> 8;
            seed16[2] ^= t >> 16;
            seed16[3] ^= t >> 24;
            seed16[4] ^= t >> 32;
            seed16[5] ^= t >> 40;
            seed16[6] ^= t >> 48;
            seed16[7] ^= t >> 56;
        }
        if (frand) {
            fclose(frand);
        }
    }
    secp256k1_rand_seed(seed16);

    printf("test count = %i\n", count);
    printf("random seed = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", seed16[0], seed16[1], seed16[2], seed16[3], seed16[4], seed16[5], seed16[6], seed16[7], seed16[8], seed16[9], seed16[10], seed16[11], seed16[12], seed16[13], seed16[14], seed16[15]);

    /* initialize */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (secp256k1_rand_bits(1)) {
        secp256k1_rand256(run32);
        CHECK(secp256k1_context_randomize(ctx, secp256k1_rand_bits(1) ? run32 : NULL));
    }

	test_ecdsa_end_to_end();

    secp256k1_rand256(run32);
    printf("random run = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", run32[0], run32[1], run32[2], run32[3], run32[4], run32[5], run32[6], run32[7], run32[8], run32[9], run32[10], run32[11], run32[12], run32[13], run32[14], run32[15]);

    /* shutdown */
    secp256k1_context_destroy(ctx);


    printf("no problems found\n");
    return 0;
}
