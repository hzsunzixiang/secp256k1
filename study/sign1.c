
#include <stdio.h>
#include "secp256k1.c"
#include "include/secp256k1.h"
#include "testrand_impl.h"

#include "contrib/lax_der_parsing.c"
#include "contrib/lax_der_privatekey_parsing.c"

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



    /* Sign. */
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[0], message, privkey, NULL, NULL) == 1);

    /* Verify. */
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);


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
    /* initialize */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	test_ecdsa_end_to_end();
    /* shutdown */
    secp256k1_context_destroy(ctx);
    printf("no problems found\n");
    return 0;
}
