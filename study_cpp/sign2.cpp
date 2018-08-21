
#include <stdio.h>
//#include "secp256k1.c"
#include "include/secp256k1.h"
#include "testrand_impl.h"
#include "scalar.h"
#include "hash_impl.h"
#include <string>
#include <iostream>
#include "utilstrencodings.h"


#include "contrib/lax_der_parsing.c"
#include "contrib/lax_der_privatekey_parsing.c"
using namespace std;

static secp256k1_context *ctx = NULL;

//static const unsigned int PUBLIC_KEY_SIZE             = 65;
//static const unsigned int COMPRESSED_PUBLIC_KEY_SIZE  = 33;
//static const unsigned int SIGNATURE_SIZE              = 72;
//static const unsigned int COMPACT_SIGNATURE_SIZE      = 65;

void test_ecdsa_end_to_end(void) {
    unsigned char extra[32] = {0x00};
    unsigned char privkey[32] =  {0xea, 0x62, 0x8a, 0xe2, 0x4b, 0xa, 0x68, 0x52, 0xfc, 0x55, 0xf8, 0xa4, 0xb, 0xf0, 0x7f, 0xa9, 0xa9, 0xe3, 0xbe, 0x78, 0xd7, 0x63, 0x59, 0x67, 0x1f, 0x2c, 0x4a, 0xa2, 0xe6, 0x95, 0xca, 0x20};
    unsigned char message[32] = "helloworld";
    //unsigned char message[32] = {0x5a, 0x72, 0x9, 0x79, 0xcd, 0x61, 0xf9, 0x2f, 0xea, 0xfc, 0xe2, 0xd5, 0xbd, 0x44, 0x67, 0xb0, 0xf0, 0x7b, 0xfd, 0xa2, 0xb3, 0x66, 0x50, 0x5b, 0xa6, 0x4c, 0x72, 0x4d, 0x82, 0xf8, 0x40, 0xe8};
    unsigned char privkey2[32] =  {0xea, 0x62, 0x8a, 0xe2, 0x4b, 0xa, 0x68, 0x52, 0xfc, 0x55, 0xf8, 0xa4, 0xb, 0xf0, 0x7f, 0xa9, 0xa9, 0xe3, 0xbe, 0x78, 0xd7, 0x63, 0x59, 0x67, 0x1f, 0x2c, 0x4a, 0xa2, 0xe6, 0x95, 0xca, 0x20};
    secp256k1_ecdsa_signature signature;
    secp256k1_scalar r, s;
    unsigned char sig[74];
    size_t siglen = 74;
    unsigned char pubkeyc[33];
    size_t pubkeyclen = 33;

    unsigned char pubkeyc1[65];
    size_t pubkeyclen1 = 65;

    secp256k1_pubkey pubkey;
    secp256k1_pubkey pubkey_tmp;
    unsigned char seckey[300];
    size_t seckeylen = 300;

    /* Construct and verify corresponding public key. */
    secp256k1_ec_seckey_verify(ctx, privkey);
    secp256k1_ec_pubkey_create(ctx, &pubkey, privkey);

    string priv = HexStr(privkey, privkey+31);
	cout << priv << endl;

    // 此时才真正获取到了公钥
    /* Verify exporting and importing public key. */
    // 压缩公钥
    secp256k1_ec_pubkey_serialize(ctx, pubkeyc, &pubkeyclen, &pubkey, SECP256K1_EC_COMPRESSED);

    string pubcom = HexStr(pubkeyc, pubkeyc+pubkeyclen-1);
	cout << pubcom << endl;


    //(gdb) p/x pubkeyc
    //$4 = {0x2, 0xb9, 0xc7, 0x7, 0x7d, 0xaa, 0xa5, 0x5a, 0xcf, 0x0, 0x4, 0x8b, 0xca, 0x3c, 0x5d, 0x4, 0xd0, 0x53, 0xa5, 0xa4, 0xe4, 0x8c, 0x32, 0xc8, 0x8e, 0x67, 0x76, 0xcc, 0xc2, 0x75, 0xc9, 0x4d, 0xaf, 0x0 <repeats 32 times>}
   
    //(gdb) p/x pubkeyc1
    //$2 = {0x4, 0xb9, 0xc7, 0x7, 0x7d, 0xaa, 0xa5, 0x5a, 0xcf, 0x0, 0x4, 0x8b, 0xca, 0x3c, 0x5d, 0x4, 0xd0, 0x53, 0xa5, 0xa4, 0xe4, 0x8c, 0x32, 0xc8, 0x8e, 0x67, 0x76, 0xcc, 0xc2, 0x75, 0xc9, 0x4d, 0xaf, 0x47, 0x3a, 0x9d, 0xbe, 0xa3, 0xfb, 0x3e, 0xbc, 0xb4, 0x37, 0x97, 0xa9, 0x58, 0x3c, 0x63, 0x4f, 0xd2, 0x5, 0xc7, 0xd8, 0x74, 0x69, 0xb0, 0xe4, 0xf2, 0xa5, 0xd3, 0xf6, 0xa7, 0x94, 0xf4, 0x24}
    // 非压缩公钥
    secp256k1_ec_pubkey_serialize(ctx, pubkeyc1, &pubkeyclen1, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    string pubuncom = HexStr(pubkeyc1, pubkeyc1+pubkeyclen1-1);
	cout << pubuncom << endl;

    memset(&pubkey, 0, sizeof(pubkey));
    secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, pubkeyclen);

    ///* Verify negation changes the key and changes it back */
    //memcpy(&pubkey_tmp, &pubkey, sizeof(pubkey));
    //secp256k1_ec_pubkey_negate(ctx, &pubkey_tmp);
    //memcmp(&pubkey_tmp, &pubkey, sizeof(pubkey));
    //secp256k1_ec_pubkey_negate(ctx, &pubkey_tmp);
    //memcmp(&pubkey_tmp, &pubkey, sizeof(pubkey));

    ///* Verify private key import and export. */
    //ec_privkey_export_der(ctx, seckey, &seckeylen, privkey, secp256k1_rand_bits(1));
    //ec_privkey_import_der(ctx, privkey2, seckey, seckeylen);
    //memcmp(privkey, privkey2, 32);


    /* Sign. */
    secp256k1_ecdsa_sign(ctx, &signature, message, privkey, NULL, NULL);

    ///* Verify. */
    //secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey);
    // 这里才是编码之后的签名
    // (gdb) p/x sig
    //$4 = {0x30, 0x45, 0x2, 0x21, 0x0, 0xcd, 0x5c, 0xf2, 0x8, 0xa4, 0xc0, 0x64, 0x19, 0xd6, 0x4d, 0xf9, 0x8b, 0xa7, 0xef, 0xcc, 0xd4, 0xf6, 0x6a, 0x7e, 0x77, 0xba, 0x4b, 0x30, 0xb9, 0x28, 0x5d, 0x50, 0x2b, 0x74, 0x8e, 0x66, 0x2a, 0x2, 0x20, 0x43, 0x21, 0x60, 0xa1, 0xac, 0xb7, 0xf2, 0x18, 0x8d, 0x38, 0x5b, 0xd, 0x6c, 0xed, 0x44, 0x1a, 0xa2, 0xdb, 0x1f, 0xfc, 0x1e, 0x6f, 0xc8, 0x8c, 0x3f, 0xd4, 0x3e, 0xd9, 0x5f, 0x56, 0x2b, 0xc7, 0x0, 0x0, 0x0}

    ///* Serialize/parse DER and verify again */
    secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature);
    memset(&signature, 0, sizeof(signature));


    string sign = HexStr(sig, sig+siglen);
	cout << sign << endl;

    //secp256k1_ecdsa_signature_parse_der(ctx, &signature, sig, siglen);

    //secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey);

    ///* Serialize/destroy/parse DER and verify again. */
    //siglen = 74;
    //secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature);
    //sig[secp256k1_rand_int(siglen)] += 1 + secp256k1_rand_int(255);
	//secp256k1_ecdsa_signature_parse_der(ctx, &signature[0], sig, siglen);
	//secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey);
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
