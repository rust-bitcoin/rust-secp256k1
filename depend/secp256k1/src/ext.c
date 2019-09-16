/** @file ext.c
 * Ethereum extensions to libecp256k1
 * @authors:
 *   Arkadiy Paronyan <arkady@ethdev.com>
 * @date 2015
 */

#include "src/secp256k1.c"


static int ecdh_hash_function_raw(unsigned char *output, const unsigned char *x, const unsigned char *y, void *data) {
    (void)y;
    (void)data;

    memcpy(output, x, 32);

    return 1;
}

const secp256k1_ecdh_hash_function secp256k1_ecdh_hash_function_raw = ecdh_hash_function_raw;

int secp256k1_ecdh_raw(const secp256k1_context* ctx, unsigned char *result, const secp256k1_pubkey *point, const unsigned char *scalar)
{
    return secp256k1_ecdh(ctx, result, point, scalar, secp256k1_ecdh_hash_function_raw, NULL);
}

/// Returns inverse (1 / n) of secret key `seckey`
int secp256k1_ec_privkey_inverse(const secp256k1_context* ctx, unsigned char *inversed, const unsigned char* seckey) {
	secp256k1_scalar inv;
	secp256k1_scalar sec;
	int ret = 0;
	int overflow = 0;
	VERIFY_CHECK(ctx != NULL);
	ARG_CHECK(inversed != NULL);
	ARG_CHECK(seckey != NULL);

	secp256k1_scalar_set_b32(&sec, seckey, NULL);
	ret = !overflow;
	if (ret) {
		memset(inversed, 0, 32);
		secp256k1_scalar_inverse(&inv, &sec);
		secp256k1_scalar_get_b32(inversed, &inv);
	}

	secp256k1_scalar_clear(&inv);
	secp256k1_scalar_clear(&sec);
	return ret;
}
