/** @file ext.c
 * Ethereum extensions to libecp256k1
 * @authors:
 *   Arkadiy Paronyan <arkady@ethdev.com>
 * @date 2015
 */

#include "src/secp256k1.c"
// todo[dvdplm] Should probably follow the naming convention of `rustsecp256k1_v0_1_0_ec_privkey_inverse()`
/// Returns inverse (1 / n) of secret key `seckey`
int secp256k1_ec_privkey_inverse(const rustsecp256k1_v0_1_0_context* ctx, unsigned char *inversed, const unsigned char* seckey) {
	rustsecp256k1_v0_1_0_scalar inv;
	rustsecp256k1_v0_1_0_scalar sec;
	int ret = 0;
	int overflow = 0;
	VERIFY_CHECK(ctx != NULL);
	ARG_CHECK(inversed != NULL);
	ARG_CHECK(seckey != NULL);

	rustsecp256k1_v0_1_0_scalar_set_b32(&sec, seckey, NULL);

	ret = !overflow;
	if (ret) {
		memset(inversed, 0, 32);
		rustsecp256k1_v0_1_0_scalar_inverse(&inv, &sec);
		rustsecp256k1_v0_1_0_scalar_get_b32(inversed, &inv);
	}

	rustsecp256k1_v0_1_0_scalar_clear(&inv);
	rustsecp256k1_v0_1_0_scalar_clear(&sec);
	return ret;
}
