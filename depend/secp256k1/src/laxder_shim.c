/* Bitcoin secp256k1 bindings
 * Written in 2015 by
 *   Andrew Poelstra
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to
 * the public domain worldwide. This software is distributed without
 * any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "contrib/lax_der_parsing.h"

int secp256k1_ecdsa_signature_parse_der_lax_(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    return secp256k1_ecdsa_signature_parse_der_lax(ctx, sig, input, inputlen);
}


