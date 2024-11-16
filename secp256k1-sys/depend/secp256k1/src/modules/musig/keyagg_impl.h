/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_KEYAGG_IMPL_H
#define SECP256K1_MODULE_MUSIG_KEYAGG_IMPL_H

#include <string.h>

#include "keyagg.h"
#include "../../eckey.h"
#include "../../ecmult.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../util.h"

static const unsigned char rustsecp256k1_v0_11_musig_keyagg_cache_magic[4] = { 0xf4, 0xad, 0xbb, 0xdf };

/* A keyagg cache consists of
 * - 4 byte magic set during initialization to allow detecting an uninitialized
 *   object.
 * - 64 byte aggregate (and potentially tweaked) public key
 * - 64 byte "second" public key (set to the point at infinity if not present)
 * - 32 byte hash of all public keys
 * - 1 byte the parity of the internal key (if tweaked, otherwise 0)
 * - 32 byte tweak
 */
/* Requires that cache_i->pk is not infinity. */
static void rustsecp256k1_v0_11_keyagg_cache_save(rustsecp256k1_v0_11_musig_keyagg_cache *cache, const rustsecp256k1_v0_11_keyagg_cache_internal *cache_i) {
    unsigned char *ptr = cache->data;
    memcpy(ptr, rustsecp256k1_v0_11_musig_keyagg_cache_magic, 4);
    ptr += 4;
    rustsecp256k1_v0_11_ge_to_bytes(ptr, &cache_i->pk);
    ptr += 64;
    rustsecp256k1_v0_11_ge_to_bytes_ext(ptr, &cache_i->second_pk);
    ptr += 64;
    memcpy(ptr, cache_i->pks_hash, 32);
    ptr += 32;
    *ptr = cache_i->parity_acc;
    ptr += 1;
    rustsecp256k1_v0_11_scalar_get_b32(ptr, &cache_i->tweak);
}

static int rustsecp256k1_v0_11_keyagg_cache_load(const rustsecp256k1_v0_11_context* ctx, rustsecp256k1_v0_11_keyagg_cache_internal *cache_i, const rustsecp256k1_v0_11_musig_keyagg_cache *cache) {
    const unsigned char *ptr = cache->data;
    ARG_CHECK(rustsecp256k1_v0_11_memcmp_var(ptr, rustsecp256k1_v0_11_musig_keyagg_cache_magic, 4) == 0);
    ptr += 4;
    rustsecp256k1_v0_11_ge_from_bytes(&cache_i->pk, ptr);
    ptr += 64;
    rustsecp256k1_v0_11_ge_from_bytes_ext(&cache_i->second_pk, ptr);
    ptr += 64;
    memcpy(cache_i->pks_hash, ptr, 32);
    ptr += 32;
    cache_i->parity_acc = *ptr & 1;
    ptr += 1;
    rustsecp256k1_v0_11_scalar_set_b32(&cache_i->tweak, ptr, NULL);
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("KeyAgg list")||SHA256("KeyAgg list"). */
static void rustsecp256k1_v0_11_musig_keyagglist_sha256(rustsecp256k1_v0_11_sha256 *sha) {
    rustsecp256k1_v0_11_sha256_initialize(sha);

    sha->s[0] = 0xb399d5e0ul;
    sha->s[1] = 0xc8fff302ul;
    sha->s[2] = 0x6badac71ul;
    sha->s[3] = 0x07c5b7f1ul;
    sha->s[4] = 0x9701e2eful;
    sha->s[5] = 0x2a72ecf8ul;
    sha->s[6] = 0x201a4c7bul;
    sha->s[7] = 0xab148a38ul;
    sha->bytes = 64;
}

/* Computes pks_hash = tagged_hash(pk[0], ..., pk[np-1]) */
static int rustsecp256k1_v0_11_musig_compute_pks_hash(const rustsecp256k1_v0_11_context *ctx, unsigned char *pks_hash, const rustsecp256k1_v0_11_pubkey * const* pks, size_t np) {
    rustsecp256k1_v0_11_sha256 sha;
    size_t i;

    rustsecp256k1_v0_11_musig_keyagglist_sha256(&sha);
    for (i = 0; i < np; i++) {
        unsigned char ser[33];
        size_t ser_len = sizeof(ser);
        if (!rustsecp256k1_v0_11_ec_pubkey_serialize(ctx, ser, &ser_len, pks[i], SECP256K1_EC_COMPRESSED)) {
            return 0;
        }
        VERIFY_CHECK(ser_len == sizeof(ser));
        rustsecp256k1_v0_11_sha256_write(&sha, ser, sizeof(ser));
    }
    rustsecp256k1_v0_11_sha256_finalize(&sha, pks_hash);
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("KeyAgg coefficient")||SHA256("KeyAgg coefficient"). */
static void rustsecp256k1_v0_11_musig_keyaggcoef_sha256(rustsecp256k1_v0_11_sha256 *sha) {
    rustsecp256k1_v0_11_sha256_initialize(sha);

    sha->s[0] = 0x6ef02c5aul;
    sha->s[1] = 0x06a480deul;
    sha->s[2] = 0x1f298665ul;
    sha->s[3] = 0x1d1134f2ul;
    sha->s[4] = 0x56a0b063ul;
    sha->s[5] = 0x52da4147ul;
    sha->s[6] = 0xf280d9d4ul;
    sha->s[7] = 0x4484be15ul;
    sha->bytes = 64;
}

/* Compute KeyAgg coefficient which is constant 1 for the second pubkey and
 * otherwise tagged_hash(pks_hash, pk) where pks_hash is the hash of public keys.
 * second_pk is the point at infinity in case there is no second_pk. Assumes
 * that pk is not the point at infinity and that the Y-coordinates of pk and
 * second_pk are normalized. */
static void rustsecp256k1_v0_11_musig_keyaggcoef_internal(rustsecp256k1_v0_11_scalar *r, const unsigned char *pks_hash, rustsecp256k1_v0_11_ge *pk, const rustsecp256k1_v0_11_ge *second_pk) {
    VERIFY_CHECK(!rustsecp256k1_v0_11_ge_is_infinity(pk));

    if (!rustsecp256k1_v0_11_ge_is_infinity(second_pk)
          && rustsecp256k1_v0_11_ge_eq_var(pk, second_pk)) {
        rustsecp256k1_v0_11_scalar_set_int(r, 1);
    } else {
        rustsecp256k1_v0_11_sha256 sha;
        unsigned char buf[33];
        size_t buflen = sizeof(buf);
        int ret;
        rustsecp256k1_v0_11_musig_keyaggcoef_sha256(&sha);
        rustsecp256k1_v0_11_sha256_write(&sha, pks_hash, 32);
        ret = rustsecp256k1_v0_11_eckey_pubkey_serialize(pk, buf, &buflen, 1);
#ifdef VERIFY
        /* Serialization does not fail since the pk is not the point at infinity
         * (according to this function's precondition). */
        VERIFY_CHECK(ret && buflen == sizeof(buf));
#else
        (void) ret;
#endif
        rustsecp256k1_v0_11_sha256_write(&sha, buf, sizeof(buf));
        rustsecp256k1_v0_11_sha256_finalize(&sha, buf);
        rustsecp256k1_v0_11_scalar_set_b32(r, buf, NULL);
    }
}

/* Assumes that pk is not the point at infinity and that the Y-coordinates of pk
 * and cache_i->second_pk are normalized. */
static void rustsecp256k1_v0_11_musig_keyaggcoef(rustsecp256k1_v0_11_scalar *r, const rustsecp256k1_v0_11_keyagg_cache_internal *cache_i, rustsecp256k1_v0_11_ge *pk) {
    rustsecp256k1_v0_11_musig_keyaggcoef_internal(r, cache_i->pks_hash, pk, &cache_i->second_pk);
}

typedef struct {
    const rustsecp256k1_v0_11_context *ctx;
    /* pks_hash is the hash of the public keys */
    unsigned char pks_hash[32];
    const rustsecp256k1_v0_11_pubkey * const* pks;
    rustsecp256k1_v0_11_ge second_pk;
} rustsecp256k1_v0_11_musig_pubkey_agg_ecmult_data;

/* Callback for batch EC multiplication to compute keyaggcoef_0*P0 + keyaggcoef_1*P1 + ...  */
static int rustsecp256k1_v0_11_musig_pubkey_agg_callback(rustsecp256k1_v0_11_scalar *sc, rustsecp256k1_v0_11_ge *pt, size_t idx, void *data) {
    rustsecp256k1_v0_11_musig_pubkey_agg_ecmult_data *ctx = (rustsecp256k1_v0_11_musig_pubkey_agg_ecmult_data *) data;
    int ret;
    ret = rustsecp256k1_v0_11_pubkey_load(ctx->ctx, pt, ctx->pks[idx]);
#ifdef VERIFY
    /* pubkey_load can't fail because the same pks have already been loaded in
     * `musig_compute_pks_hash` (and we test this). */
    VERIFY_CHECK(ret);
#else
    (void) ret;
#endif
    rustsecp256k1_v0_11_musig_keyaggcoef_internal(sc, ctx->pks_hash, pt, &ctx->second_pk);
    return 1;
}

int rustsecp256k1_v0_11_musig_pubkey_agg(const rustsecp256k1_v0_11_context* ctx, rustsecp256k1_v0_11_xonly_pubkey *agg_pk, rustsecp256k1_v0_11_musig_keyagg_cache *keyagg_cache, const rustsecp256k1_v0_11_pubkey * const* pubkeys, size_t n_pubkeys) {
    rustsecp256k1_v0_11_musig_pubkey_agg_ecmult_data ecmult_data;
    rustsecp256k1_v0_11_gej pkj;
    rustsecp256k1_v0_11_ge pkp;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    if (agg_pk != NULL) {
        memset(agg_pk, 0, sizeof(*agg_pk));
    }
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(n_pubkeys > 0);

    ecmult_data.ctx = ctx;
    ecmult_data.pks = pubkeys;

    rustsecp256k1_v0_11_ge_set_infinity(&ecmult_data.second_pk);
    for (i = 1; i < n_pubkeys; i++) {
        if (rustsecp256k1_v0_11_memcmp_var(pubkeys[0], pubkeys[i], sizeof(*pubkeys[0])) != 0) {
            rustsecp256k1_v0_11_ge pk;
            if (!rustsecp256k1_v0_11_pubkey_load(ctx, &pk, pubkeys[i])) {
                return 0;
            }
            ecmult_data.second_pk = pk;
            break;
        }
    }

    if (!rustsecp256k1_v0_11_musig_compute_pks_hash(ctx, ecmult_data.pks_hash, pubkeys, n_pubkeys)) {
        return 0;
    }
    /* TODO: actually use optimized ecmult_multi algorithms by providing a
     * scratch space */
    if (!rustsecp256k1_v0_11_ecmult_multi_var(&ctx->error_callback, NULL, &pkj, NULL, rustsecp256k1_v0_11_musig_pubkey_agg_callback, (void *) &ecmult_data, n_pubkeys)) {
        /* In order to reach this line with the current implementation of
         * ecmult_multi_var one would need to provide a callback that can
         * fail. */
        return 0;
    }
    rustsecp256k1_v0_11_ge_set_gej(&pkp, &pkj);
    rustsecp256k1_v0_11_fe_normalize_var(&pkp.y);
    /* The resulting public key is infinity with negligible probability */
    VERIFY_CHECK(!rustsecp256k1_v0_11_ge_is_infinity(&pkp));
    if (keyagg_cache != NULL) {
        rustsecp256k1_v0_11_keyagg_cache_internal cache_i = { 0 };
        cache_i.pk = pkp;
        cache_i.second_pk = ecmult_data.second_pk;
        memcpy(cache_i.pks_hash, ecmult_data.pks_hash, sizeof(cache_i.pks_hash));
        rustsecp256k1_v0_11_keyagg_cache_save(keyagg_cache, &cache_i);
    }

    if (agg_pk != NULL) {
        rustsecp256k1_v0_11_extrakeys_ge_even_y(&pkp);
        rustsecp256k1_v0_11_xonly_pubkey_save(agg_pk, &pkp);
    }
    return 1;
}

int rustsecp256k1_v0_11_musig_pubkey_get(const rustsecp256k1_v0_11_context* ctx, rustsecp256k1_v0_11_pubkey *agg_pk, const rustsecp256k1_v0_11_musig_keyagg_cache *keyagg_cache) {
    rustsecp256k1_v0_11_keyagg_cache_internal cache_i;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(agg_pk != NULL);
    memset(agg_pk, 0, sizeof(*agg_pk));
    ARG_CHECK(keyagg_cache != NULL);

    if (!rustsecp256k1_v0_11_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    rustsecp256k1_v0_11_pubkey_save(agg_pk, &cache_i.pk);
    return 1;
}

static int rustsecp256k1_v0_11_musig_pubkey_tweak_add_internal(const rustsecp256k1_v0_11_context* ctx, rustsecp256k1_v0_11_pubkey *output_pubkey, rustsecp256k1_v0_11_musig_keyagg_cache *keyagg_cache, const unsigned char *tweak32, int xonly) {
    rustsecp256k1_v0_11_keyagg_cache_internal cache_i;
    int overflow = 0;
    rustsecp256k1_v0_11_scalar tweak;

    VERIFY_CHECK(ctx != NULL);
    if (output_pubkey != NULL) {
        memset(output_pubkey, 0, sizeof(*output_pubkey));
    }
    ARG_CHECK(keyagg_cache != NULL);
    ARG_CHECK(tweak32 != NULL);

    if (!rustsecp256k1_v0_11_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    rustsecp256k1_v0_11_scalar_set_b32(&tweak, tweak32, &overflow);
    if (overflow) {
        return 0;
    }
    if (xonly && rustsecp256k1_v0_11_extrakeys_ge_even_y(&cache_i.pk)) {
        cache_i.parity_acc ^= 1;
        rustsecp256k1_v0_11_scalar_negate(&cache_i.tweak, &cache_i.tweak);
    }
    rustsecp256k1_v0_11_scalar_add(&cache_i.tweak, &cache_i.tweak, &tweak);
    if (!rustsecp256k1_v0_11_eckey_pubkey_tweak_add(&cache_i.pk, &tweak)) {
        return 0;
    }
    /* eckey_pubkey_tweak_add fails if cache_i.pk is infinity */
    VERIFY_CHECK(!rustsecp256k1_v0_11_ge_is_infinity(&cache_i.pk));
    rustsecp256k1_v0_11_keyagg_cache_save(keyagg_cache, &cache_i);
    if (output_pubkey != NULL) {
        rustsecp256k1_v0_11_pubkey_save(output_pubkey, &cache_i.pk);
    }
    return 1;
}

int rustsecp256k1_v0_11_musig_pubkey_ec_tweak_add(const rustsecp256k1_v0_11_context* ctx, rustsecp256k1_v0_11_pubkey *output_pubkey, rustsecp256k1_v0_11_musig_keyagg_cache *keyagg_cache, const unsigned char *tweak32) {
    return rustsecp256k1_v0_11_musig_pubkey_tweak_add_internal(ctx, output_pubkey, keyagg_cache, tweak32, 0);
}

int rustsecp256k1_v0_11_musig_pubkey_xonly_tweak_add(const rustsecp256k1_v0_11_context* ctx, rustsecp256k1_v0_11_pubkey *output_pubkey, rustsecp256k1_v0_11_musig_keyagg_cache *keyagg_cache, const unsigned char *tweak32) {
    return rustsecp256k1_v0_11_musig_pubkey_tweak_add_internal(ctx, output_pubkey, keyagg_cache, tweak32, 1);
}

#endif
