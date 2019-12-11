#include <stdlib.h>
#include <stdint.h>
#include "org_bitcoin_Secp256k1Context.h"
#include "include/secp256k1.h"

SECP256K1_API jlong JNICALL Java_org_bitcoin_Secp256k1Context_rustsecp256k1_v0_1_1_1init_1context
  (JNIEnv* env, jclass classObject)
{
  rustsecp256k1_v0_1_1_context *ctx = rustsecp256k1_v0_1_1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  (void)classObject;(void)env;

  return (uintptr_t)ctx;
}

