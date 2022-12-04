#include <stddef.h>

// Note that this symbol is NOT linked with the rest of the library.
// The name is sort of unique in case it accidentally gets linked.
const size_t rust_secp256k1_private_max_align = _Alignof(max_align_t);
