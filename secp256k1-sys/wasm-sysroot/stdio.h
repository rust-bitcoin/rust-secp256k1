#include <stddef.h>
#define alignof(type) offsetof (struct { char c; type member; }, member)

extern const unsigned char WASM32_INT_SIZE = sizeof(int);
extern const unsigned char WASM32_INT_ALIGN = alignof(int);

extern const unsigned char WASM32_UNSIGNED_INT_SIZE = sizeof(unsigned int);
extern const unsigned char WASM32_UNSIGNED_INT_ALIGN = alignof(unsigned int);

extern const unsigned char WASM32_SIZE_T_SIZE = sizeof(size_t);
extern const unsigned char WASM32_SIZE_T_ALIGN = alignof(size_t);

extern const unsigned char WASM32_UNSIGNED_CHAR_SIZE = sizeof(unsigned char);
extern const unsigned char WASM32_UNSIGNED_CHAR_ALIGN = alignof(unsigned char);

extern const unsigned char WASM32_PTR_SIZE = sizeof(void*);
extern const unsigned char WASM32_PTR_ALIGN = alignof(void*);