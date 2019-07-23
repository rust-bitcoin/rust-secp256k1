#include <gmp.h>
#include <stdio.h>

int main(void) {
    mpz_t a, b;
    mpz_init(a);
    mpz_init(b);

    mpz_set_ui(a, 1);
    mpz_set_ui(b, 2);
    mpz_add(b, b, a);

    if (mpz_cmp_ui(b, 3) == 0) {
        return 0;
    }
    return -1;
}

