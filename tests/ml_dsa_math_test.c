/* Reference ring arithmetic tests include edge values and polynomial cases;
 * they do not validate or replace OpenSSL's ML-DSA implementation. */
#include "crypto/ml_dsa_math.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #test); \
    exit(EXIT_FAILURE); \
} } while (0)

int main(void)
{
    CHECK(eclipse_ml_dsa_mod_q(-1) == ECLIPSE_ML_DSA_Q - 1);
    CHECK(eclipse_ml_dsa_mod_q((int64_t)ECLIPSE_ML_DSA_Q) == 0);
    CHECK(eclipse_ml_dsa_mod_q(INT64_MIN) < ECLIPSE_ML_DSA_Q);
    CHECK(eclipse_ml_dsa_add_q(ECLIPSE_ML_DSA_Q - 1, 1) == 0);
    CHECK(eclipse_ml_dsa_sub_q(0, 1) == ECLIPSE_ML_DSA_Q - 1);
    CHECK(eclipse_ml_dsa_mul_q(ECLIPSE_ML_DSA_Q - 1,
                                ECLIPSE_ML_DSA_Q - 1) == 1);

    eclipse_ml_dsa_poly_t x = {0};
    eclipse_ml_dsa_poly_t high = {0};
    eclipse_ml_dsa_poly_t product = {0};
    x.coefficient[1] = 1;
    high.coefficient[ECLIPSE_ML_DSA_N - 1] = 1;
    CHECK(eclipse_ml_dsa_poly_mul(&x, &high, &product) == ECLIPSE_SUCCESS);
    /* X * X^255 = X^256 = -1 in the quotient ring. */
    CHECK(product.coefficient[0] == ECLIPSE_ML_DSA_Q - 1);
    for (size_t i = 1; i < ECLIPSE_ML_DSA_N; ++i)
        CHECK(product.coefficient[i] == 0);

    eclipse_ml_dsa_poly_t one_plus_x = x;
    eclipse_ml_dsa_poly_t one_plus_high = high;
    one_plus_x.coefficient[0] = 1;
    one_plus_high.coefficient[0] = 1;
    CHECK(eclipse_ml_dsa_poly_mul(&one_plus_x, &one_plus_high,
                                  &product) == ECLIPSE_SUCCESS);
    /* (1 + X)(1 + X^255) = X + X^255 after X^256 = -1. */
    CHECK(product.coefficient[0] == 0);
    CHECK(product.coefficient[1] == 1);
    CHECK(product.coefficient[ECLIPSE_ML_DSA_N - 1] == 1);

    eclipse_ml_dsa_poly_t sum = {0};
    CHECK(eclipse_ml_dsa_poly_add(&x, &high, &sum) == ECLIPSE_SUCCESS);
    CHECK(sum.coefficient[1] == 1);
    CHECK(sum.coefficient[ECLIPSE_ML_DSA_N - 1] == 1);
    CHECK(eclipse_ml_dsa_poly_sub(&sum, &x, &sum) == ECLIPSE_SUCCESS);
    CHECK(memcmp(&sum, &high, sizeof(sum)) == 0);
    CHECK(eclipse_ml_dsa_poly_mul(&x, &high, &x) == ECLIPSE_SUCCESS);
    CHECK(x.coefficient[0] == ECLIPSE_ML_DSA_Q - 1);
    CHECK(eclipse_ml_dsa_poly_add(NULL, &high, &sum) ==
          ECLIPSE_ERROR_NULL_POINTER);

    puts("ML-DSA math tests passed");
    return EXIT_SUCCESS;
}
