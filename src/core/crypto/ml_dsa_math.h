#ifndef ECLIPSE_ML_DSA_MATH_H
#define ECLIPSE_ML_DSA_MATH_H

#include <stddef.h>
#include <stdint.h>

#include "../error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* FIPS 204 ring R_q = Z_q[X] / (X^256 + 1). Educational reference routines. */
#define ECLIPSE_ML_DSA_Q UINT32_C(8380417)
#define ECLIPSE_ML_DSA_N 256u

typedef struct {
    uint32_t coefficient[ECLIPSE_ML_DSA_N];
} eclipse_ml_dsa_poly_t;

/* Results are canonical representatives in [0, q). */
uint32_t eclipse_ml_dsa_mod_q(int64_t value);
uint32_t eclipse_ml_dsa_add_q(uint32_t left, uint32_t right);
uint32_t eclipse_ml_dsa_sub_q(uint32_t left, uint32_t right);
uint32_t eclipse_ml_dsa_mul_q(uint32_t left, uint32_t right);

/* Output may alias either input. These routines do not run in constant time. */
eclipse_error_t eclipse_ml_dsa_poly_add(const eclipse_ml_dsa_poly_t *left,
                                        const eclipse_ml_dsa_poly_t *right,
                                        eclipse_ml_dsa_poly_t *out);
eclipse_error_t eclipse_ml_dsa_poly_sub(const eclipse_ml_dsa_poly_t *left,
                                        const eclipse_ml_dsa_poly_t *right,
                                        eclipse_ml_dsa_poly_t *out);
eclipse_error_t eclipse_ml_dsa_poly_mul(const eclipse_ml_dsa_poly_t *left,
                                        const eclipse_ml_dsa_poly_t *right,
                                        eclipse_ml_dsa_poly_t *out);

#ifdef __cplusplus
}
#endif

#endif
