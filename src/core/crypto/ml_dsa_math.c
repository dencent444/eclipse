#include "ml_dsa_math.h"

uint32_t eclipse_ml_dsa_mod_q(int64_t value)
{
    int64_t result = value % (int64_t)ECLIPSE_ML_DSA_Q;
    if (result < 0) result += ECLIPSE_ML_DSA_Q;
    return (uint32_t)result;
}

uint32_t eclipse_ml_dsa_add_q(uint32_t left, uint32_t right)
{
    return (uint32_t)(((uint64_t)(left % ECLIPSE_ML_DSA_Q) +
                       (right % ECLIPSE_ML_DSA_Q)) % ECLIPSE_ML_DSA_Q);
}

uint32_t eclipse_ml_dsa_sub_q(uint32_t left, uint32_t right)
{
    uint32_t a = left % ECLIPSE_ML_DSA_Q;
    uint32_t b = right % ECLIPSE_ML_DSA_Q;
    return a >= b ? a - b : ECLIPSE_ML_DSA_Q - (b - a);
}

uint32_t eclipse_ml_dsa_mul_q(uint32_t left, uint32_t right)
{
    return (uint32_t)(((uint64_t)(left % ECLIPSE_ML_DSA_Q) *
                       (right % ECLIPSE_ML_DSA_Q)) % ECLIPSE_ML_DSA_Q);
}

eclipse_error_t eclipse_ml_dsa_poly_add(const eclipse_ml_dsa_poly_t *left,
                                        const eclipse_ml_dsa_poly_t *right,
                                        eclipse_ml_dsa_poly_t *out)
{
    if (left == NULL || right == NULL || out == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    for (size_t i = 0; i < ECLIPSE_ML_DSA_N; ++i)
        out->coefficient[i] = eclipse_ml_dsa_add_q(left->coefficient[i],
                                                    right->coefficient[i]);
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_ml_dsa_poly_sub(const eclipse_ml_dsa_poly_t *left,
                                        const eclipse_ml_dsa_poly_t *right,
                                        eclipse_ml_dsa_poly_t *out)
{
    if (left == NULL || right == NULL || out == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    for (size_t i = 0; i < ECLIPSE_ML_DSA_N; ++i)
        out->coefficient[i] = eclipse_ml_dsa_sub_q(left->coefficient[i],
                                                    right->coefficient[i]);
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_ml_dsa_poly_mul(const eclipse_ml_dsa_poly_t *left,
                                        const eclipse_ml_dsa_poly_t *right,
                                        eclipse_ml_dsa_poly_t *out)
{
    if (left == NULL || right == NULL || out == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;

    eclipse_ml_dsa_poly_t result = {0};
    for (size_t i = 0; i < ECLIPSE_ML_DSA_N; ++i) {
        for (size_t j = 0; j < ECLIPSE_ML_DSA_N; ++j) {
            uint32_t product = eclipse_ml_dsa_mul_q(left->coefficient[i],
                                                      right->coefficient[j]);
            size_t degree = i + j;
            if (degree < ECLIPSE_ML_DSA_N)
                result.coefficient[degree] =
                    eclipse_ml_dsa_add_q(result.coefficient[degree], product);
            else
                /* X^256 = -1 in R_q. */
                result.coefficient[degree - ECLIPSE_ML_DSA_N] =
                    eclipse_ml_dsa_sub_q(
                        result.coefficient[degree - ECLIPSE_ML_DSA_N], product);
        }
    }
    *out = result;
    return ECLIPSE_SUCCESS;
}
