#include "ml_dsa_math.h"
#include "../log.h"

/* Educational arithmetic for q = 8,380,417. These routines explain the
 * ring used by ML-DSA; OpenSSL signing does not call them. */

/* C's remainder may be negative, so map it to the canonical range [0,q). */
static uint32_t mod_q_raw(int64_t value)
{
    int64_t result = value % (int64_t)ECLIPSE_ML_DSA_Q;
    if (result < 0) result += ECLIPSE_ML_DSA_Q;
    return (uint32_t)result;
}

/* Widen before addition so the intermediate cannot overflow uint32_t. */
static uint32_t add_q_raw(uint32_t left, uint32_t right)
{
    return (uint32_t)(((uint64_t)(left % ECLIPSE_ML_DSA_Q) +
                       (right % ECLIPSE_ML_DSA_Q)) % ECLIPSE_ML_DSA_Q);
}

/* Add q only when subtraction would otherwise become negative. */
static uint32_t sub_q_raw(uint32_t left, uint32_t right)
{
    uint32_t a = left % ECLIPSE_ML_DSA_Q;
    uint32_t b = right % ECLIPSE_ML_DSA_Q;
    return a >= b ? a - b : ECLIPSE_ML_DSA_Q - (b - a);
}

/* Widen before multiplication; q^2 fits in uint64_t. */
static uint32_t mul_q_raw(uint32_t left, uint32_t right)
{
    return (uint32_t)(((uint64_t)(left % ECLIPSE_ML_DSA_Q) *
                       (right % ECLIPSE_ML_DSA_Q)) % ECLIPSE_ML_DSA_Q);
}

/* Public wrapper for canonical reduction of a possibly negative integer. */
uint32_t eclipse_ml_dsa_mod_q(int64_t value)
{
    uint32_t result = mod_q_raw(value);
    ECLIPSE_LOG_INFO(5, "integer reduced modulo q");
    return result;
}

/* Public modular addition; the raw helper keeps polynomial loops log-free. */
uint32_t eclipse_ml_dsa_add_q(uint32_t left, uint32_t right)
{
    uint32_t result = add_q_raw(left, right);
    ECLIPSE_LOG_INFO(5, "modular addition completed");
    return result;
}

/* Public modular subtraction with a canonical [0,q) result. */
uint32_t eclipse_ml_dsa_sub_q(uint32_t left, uint32_t right)
{
    uint32_t result = sub_q_raw(left, right);
    ECLIPSE_LOG_INFO(5, "modular subtraction completed");
    return result;
}

/* Public modular multiplication using a widened intermediate. */
uint32_t eclipse_ml_dsa_mul_q(uint32_t left, uint32_t right)
{
    uint32_t result = mul_q_raw(left, right);
    ECLIPSE_LOG_INFO(5, "modular multiplication completed");
    return result;
}

/* Add matching coefficients independently. In-place output is allowed
 * because each coefficient is read before its own destination is written. */
eclipse_error_t eclipse_ml_dsa_poly_add(const eclipse_ml_dsa_poly_t *left,
                                        const eclipse_ml_dsa_poly_t *right,
                                        eclipse_ml_dsa_poly_t *out)
{
    if (left == NULL || right == NULL || out == NULL) {
        ECLIPSE_LOG_WARNING("polynomial addition rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    for (size_t i = 0; i < ECLIPSE_ML_DSA_N; ++i)
        out->coefficient[i] = add_q_raw(left->coefficient[i],
                                        right->coefficient[i]);
    ECLIPSE_LOG_INFO(5, "polynomial addition completed");
    return ECLIPSE_SUCCESS;
}

/* Subtract matching coefficients under the same safe aliasing rule as add. */
eclipse_error_t eclipse_ml_dsa_poly_sub(const eclipse_ml_dsa_poly_t *left,
                                        const eclipse_ml_dsa_poly_t *right,
                                        eclipse_ml_dsa_poly_t *out)
{
    if (left == NULL || right == NULL || out == NULL) {
        ECLIPSE_LOG_WARNING("polynomial subtraction rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    for (size_t i = 0; i < ECLIPSE_ML_DSA_N; ++i)
        out->coefficient[i] = sub_q_raw(left->coefficient[i],
                                        right->coefficient[i]);
    ECLIPSE_LOG_INFO(5, "polynomial subtraction completed");
    return ECLIPSE_SUCCESS;
}

/* Schoolbook multiplication in Z_q[X]/(X^256 + 1). Terms at degree >=256
 * wrap to degree-256 with a minus sign because X^256 = -1. This is for study,
 * is quadratic in 256 coefficients, and is not constant-time cryptography. */
eclipse_error_t eclipse_ml_dsa_poly_mul(const eclipse_ml_dsa_poly_t *left,
                                        const eclipse_ml_dsa_poly_t *right,
                                        eclipse_ml_dsa_poly_t *out)
{
    if (left == NULL || right == NULL || out == NULL) {
        ECLIPSE_LOG_WARNING("polynomial multiplication rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }

    eclipse_ml_dsa_poly_t result = {0};
    for (size_t i = 0; i < ECLIPSE_ML_DSA_N; ++i) {
        for (size_t j = 0; j < ECLIPSE_ML_DSA_N; ++j) {
            uint32_t product = mul_q_raw(left->coefficient[i],
                                         right->coefficient[j]);
            size_t degree = i + j;
            if (degree < ECLIPSE_ML_DSA_N)
                result.coefficient[degree] =
                    add_q_raw(result.coefficient[degree], product);
            else
                /* X^256 = -1 in R_q. */
                result.coefficient[degree - ECLIPSE_ML_DSA_N] =
                    sub_q_raw(
                        result.coefficient[degree - ECLIPSE_ML_DSA_N], product);
        }
    }
    *out = result;
    ECLIPSE_LOG_INFO(5, "polynomial multiplication completed");
    return ECLIPSE_SUCCESS;
}
