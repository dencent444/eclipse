#ifndef ERROR_H
#define ERROR_H


/* Shared API status codes. ECLIPSE_SUCCESS means the operation ran; callers
 * must still inspect a separate bool when checking a signature or commitment.
 * Invalid input and provider/I/O failures remain distinguishable. */
typedef enum {
    ECLIPSE_SUCCESS = 0,
    ECLIPSE_ERROR_INVALID_ARGUMENT,
    ECLIPSE_ERROR_NULL_POINTER,
    ECLIPSE_ERROR_OUT_OF_MEMORY,
    ECLIPSE_ERROR_BUFFER_TOO_SMALL,
    ECLIPSE_ERROR_CRYPTO_FAILURE,
    ECLIPSE_ERROR_IO,
} eclipse_error_t;

#endif // ERROR_H
