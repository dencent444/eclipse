#ifndef ECLIPSE_PLATFORM_H
#define ECLIPSE_PLATFORM_H

#include <limits.h>
#include <stdint.h>

/* These values are selected by the TARGET compiler for each binary (or each
 * slice of a universal binary). Do not use uname or the build host here: a
 * cross-compiled binary must describe the architecture it actually targets.
 * Unknown CPUs use the same portable C implementation as known CPUs. */
#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
#define ECLIPSE_TARGET_ARCH "x86_64"
#elif defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
#define ECLIPSE_TARGET_ARCH "aarch64"
#elif defined(__i386__) || defined(_M_IX86)
#define ECLIPSE_TARGET_ARCH "x86"
#elif defined(__arm__) || defined(_M_ARM)
#define ECLIPSE_TARGET_ARCH "arm"
#elif defined(__riscv) && defined(__riscv_xlen) && __riscv_xlen == 64
#define ECLIPSE_TARGET_ARCH "riscv64"
#elif defined(__riscv) && defined(__riscv_xlen) && __riscv_xlen == 32
#define ECLIPSE_TARGET_ARCH "riscv32"
#elif defined(__powerpc64__) || defined(__ppc64__)
#define ECLIPSE_TARGET_ARCH "powerpc64"
#elif defined(__s390x__)
#define ECLIPSE_TARGET_ARCH "s390x"
#else
#define ECLIPSE_TARGET_ARCH "unknown"
#endif

#if defined(__linux__)
#define ECLIPSE_TARGET_OS "Linux"
#elif defined(__APPLE__) && defined(__MACH__)
#define ECLIPSE_TARGET_OS "macOS"
#elif defined(__FreeBSD__)
#define ECLIPSE_TARGET_OS "FreeBSD"
#elif defined(__NetBSD__)
#define ECLIPSE_TARGET_OS "NetBSD"
#elif defined(__OpenBSD__)
#define ECLIPSE_TARGET_OS "OpenBSD"
#else
#define ECLIPSE_TARGET_OS "other POSIX"
#endif

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ECLIPSE_TARGET_BYTE_ORDER "little"
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
      __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ECLIPSE_TARGET_BYTE_ORDER "big"
#else
#define ECLIPSE_TARGET_BYTE_ORDER "unknown"
#endif

/* Protocol encodings operate on octets and exact 64-bit integers. Pointer
 * width is intentionally unrestricted: both 32-bit and 64-bit builds use the
 * same canonical wire format. */
_Static_assert(CHAR_BIT == 8, "Eclipse protocol requires 8-bit bytes");
_Static_assert(sizeof(uint64_t) == 8, "Eclipse protocol requires uint64_t");

#define ECLIPSE_TARGET_POINTER_BITS (sizeof(void *) * CHAR_BIT)

#endif
