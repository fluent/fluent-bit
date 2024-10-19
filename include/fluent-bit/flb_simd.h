/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_SIMD_H
#define FLB_SIMD_H

#include <stdint.h>
#include <stdbool.h>

#include <fluent-bit/flb_info.h>
#define UINT64CONST(x) (x##ULL)

/* Only enable SIMD support if it has not been explicity disabled */
#ifdef FLB_HAVE_SIMD

#if (defined(__x86_64__) || defined(_M_AMD64))
/*
 * SSE2 instructions are part of the spec for the 64-bit x86 ISA. We assume
 * that compilers targeting this architecture understand SSE2 intrinsics.
 *
 * We use emmintrin.h rather than the comprehensive header immintrin.h in
 * order to exclude extensions beyond SSE2. This is because MSVC, at least,
 * will allow the use of intrinsics that haven't been enabled at compile
 * time.
 */
#include <emmintrin.h>
#define FLB_SIMD_SSE2

typedef __m128i flb_vector8;
typedef __m128i flb_vector32;

#elif defined(__aarch64__) && defined(__ARM_NEON)
/*
 * We use the Neon instructions if the compiler provides access to them (as
 * indicated by __ARM_NEON) and we are on aarch64.  While Neon support is
 * technically optional for aarch64, it appears that all available 64-bit
 * hardware does have it.  Neon exists in some 32-bit hardware too, but we
 * could not realistically use it there without a run-time check, which seems
 * not worth the trouble for now.
 */
#include <arm_neon.h>
#define FLB_SIMD_NEON
typedef uint8x16_t flb_vector8;
typedef uint32x4_t flb_vector32;

#else
/*
 * If no SIMD instructions are available, we can in some cases emulate vector
 * operations using bitwise operations on unsigned integers.  Note that many
 * of the functions in this file presently do not have non-SIMD
 * implementations.  In particular, none of the functions involving Vector32
 * are implemented without SIMD since it's likely not worthwhile to represent
 * two 32-bit integers using a uint64.
 */
#define FLB_SIMD_NONE
typedef uint64_t flb_vector8;
#endif

#else
#define FLB_SIMD_NONE

/* Original code aims to handle this as a uint64_t to search */
typedef uint8_t flb_vector8;
#endif /* FLB_SIMD_DISABLED */

/* element-wise comparisons to a scalar */
static inline bool flb_vector8_has(const flb_vector8 v, const uint8_t c);
static inline bool flb_vector8_has_zero(const flb_vector8 v);
static inline bool flb_vector8_has_le(const flb_vector8 v, const uint8_t c);
static inline bool flb_vector8_is_highbit_set(const flb_vector8 v);

/*
 * Load a chunk of memory into the given vector.
 */
static inline void flb_vector8_load(flb_vector8 *v, const uint8_t *s)
{
#if defined(FLB_SIMD_SSE2)
	*v = _mm_loadu_si128((const __m128i *) s);
#elif defined(FLB_SIMD_NEON)
	*v = vld1q_u8(s);
#else
	memset(v, 0, sizeof(flb_vector8));
#endif
}

/*
 * Convenience function equivalent to vector8_has(v, 0)
 */
static inline bool flb_vector8_has_zero(const flb_vector8 v)
{
#if defined(FLB_SIMD_NONE)
	/*
	 * We cannot call vector8_has() here, because that would lead to a
	 * circular definition.
	 */
	return flb_vector8_has_le(v, 0);
#else
	return flb_vector8_has(v, 0);
#endif
}


/*
 * Return the result of subtracting the respective elements of the input
 * vectors using saturation (i.e., if the operation would yield a value less
 * than zero, zero is returned instead).  For more information on saturation
 * arithmetic, see https://en.wikipedia.org/wiki/Saturation_arithmetic
 */
#ifndef FLB_SIMD_NONE
static inline flb_vector8 flb_vector8_ssub(const flb_vector8 v1, const flb_vector8 v2)
{
#ifdef FLB_SIMD_SSE2
	return _mm_subs_epu8(v1, v2);
#elif defined(FLB_SIMD_NEON)
	return vqsubq_u8(v1, v2);
#endif
}
#endif /* ! FLB_SIMD_NONE */

/*
 * Return a vector with all bits set in each lane where the corresponding
 * lanes in the inputs are equal.
 */
#ifndef FLB_SIMD_NONE
static inline flb_vector8 flb_vector8_eq(const flb_vector8 v1, const flb_vector8 v2)
{
#ifdef FLB_SIMD_SSE2
	return _mm_cmpeq_epi8(v1, v2);
#elif defined(FLB_SIMD_NEON)
	return vceqq_u8(v1, v2);
#endif
}
#endif /* ! FLB_SIMD_NONE */

#ifndef FLB_SIMD_NONE
static inline flb_vector32 flb_vector32_eq(const flb_vector32 v1, const flb_vector32 v2)
{
#ifdef FLB_SIMD_SSE2
	return _mm_cmpeq_epi32(v1, v2);
#elif defined(FLB_SIMD_NEON)
	return vceqq_u32(v1, v2);
#endif
}
#endif /* ! FLB_SIMD_NONE */

/*
 * Create a vector with all elements set to the same value.
 */
static inline flb_vector8 flb_vector8_broadcast(const uint8_t c)
{
#if defined(FLB_SIMD_SSE2)
	return _mm_set1_epi8(c);
#elif defined(FLB_SIMD_NEON)
	return vdupq_n_u8(c);
#else
	return ~UINT64CONST(0) / 0xFF * c;
#endif
}

/*
 * Return true if the high bit of any element is set
 */
static inline bool flb_vector8_is_highbit_set(const flb_vector8 v)
{
#ifdef FLB_SIMD_SSE2
	return _mm_movemask_epi8(v) != 0;
#elif defined(FLB_SIMD_NEON)
	return vmaxvq_u8(v) > 0x7F;
#else
	return v & flb_vector8_broadcast(0x80);
#endif
}

/*
 * Return true if any elements in the vector are equal to the given scalar.
 */
static inline bool flb_vector8_has(const flb_vector8 v, const uint8_t c)
{
	bool result = false;

#if defined(FLB_SIMD_NONE)
	 return flb_vector8_has_zero(v ^ flb_vector8_broadcast(c));
#else
	result = flb_vector8_is_highbit_set(flb_vector8_eq(v, flb_vector8_broadcast(c)));
#endif

	return result;
}

static inline bool flb_vector8_has_le(const flb_vector8 v, const uint8_t c)
{
	bool result = false;

#if defined(FLB_SIMD_NONE)
	/*
	 *  To find bytes <= c, we can use bitwise operations to find bytes < c+1,
	 *  but it only works if c+1 <= 128 and if the highest bit in v is not set.
	 *
	 *  Adapted from
	 *
	 *    https://graphics.stanford.edu/~seander/bithacks.html#HasLessInWord
	 */
	if ((int64_t) v >= 0 && c < 0x80) {
		result = (v - flb_vector8_broadcast(c + 1)) & ~v & flb_vector8_broadcast(0x80);
	}
	else {
		size_t i;
			for (i = 0; i < sizeof(flb_vector8); i++) {
			if (((const uint8_t *) &v)[i] <= c) {
				result = true;
				break;
			}
		}
	}

	return result;
#else
	/*
	 * Use saturating subtraction to find bytes <= c, which will present as
	 * NUL bytes.  This approach is a workaround for the lack of unsigned
	 * comparison instructions on some architectures.
	 */
	result = flb_vector8_has_zero(flb_vector8_ssub(v, flb_vector8_broadcast(c)));
#endif

	return result;
}

static inline char *flb_simd_info()
{
	#ifdef FLB_HAVE_SIMD
		#if defined(FLB_SIMD_SSE2)
			return "SSE2";
		#elif defined(FLB_SIMD_NEON)
			return "NEON";
		#elif defined(FLB_SIMD_NONE)
			return "none";
		#else
			return "unknown";
		#endif
	#else
        return "disabled";
    #endif
}

#endif /* FLB_HAVE_SIMD */
