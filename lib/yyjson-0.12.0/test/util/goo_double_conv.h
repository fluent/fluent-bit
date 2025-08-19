#ifndef goo_double_conv_h
#define goo_double_conv_h

/// IEEE 754 floating-point binary representation detection.
/// The functions below may produce incorrect results if `GOO_HAS_IEEE_754 == 0`.
#include <float.h>
#if defined(__STDC_IEC_559__) || defined(__STDC_IEC_60559_BFP__)
#   define GOO_HAS_IEEE_754 1
#elif FLT_RADIX == 2 && \
    FLT_MANT_DIG == 24 && FLT_DIG == 6 && \
    FLT_MIN_EXP == -125 && FLT_MAX_EXP == 128 && \
    FLT_MIN_10_EXP == -37 && FLT_MAX_10_EXP == 38 && \
    DBL_MANT_DIG == 53 && DBL_DIG == 15 && \
    DBL_MIN_EXP == -1021 && DBL_MAX_EXP == 1024 && \
    DBL_MIN_10_EXP == -307 && DBL_MAX_10_EXP == 308
#   define GOO_HAS_IEEE_754 1
#else
#   define GOO_HAS_IEEE_754 0
#endif

/// Number to string format.
typedef enum {
    /// Shortest string, `prec` is ignored.
    GOO_FMT_SHORTEST,
    /// Fixed-point notation, `prec` is the number of digits after decimal point.
    GOO_FMT_FIXED,
    /// Precision notation, `prec` is the number of significant digits.
    GOO_FMT_PRECISION,
    /// Exponential notation, `prec` is the number of digits after decimal point.
    GOO_FMT_EXPONENTIAL
} goo_fmt;

/// Write double number to string (null-terminated).
/// The string format follows the ECMAScript spec with the following changes:
/// 1. Keep the negative sign of `-0.0` to preserve input information.
/// 2. Keep decimal point to indicate the number is floating point.
/// 3. Remove positive sign of exponent part.
/// @param val The double value.
/// @param fmt The output format (pass NULL for shortest format).
/// @param prec The precision value for the `fmt`.
/// @param buf The string buffer for the output.
/// @param len The string buffer length.
/// @return The output string length, or 0 if failed.
int goo_dtoa(double val, goo_fmt fmt, int prec, char *buf, int len);
int goo_ftoa(float  val, goo_fmt fmt, int prec, char *buf, int len);

/// Read double number from string.
/// @param str The string containing a double number.
/// @param len The string length.
/// @param proc The processed length, or 0 if failed (pass NULL to ignore).
/// @return The double value, or 0.0 if failed.
double goo_strtod(const char *str, int len, int *proc);
float  goo_strtof(const char *str, int len, int *proc);

#endif /* goo_double_conv_h */
