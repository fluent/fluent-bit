/*
Copyright Rene Rivera 2017
Distributed under the Boost Software License, Version 1.0.
(See accompanying file LICENSE_1_0.txt or copy at
http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef MSGPACK_PREDEF_WORKAROUND_H
#define MSGPACK_PREDEF_WORKAROUND_H

/*`
[heading `MSGPACK_PREDEF_WORKAROUND`]

``
MSGPACK_PREDEF_WORKAROUND(symbol,comp,major,minor,patch)
``

Usage:

``
#if MSGPACK_PREDEF_WORKAROUND(MSGPACK_COMP_CLANG,<,3,0,0)
    // Workaround for old clang compilers..
#endif
``

Defines a comparison against two version numbers that depends on the definion
of `MSGPACK_STRICT_CONFIG`. When `MSGPACK_STRICT_CONFIG` is defined this will expand
to a value convertible to `false`. Which has the effect of disabling all code
conditionally guarded by `MSGPACK_PREDEF_WORKAROUND`. When `MSGPACK_STRICT_CONFIG`
is undefine this expand to test the given `symbol` version value with the
`comp` comparison against `MSGPACK_VERSION_NUMBER(major,minor,patch)`.
*/
#ifdef MSGPACK_STRICT_CONFIG
#   define MSGPACK_PREDEF_WORKAROUND(symbol, comp, major, minor, patch) (0)
#else
#   include <msgpack/predef/version_number.h>
#   define MSGPACK_PREDEF_WORKAROUND(symbol, comp, major, minor, patch) \
        ( (symbol) != (0) ) && \
        ( (symbol) comp (MSGPACK_VERSION_NUMBER( (major) , (minor) , (patch) )) )
#endif

/*`
[heading `MSGPACK_PREDEF_TESTED_AT`]

``
MSGPACK_PREDEF_TESTED_AT(symbol,major,minor,patch)
``

Usage:

``
#if MSGPACK_PREDEF_TESTED_AT(MSGPACK_COMP_CLANG,3,5,0)
    // Needed for clang, and last checked for 3.5.0.
#endif
``

Defines a comparison against two version numbers that depends on the definion
of `MSGPACK_STRICT_CONFIG` and `MSGPACK_DETECT_OUTDATED_WORKAROUNDS`.
When `MSGPACK_STRICT_CONFIG` is defined this will expand to a value convertible
to `false`. Which has the effect of disabling all code
conditionally guarded by `MSGPACK_PREDEF_TESTED_AT`. When `MSGPACK_STRICT_CONFIG`
is undefined this expand to either:

* A value convertible to `true` when `MSGPACK_DETECT_OUTDATED_WORKAROUNDS` is not
  defined.
* A value convertible `true` when the expansion of
  `MSGPACK_PREDEF_WORKAROUND(symbol, <=, major, minor, patch)` is `true` and
  `MSGPACK_DETECT_OUTDATED_WORKAROUNDS` is defined.
* A compile error when the expansion of
  `MSGPACK_PREDEF_WORKAROUND(symbol, >, major, minor, patch)` is true and
  `MSGPACK_DETECT_OUTDATED_WORKAROUNDS` is defined.
*/
#ifdef MSGPACK_STRICT_CONFIG
#   define MSGPACK_PREDEF_TESTED_AT(symbol, major, minor, patch) (0)
#else
#   ifdef MSGPACK_DETECT_OUTDATED_WORKAROUNDS
#       define MSGPACK_PREDEF_TESTED_AT(symbol, major, minor, patch) ( \
            MSGPACK_PREDEF_WORKAROUND(symbol, <=, major, minor, patch) \
            ? 1 \
            : (1%0) )
#   else
#       define MSGPACK_PREDEF_TESTED_AT(symbol, major, minor, patch) \
            ( (symbol) >= MSGPACK_VERSION_NUMBER_AVAILABLE )
#   endif
#endif

#endif
