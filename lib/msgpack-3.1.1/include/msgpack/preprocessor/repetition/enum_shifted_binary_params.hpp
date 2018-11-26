# /* **************************************************************************
#  *                                                                          *
#  *     (C) Copyright Paul Mensonides 2005.                                  *
#  *     Distributed under the Boost Software License, Version 1.0. (See      *
#  *     accompanying file LICENSE_1_0.txt or copy at                         *
#  *     http://www.boost.org/LICENSE_1_0.txt)                                *
#  *                                                                          *
#  ************************************************************************** */
#
# /* See http://www.boost.org for most recent version. */
#
# ifndef MSGPACK_PREPROCESSOR_REPETITION_ENUM_SHIFTED_BINARY_PARAMS_HPP
# define MSGPACK_PREPROCESSOR_REPETITION_ENUM_SHIFTED_BINARY_PARAMS_HPP
#
# include <msgpack/preprocessor/arithmetic/dec.hpp>
# include <msgpack/preprocessor/arithmetic/inc.hpp>
# include <msgpack/preprocessor/cat.hpp>
# include <msgpack/preprocessor/config/config.hpp>
# include <msgpack/preprocessor/punctuation/comma_if.hpp>
# include <msgpack/preprocessor/repetition/repeat.hpp>
# include <msgpack/preprocessor/tuple/elem.hpp>
# include <msgpack/preprocessor/tuple/rem.hpp>
#
# /* MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS */
#
# if ~MSGPACK_PP_CONFIG_FLAGS() & MSGPACK_PP_CONFIG_EDG()
#    define MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS(count, p1, p2) MSGPACK_PP_REPEAT(MSGPACK_PP_DEC(count), MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_M, (p1, p2))
# else
#    define MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS(count, p1, p2) MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_I(count, p1, p2)
#    define MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_I(count, p1, p2) MSGPACK_PP_REPEAT(MSGPACK_PP_DEC(count), MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_M, (p1, p2))
# endif
#
# if MSGPACK_PP_CONFIG_FLAGS() & MSGPACK_PP_CONFIG_STRICT()
#    define MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_M(z, n, pp) MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_M_IM(z, n, MSGPACK_PP_TUPLE_REM_2 pp)
#    define MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_M_IM(z, n, im) MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_M_I(z, n, im)
# else
#    define MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_M(z, n, pp) MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_M_I(z, n, MSGPACK_PP_TUPLE_ELEM(2, 0, pp), MSGPACK_PP_TUPLE_ELEM(2, 1, pp))
# endif
#
# define MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_M_I(z, n, p1, p2) MSGPACK_PP_COMMA_IF(n) MSGPACK_PP_CAT(p1, MSGPACK_PP_INC(n)) MSGPACK_PP_CAT(p2, MSGPACK_PP_INC(n))
#
# /* MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_Z */
#
# if ~MSGPACK_PP_CONFIG_FLAGS() & MSGPACK_PP_CONFIG_EDG()
#    define MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_Z(z, count, p1, p2) MSGPACK_PP_REPEAT_ ## z(MSGPACK_PP_DEC(count), MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_M, (p1, p2))
# else
#    define MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_Z(z, count, p1, p2) MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_Z_I(z, count, p1, p2)
#    define MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_Z_I(z, count, p1, p2) MSGPACK_PP_REPEAT_ ## z(MSGPACK_PP_DEC(count), MSGPACK_PP_ENUM_SHIFTED_BINARY_PARAMS_M, (p1, p2))
# endif
#
# endif
