# /* **************************************************************************
#  *                                                                          *
#  *     (C) Copyright Paul Mensonides 2011.                                  *
#  *     Distributed under the Boost Software License, Version 1.0. (See      *
#  *     accompanying file LICENSE_1_0.txt or copy at                         *
#  *     http://www.boost.org/LICENSE_1_0.txt)                                *
#  *                                                                          *
#  ************************************************************************** */
#
# /* See http://www.boost.org for most recent version. */
#
# ifndef MSGPACK_PREPROCESSOR_SEQ_DETAIL_BINARY_TRANSFORM_HPP
# define MSGPACK_PREPROCESSOR_SEQ_DETAIL_BINARY_TRANSFORM_HPP
#
# include <msgpack/preprocessor/cat.hpp>
# include <msgpack/preprocessor/config/config.hpp>
# include <msgpack/preprocessor/tuple/eat.hpp>
# include <msgpack/preprocessor/tuple/rem.hpp>
# include <msgpack/preprocessor/variadic/detail/is_single_return.hpp>
#
# /* MSGPACK_PP_SEQ_BINARY_TRANSFORM */
#
# if MSGPACK_PP_CONFIG_FLAGS() & MSGPACK_PP_CONFIG_MSVC()
#    define MSGPACK_PP_SEQ_BINARY_TRANSFORM(seq) MSGPACK_PP_SEQ_BINARY_TRANSFORM_I(, seq)
#    define MSGPACK_PP_SEQ_BINARY_TRANSFORM_I(p, seq) MSGPACK_PP_SEQ_BINARY_TRANSFORM_II(p ## seq)
#    define MSGPACK_PP_SEQ_BINARY_TRANSFORM_II(seq) MSGPACK_PP_SEQ_BINARY_TRANSFORM_III(seq)
#    define MSGPACK_PP_SEQ_BINARY_TRANSFORM_III(seq) MSGPACK_PP_CAT(MSGPACK_PP_SEQ_BINARY_TRANSFORM_A seq, 0)
# else
#    define MSGPACK_PP_SEQ_BINARY_TRANSFORM(seq) MSGPACK_PP_CAT(MSGPACK_PP_SEQ_BINARY_TRANSFORM_A seq, 0)
# endif
# if MSGPACK_PP_VARIADICS
#    if MSGPACK_PP_VARIADICS_MSVC
#		define MSGPACK_PP_SEQ_BINARY_TRANSFORM_REM(data) data
#       define MSGPACK_PP_SEQ_BINARY_TRANSFORM_A(...) (MSGPACK_PP_SEQ_BINARY_TRANSFORM_REM, __VA_ARGS__)() MSGPACK_PP_SEQ_BINARY_TRANSFORM_B
#       define MSGPACK_PP_SEQ_BINARY_TRANSFORM_B(...) (MSGPACK_PP_SEQ_BINARY_TRANSFORM_REM, __VA_ARGS__)() MSGPACK_PP_SEQ_BINARY_TRANSFORM_A
#	 else
#       define MSGPACK_PP_SEQ_BINARY_TRANSFORM_A(...) (MSGPACK_PP_REM, __VA_ARGS__)() MSGPACK_PP_SEQ_BINARY_TRANSFORM_B
#       define MSGPACK_PP_SEQ_BINARY_TRANSFORM_B(...) (MSGPACK_PP_REM, __VA_ARGS__)() MSGPACK_PP_SEQ_BINARY_TRANSFORM_A
#	 endif
# else
#    define MSGPACK_PP_SEQ_BINARY_TRANSFORM_A(e) (MSGPACK_PP_REM, e)() MSGPACK_PP_SEQ_BINARY_TRANSFORM_B
#    define MSGPACK_PP_SEQ_BINARY_TRANSFORM_B(e) (MSGPACK_PP_REM, e)() MSGPACK_PP_SEQ_BINARY_TRANSFORM_A
# endif
# define MSGPACK_PP_SEQ_BINARY_TRANSFORM_A0 (MSGPACK_PP_EAT, ?)
# define MSGPACK_PP_SEQ_BINARY_TRANSFORM_B0 (MSGPACK_PP_EAT, ?)
#
# endif
