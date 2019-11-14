# /* **************************************************************************
#  *                                                                          *
#  *     (C) Copyright Paul Mensonides 2002.
#  *     Distributed under the Boost Software License, Version 1.0. (See
#  *     accompanying file LICENSE_1_0.txt or copy at
#  *     http://www.boost.org/LICENSE_1_0.txt)
#  *                                                                          *
#  ************************************************************************** */
#
# /* See http://www.boost.org for most recent version. */
#
# ifndef MSGPACK_PREPROCESSOR_ARRAY_POP_BACK_HPP
# define MSGPACK_PREPROCESSOR_ARRAY_POP_BACK_HPP
#
# include <msgpack/preprocessor/arithmetic/dec.hpp>
# include <msgpack/preprocessor/array/elem.hpp>
# include <msgpack/preprocessor/array/size.hpp>
# include <msgpack/preprocessor/repetition/enum.hpp>
# include <msgpack/preprocessor/repetition/deduce_z.hpp>
#
# /* MSGPACK_PP_ARRAY_POP_BACK */
#
# define MSGPACK_PP_ARRAY_POP_BACK(array) MSGPACK_PP_ARRAY_POP_BACK_Z(MSGPACK_PP_DEDUCE_Z(), array)
#
# /* MSGPACK_PP_ARRAY_POP_BACK_Z */
#
# if ~MSGPACK_PP_CONFIG_FLAGS() & MSGPACK_PP_CONFIG_EDG()
#    define MSGPACK_PP_ARRAY_POP_BACK_Z(z, array) MSGPACK_PP_ARRAY_POP_BACK_I(z, MSGPACK_PP_ARRAY_SIZE(array), array)
# else
#    define MSGPACK_PP_ARRAY_POP_BACK_Z(z, array) MSGPACK_PP_ARRAY_POP_BACK_Z_D(z, array)
#    define MSGPACK_PP_ARRAY_POP_BACK_Z_D(z, array) MSGPACK_PP_ARRAY_POP_BACK_I(z, MSGPACK_PP_ARRAY_SIZE(array), array)
# endif
#
# define MSGPACK_PP_ARRAY_POP_BACK_I(z, size, array) (MSGPACK_PP_DEC(size), (MSGPACK_PP_ENUM_ ## z(MSGPACK_PP_DEC(size), MSGPACK_PP_ARRAY_POP_BACK_M, array)))
# define MSGPACK_PP_ARRAY_POP_BACK_M(z, n, data) MSGPACK_PP_ARRAY_ELEM(n, data)
#
# endif
