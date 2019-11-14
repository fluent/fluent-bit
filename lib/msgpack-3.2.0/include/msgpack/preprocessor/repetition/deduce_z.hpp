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
# ifndef MSGPACK_PREPROCESSOR_REPETITION_DEDUCE_Z_HPP
# define MSGPACK_PREPROCESSOR_REPETITION_DEDUCE_Z_HPP
#
# include <msgpack/preprocessor/detail/auto_rec.hpp>
# include <msgpack/preprocessor/repetition/repeat.hpp>
#
# /* MSGPACK_PP_DEDUCE_Z */
#
# define MSGPACK_PP_DEDUCE_Z() MSGPACK_PP_AUTO_REC(MSGPACK_PP_REPEAT_P, 4)
#
# endif
