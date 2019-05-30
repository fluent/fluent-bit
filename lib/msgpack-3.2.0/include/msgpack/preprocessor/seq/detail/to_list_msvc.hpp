# /* **************************************************************************
#  *                                                                          *
#  *     (C) Copyright Edward Diener 2016.                                    *
#  *     Distributed under the Boost Software License, Version 1.0. (See      *
#  *     accompanying file LICENSE_1_0.txt or copy at                         *
#  *     http://www.boost.org/LICENSE_1_0.txt)                                *
#  *                                                                          *
#  ************************************************************************** */
#
# /* See http://www.boost.org for most recent version. */
#
# ifndef MSGPACK_PREPROCESSOR_SEQ_DETAIL_TO_LIST_MSVC_HPP
# define MSGPACK_PREPROCESSOR_SEQ_DETAIL_TO_LIST_MSVC_HPP
#
# include <msgpack/preprocessor/config/config.hpp>
#
# if MSGPACK_PP_CONFIG_FLAGS() & MSGPACK_PP_CONFIG_MSVC()
#
# include <msgpack/preprocessor/cat.hpp>
# include <msgpack/preprocessor/arithmetic/dec.hpp>
# include <msgpack/preprocessor/control/while.hpp>
# include <msgpack/preprocessor/tuple/elem.hpp>
#
# define MSGPACK_PP_SEQ_DETAIL_TO_LIST_MSVC_STATE_RESULT(state) \
    MSGPACK_PP_TUPLE_ELEM(2, 0, state) \
/**/
# define MSGPACK_PP_SEQ_DETAIL_TO_LIST_MSVC_STATE_SIZE(state) \
    MSGPACK_PP_TUPLE_ELEM(2, 1, state) \
/**/
# define MSGPACK_PP_SEQ_DETAIL_TO_LIST_MSVC_PRED(d,state) \
    MSGPACK_PP_SEQ_DETAIL_TO_LIST_MSVC_STATE_SIZE(state) \
/**/
# define MSGPACK_PP_SEQ_DETAIL_TO_LIST_MSVC_OP(d,state) \
    ( \
    MSGPACK_PP_CAT(MSGPACK_PP_SEQ_DETAIL_TO_LIST_MSVC_STATE_RESULT(state),), \
    MSGPACK_PP_DEC(MSGPACK_PP_SEQ_DETAIL_TO_LIST_MSVC_STATE_SIZE(state)) \
    ) \
/**/
#
# /* MSGPACK_PP_SEQ_DETAIL_TO_LIST_MSVC */
#
# define MSGPACK_PP_SEQ_DETAIL_TO_LIST_MSVC(result,seqsize) \
    MSGPACK_PP_SEQ_DETAIL_TO_LIST_MSVC_STATE_RESULT \
        ( \
        MSGPACK_PP_WHILE \
            ( \
            MSGPACK_PP_SEQ_DETAIL_TO_LIST_MSVC_PRED, \
            MSGPACK_PP_SEQ_DETAIL_TO_LIST_MSVC_OP, \
            (result,seqsize) \
            ) \
        ) \
/**/
# endif // MSGPACK_PP_CONFIG_FLAGS() & MSGPACK_PP_CONFIG_MSVC()
#
# endif // MSGPACK_PREPROCESSOR_SEQ_DETAIL_TO_LIST_MSVC_HPP
