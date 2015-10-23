//
// MessagePack for C++ static resolution routine
//
// Copyright (C) 2015 KONDO Takatoshi
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//
#ifndef MSGPACK_TYPE_BOOST_FUSION_HPP
#define MSGPACK_TYPE_BOOST_FUSION_HPP

#include "msgpack/versioning.hpp"
#include "msgpack/adaptor/adaptor_base.hpp"
#include "msgpack/adaptor/check_container_size.hpp"
#include "msgpack/meta.hpp"

#if !defined (MSGPACK_USE_CPP03)
#include "msgpack/adaptor/cpp11/tuple.hpp"
#endif // #if !defined (MSGPACK_USE_CPP03)

#include <boost/fusion/support/is_sequence.hpp>
#include <boost/fusion/sequence/intrinsic/size.hpp>
#include <boost/fusion/algorithm/iteration/for_each.hpp>
#include <boost/fusion/sequence/intrinsic/at.hpp>
#include <boost/fusion/include/mpl.hpp>
#include <boost/mpl/size.hpp>

namespace msgpack {

/// @cond
MSGPACK_API_VERSION_NAMESPACE(v1) {
/// @endcond

namespace adaptor {

#if !defined (MSGPACK_USE_CPP03)

template <typename T>
struct as<
    T,
    typename msgpack::enable_if<
        boost::fusion::traits::is_sequence<T>::value &&
        boost::mpl::fold<
            T,
            boost::mpl::bool_<true>,
            boost::mpl::if_ <
                boost::mpl::and_<
                    boost::mpl::_1,
                    msgpack::has_as<boost::mpl::_2>
                >,
                boost::mpl::bool_<true>,
                boost::mpl::bool_<false>
            >
        >::type::value
    >::type
> {
    T operator()(msgpack::object const& o) const {
        if (o.type != msgpack::type::ARRAY) { throw msgpack::type_error(); }
        if (o.via.array.size != checked_get_container_size(boost::mpl::size<T>::value)) {
            throw msgpack::type_error();
        }
        using tuple_t = decltype(to_tuple(std::declval<T>(), gen_seq<boost::mpl::size<T>::value>()));
        return to_t(
            o.as<tuple_t>(),
            msgpack::gen_seq<boost::mpl::size<T>::value>());
    }
    template<std::size_t... Is, typename U>
    static std::tuple<
        typename std::remove_reference<
            typename boost::fusion::result_of::at_c<T, Is>::type
        >::type...>
    to_tuple(U const& u, seq<Is...>) {
        return std::make_tuple(boost::fusion::at_c<Is>(u)...);
    }
    template<std::size_t... Is, typename U>
    static T to_t(U const& u, seq<Is...>) {
        return T(std::get<Is>(u)...);
    }
};

#endif // !defined (MSGPACK_USE_CPP03)

template <typename T>
struct convert<T, typename msgpack::enable_if<boost::fusion::traits::is_sequence<T>::value>::type > {
    msgpack::object const& operator()(msgpack::object const& o, T& v) const {
        if (o.type != msgpack::type::ARRAY) { throw msgpack::type_error(); }
        if (o.via.array.size != checked_get_container_size(boost::fusion::size(v))) {
            throw msgpack::type_error();
        }
        uint32_t index = 0;
        boost::fusion::for_each(v, convert_imp(o, index));
        return o;
    }
private:
    struct convert_imp {
        convert_imp(msgpack::object const& obj, uint32_t& index):obj_(obj), index_(index) {}
        template <typename U>
        void operator()(U& v) const {
            msgpack::adaptor::convert<U>()(obj_.via.array.ptr[index_++], v);
        }
    private:
        msgpack::object const& obj_;
        uint32_t& index_;
    };
};

template <typename T>
struct pack<T, typename msgpack::enable_if<boost::fusion::traits::is_sequence<T>::value>::type > {
    template <typename Stream>
    msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, const T& v) const {
        uint32_t size = checked_get_container_size(boost::fusion::size(v));
        o.pack_array(size);
        boost::fusion::for_each(v, pack_imp<Stream>(o));
        return o;
    }
private:
    template <typename Stream>
    struct pack_imp {
        pack_imp(msgpack::packer<Stream>& stream):stream_(stream) {}
        template <typename U>
        void operator()(U const& v) const {
            stream_.pack(v);
        }
    private:
        msgpack::packer<Stream>& stream_;
    };
};

template <typename T>
struct object_with_zone<T, typename msgpack::enable_if<boost::fusion::traits::is_sequence<T>::value>::type > {
    void operator()(msgpack::object::with_zone& o, const T& v) const {
        uint32_t size = checked_get_container_size(boost::fusion::size(v));
        o.type = msgpack::type::ARRAY;
        o.via.array.ptr = static_cast<msgpack::object*>(o.zone.allocate_align(sizeof(msgpack::object)*size));
        o.via.array.size = size;
        uint32_t count = 0;
        boost::fusion::for_each(v, with_zone_imp(o, count));
    }
private:
    struct with_zone_imp {
        with_zone_imp(msgpack::object::with_zone const& obj, uint32_t& count):obj_(obj), count_(count) {}
        template <typename U>
        void operator()(U const& v) const {
            obj_.via.array.ptr[count_++] = msgpack::object(v, obj_.zone);
        }
        msgpack::object::with_zone const& obj_;
        uint32_t& count_;
    };
};

} // namespace adaptor

/// @cond
} // MSGPACK_API_VERSION_NAMESPACE(v1)
/// @endcond

} // namespace msgpack

#endif // MSGPACK_TYPE_BOOST_FUSION_HPP
