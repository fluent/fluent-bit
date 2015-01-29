//
// MessagePack for C++ atomic operations
//
// Copyright (C) 2008-2013 FURUHASHI Sadayuki
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

#if defined(__GNUC__) && ((__GNUC__*10 + __GNUC_MINOR__) < 41)

#include "gcc_atomic.h"
#include <bits/atomicity.h>

int _msgpack_sync_decr_and_fetch(volatile _msgpack_atomic_counter_t* ptr)
{
	return  __gnu_cxx::__exchange_and_add(ptr, -1) - 1;
}

int _msgpack_sync_incr_and_fetch(volatile _msgpack_atomic_counter_t* ptr)
{
	return  __gnu_cxx::__exchange_and_add(ptr, 1) + 1;
}


#endif // old gcc workaround
