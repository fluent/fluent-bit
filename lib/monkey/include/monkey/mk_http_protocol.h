/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2026 The Monkey Authors
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

#ifndef MK_HTTP_PROTOCOL_H
#define MK_HTTP_PROTOCOL_H

/* Shared protocol identifiers, independent of server configuration and types. */
enum mk_request_methods {
    MK_METHOD_GET     = 0,
    MK_METHOD_POST       ,
    MK_METHOD_HEAD       ,
    MK_METHOD_PUT        ,
    MK_METHOD_DELETE     ,
    MK_METHOD_OPTIONS    ,
    MK_METHOD_SIZEOF     ,
    MK_METHOD_UNKNOWN
};

#define MK_HTTP_PROTOCOL_UNKNOWN (-1)
#define MK_HTTP_PROTOCOL_09 (9)
#define MK_HTTP_PROTOCOL_10 (10)
#define MK_HTTP_PROTOCOL_11 (11)

#define MK_HTTP_PROTOCOL_09_STR "HTTP/0.9"
#define MK_HTTP_PROTOCOL_10_STR "HTTP/1.0"
#define MK_HTTP_PROTOCOL_11_STR "HTTP/1.1"

#endif
