/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#ifndef MK_LOGGER_POINTERS_H
#define MK_LOGGER_POINTERS_H

#include <memory.h>

/* Request error messages for log file */
#define ERROR_MSG_400 "[error 400] Bad Request"
#define ERROR_MSG_403 "[error 403] Forbidden"
#define ERROR_MSG_404 "[error 404] Not Found"
#define ERROR_MSG_405 "[error 405] Method Not Allowed"
#define ERROR_MSG_408 "[error 408] Request Timeout"
#define ERROR_MSG_411 "[error 411] Length Required"
#define ERROR_MSG_413 "[error 413] Request Entity Too Large"
#define ERROR_MSG_500 "[error 500] Internal Server Error"
#define ERROR_MSG_501 "[error 501] Not Implemented"
#define ERROR_MSG_505 "[error 505] HTTP Version Not Supported"

#define MK_LOGGER_IOV_DASH " - "
#define MK_LOGGER_IOV_SPACE " "
#define MK_LOGGER_IOV_EMPTY "-"

/* mk pointers for errors */
extern const mk_ptr_t error_msg_400;
extern const mk_ptr_t error_msg_403;
extern const mk_ptr_t error_msg_404;
extern const mk_ptr_t error_msg_405;
extern const mk_ptr_t error_msg_408;
extern const mk_ptr_t error_msg_411;
extern const mk_ptr_t error_msg_413;
extern const mk_ptr_t error_msg_500;
extern const mk_ptr_t error_msg_501;
extern const mk_ptr_t error_msg_505;

/* mk pointer for IOV */
extern const mk_ptr_t mk_logger_iov_dash;
extern const mk_ptr_t mk_logger_iov_space;
extern const mk_ptr_t mk_logger_iov_lf;
extern const mk_ptr_t mk_logger_iov_empty;

#endif
