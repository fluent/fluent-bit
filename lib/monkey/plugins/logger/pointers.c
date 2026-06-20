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

#include <monkey/mk_plugin.h>

#include "logger.h"
#include "pointers.h"

const mk_ptr_t mk_logger_iov_none = mk_ptr_init("");

/* Writter helpers */
const mk_ptr_t mk_logger_iov_dash = mk_ptr_init(MK_LOGGER_IOV_DASH);
const mk_ptr_t mk_logger_iov_space = mk_ptr_init(MK_IOV_SPACE);
const mk_ptr_t mk_logger_iov_lf = mk_ptr_init(MK_IOV_LF);
const mk_ptr_t mk_logger_iov_empty = mk_ptr_init(MK_LOGGER_IOV_EMPTY);

/* Error messages */
const mk_ptr_t error_msg_400 = mk_ptr_init(ERROR_MSG_400);
const mk_ptr_t error_msg_403 = mk_ptr_init(ERROR_MSG_403);
const mk_ptr_t error_msg_404 = mk_ptr_init(ERROR_MSG_404);
const mk_ptr_t error_msg_405 = mk_ptr_init(ERROR_MSG_405);
const mk_ptr_t error_msg_408 = mk_ptr_init(ERROR_MSG_408);
const mk_ptr_t error_msg_411 = mk_ptr_init(ERROR_MSG_411);
const mk_ptr_t error_msg_413 = mk_ptr_init(ERROR_MSG_413);
const mk_ptr_t error_msg_500 = mk_ptr_init(ERROR_MSG_500);
const mk_ptr_t error_msg_501 = mk_ptr_init(ERROR_MSG_501);
const mk_ptr_t error_msg_505 = mk_ptr_init(ERROR_MSG_505);
