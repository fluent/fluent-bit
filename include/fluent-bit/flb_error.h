/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_ERROR_H
#define FLB_ERROR_H

#define FLB_ERR_CFG_FILE              10
#define FLB_ERR_CFG_FILE_FORMAT       11
#define FLB_ERR_CFG_FILE_STOP         12
#define FLB_ERR_CFG_FLUSH             20
#define FLB_ERR_CFG_FLUSH_CREATE      21
#define FLB_ERR_CFG_FLUSH_REGISTER    22
#define FLB_ERR_CUSTOM_INVALID        49
#define FLB_ERR_INPUT_INVALID         50
#define FLB_ERR_INPUT_UNDEF           51
#define FLB_ERR_INPUT_UNSUP           52
#define FLB_ERR_OUTPUT_UNDEF         100
#define FLB_ERR_OUTPUT_INVALID       101
#define FLB_ERR_OUTPUT_UNIQ          102
#define FLB_ERR_FILTER_INVALID       201
#define FLB_ERR_PROCESSOR_INVALID    202

/* Parser */
#define FLB_ERR_CFG_PARSER_FILE      300

/* Plugin */
#define FLB_ERR_CFG_PLUGIN_FILE      400

/* JSON errors */
#define FLB_ERR_JSON_INVAL           -501
#define FLB_ERR_JSON_PART            -502

/* Coroutine errors */
#define FLB_ERR_CORO_STACK_SIZE      -600

/* Reloading */
#define FLB_ERR_RELOADING_IN_PROGRESS 700

#endif
