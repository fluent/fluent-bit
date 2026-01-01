/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_IN_FW_PROT_H
#define FLB_IN_FW_PROT_H

#include "fw_conn.h"

struct flb_in_fw_helo;

int fw_prot_parser(struct fw_conn *conn);
int fw_prot_process(struct flb_input_instance *ins, struct fw_conn *conn);
int flb_secure_forward_set_helo(struct flb_input_instance *ins,
                                struct flb_in_fw_helo *helo,
                                unsigned char *nonce, unsigned char *salt);
int fw_prot_secure_forward_handshake_start(struct flb_input_instance *ins,
                                           struct flb_connection *connection,
                                           struct flb_in_fw_helo *helo);
int fw_prot_secure_forward_handshake(struct flb_input_instance *ins,
                                     struct fw_conn *conn);
#endif
