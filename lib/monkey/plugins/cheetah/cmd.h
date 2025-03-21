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

time_t init_time;

/* commands */
int mk_cheetah_cmd(char *cmd, struct mk_server *server);

void mk_cheetah_cmd_clear();
void mk_cheetah_cmd_uptime(struct mk_server *server);

/* Plugins commands */
void mk_cheetah_cmd_plugins_print_stage(struct mk_list *list, const char *stage,
                                        int stage_bw);
void mk_cheetah_cmd_plugins_print_core(struct mk_list *list);
void mk_cheetah_cmd_plugins_print_network(struct mk_list *list);
void mk_cheetah_cmd_plugins(struct mk_server *server);

void mk_cheetah_cmd_vhosts(struct mk_server *server);
void mk_cheetah_cmd_workers(struct mk_server *server);

int  mk_cheetah_cmd_quit();
void mk_cheetah_cmd_help();
void mk_cheetah_cmd_config(struct mk_server *server);
void mk_cheetah_cmd_status(struct mk_server *server);
