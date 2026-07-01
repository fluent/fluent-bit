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

#ifndef MK_CHEETAH_H
#define MK_CHEETAH_H

/* Commands */
#define MK_CHEETAH_CLEAR "clear"
#define MK_CHEETAH_CLEAR_SC "\\c"

#define MK_CHEETAH_CONFIG "config"
#define MK_CHEETAH_CONFIG_SC "\\f"

#define MK_CHEETAH_STATUS "status"
#define MK_CHEETAH_STATUS_SC "\\s"

#define MK_CHEETAH_HELP "help"
#define MK_CHEETAH_HELP_SC "\\h"

#define MK_CHEETAH_SHELP "?"
#define MK_CHEETAH_SHELP_SC "\\?"

#define MK_CHEETAH_UPTIME "uptime"
#define MK_CHEETAH_UPTIME_SC "\\u"

#define MK_CHEETAH_PLUGINS "plugins"
#define MK_CHEETAH_PLUGINS_SC "\\g"

#define MK_CHEETAH_VHOSTS "vhosts"
#define MK_CHEETAH_VHOSTS_SC "\\v"

#define MK_CHEETAH_WORKERS "workers"
#define MK_CHEETAH_WORKERS_SC "\\w"

#define MK_CHEETAH_QUIT "quit"
#define MK_CHEETAH_QUIT_SC "\\q"

/* Constants */
#define MK_CHEETAH_PROMPT "%s%scheetah>%s "
#define MK_CHEETAH_PROC_TASK "/proc/%i/task/%i/stat"
#define MK_CHEETAH_ONEDAY  86400
#define MK_CHEETAH_ONEHOUR  3600
#define MK_CHEETAH_ONEMINUTE  60

/* Configurarion: Listen */
#define LISTEN_STDIN_STR "STDIN"
#define LISTEN_SERVER_STR "SERVER"

#define LISTEN_STDIN 0
#define LISTEN_SERVER 1

int listen_mode;

char *cheetah_server;

int cheetah_socket;
FILE *cheetah_input;
FILE *cheetah_output;

/* functions */
void mk_cheetah_welcome_msg();

#endif
