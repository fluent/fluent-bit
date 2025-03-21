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

/* Monkey Plugin Interface */
#include <monkey/mk_api.h>

/* Local header files */
#include "cmd.h"
#include "cutils.h"
#include "cheetah.h"
#include "loop.h"

void mk_cheetah_welcome_msg()
{
    CHEETAH_WRITE("\n%s%s***%s Welcome to %sCheetah!%s, the %sMonkey Shell %s:) %s***%s\n",
                  ANSI_BOLD, ANSI_YELLOW,
                  ANSI_WHITE, ANSI_GREEN,
                  ANSI_WHITE, ANSI_RED, ANSI_WHITE, ANSI_YELLOW, ANSI_RESET);
    CHEETAH_WRITE("\n      << %sType 'help' or '\\h' for help%s >>\n\n",
                  ANSI_BLUE, ANSI_RESET);
    CHEETAH_FLUSH();
}

static int mk_cheetah_config(char *path)
{
    unsigned long len;
    char *listen = NULL;
    char *default_file = NULL;
    struct mk_rconf *conf;
    struct mk_rconf_section *section;

    /* this variable is defined in cheetah.h and points to
     * the FILE *descriptor where to write out the data
     */
    cheetah_output = NULL;

    /* read configuration file */
    mk_api->str_build(&default_file, &len, "%scheetah.conf", path);
    conf = mk_api->config_open(default_file);
    if (!conf) {
        return -1;
    }

    section = mk_api->config_section_get(conf, "CHEETAH");

    if (!section) {
        CHEETAH_WRITE("\nError, could not find CHEETAH tag");
        return -1;
    }

    /* no longer needed */
    mk_api->mem_free(default_file);

    /* Listen directive */
    listen = mk_api->config_section_get_key(section, "Listen", MK_RCONF_STR);

    if (strcasecmp(listen, LISTEN_STDIN_STR) == 0) {
        listen_mode = LISTEN_STDIN;
    }
    else if (strcasecmp(listen, LISTEN_SERVER_STR) == 0) {
        listen_mode = LISTEN_SERVER;
    }
    else {
        printf("\nCheetah! Error: Invalid LISTEN value");
        return -1;
    }

    /* Cheetah cannot work in STDIN mode if Monkey is working in background */
    if (listen_mode == LISTEN_STDIN && mk_api->config->is_daemon == MK_TRUE) {
        printf("\nCheetah!: Forcing SERVER mode as Monkey is running in background\n");
        fflush(stdout);
        listen_mode = LISTEN_SERVER;
    }

    return 0;
}

static void mk_cheetah_init(void *args)
{
    struct mk_server *server = args;

    /* Rename worker */
    mk_api->worker_rename("monkey: cheetah");

    /* Open right FDs for I/O */
    if (listen_mode == LISTEN_STDIN) {
        cheetah_input = stdin;
        cheetah_output = stdout;
        mk_cheetah_loop_stdin(server);
    }
    else if (listen_mode == LISTEN_SERVER) {
        mk_cheetah_loop_server(server);
    }
}

/* This function is called when the plugin is loaded, it must
 * return
 */
int mk_cheetah_plugin_init(struct plugin_api **api, char *confdir)
{
    int ret;
    mk_api = *api;
    init_time = time(NULL);

    ret = mk_cheetah_config(confdir);
    return ret;
}

int mk_cheetah_plugin_exit()
{
    if (listen_mode == LISTEN_SERVER) {
        /* Remote named pipe */
        unlink(cheetah_server);
        mk_api->mem_free(cheetah_server);
    }

    return 0;
}

int mk_cheetah_master_init(struct mk_server *server)
{
    int ret;
    pthread_t tid;

    ret = mk_api->worker_spawn(mk_cheetah_init, server, &tid);
    if (ret != 0) {
        return -1;
    }

    return 0;
}

struct mk_plugin mk_plugin_cheetah = {
    /* Identification */
    .shortname     = "cheetah",
    .name          = "Cheetah! Shell",
    .version       = MK_VERSION_STR,

    /* Init / Exit */
    .init_plugin   = mk_cheetah_plugin_init,
    .exit_plugin   = mk_cheetah_plugin_exit,

    /* Init Levels */
    .master_init   = mk_cheetah_master_init,
    .worker_init   = NULL
};
