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

#include <monkey/mk_api.h>

#include "fastcgi.h"
#include "fcgi_handler.h"

static int mk_fastcgi_config(char *path)
{
    int ret;
    int sep;
    char *file = NULL;
    char *cnf_srv_name = NULL;
    char *cnf_srv_addr = NULL;
    char *cnf_srv_port = NULL;
    char *cnf_srv_path = NULL;
    unsigned long len;
    struct file_info finfo;
    struct mk_rconf *conf;
    struct mk_rconf_section *section;

    mk_api->str_build(&file, &len, "%sfastcgi.conf", path);
    conf = mk_api->config_open(file);
    if (!conf) {
        return -1;
    }

    section = mk_api->config_section_get(conf, "FASTCGI_SERVER");
    if (!section) {
        return -1;
    }

    /* Get section values */
    cnf_srv_name = mk_api->config_section_get_key(section,
                                                  "ServerName",
                                                  MK_RCONF_STR);
    cnf_srv_addr = mk_api->config_section_get_key(section,
                                                  "ServerAddr",
                                                  MK_RCONF_STR);
    cnf_srv_path = mk_api->config_section_get_key(section,
                                                  "ServerPath",
                                                  MK_RCONF_STR);

    /* Validations */
    if (!cnf_srv_name) {
        mk_warn("[fastcgi] Invalid ServerName in configuration.");
        return -1;
    }

    /* Split the address, try to lookup the TCP port */
    if (cnf_srv_addr) {
        sep = mk_api->str_char_search(cnf_srv_addr, ':', strlen(cnf_srv_addr));
        if (sep <= 0) {
            mk_warn("[fastcgi] Missing TCP port con ServerAddress key");
            return -1;
        }

        cnf_srv_port = mk_api->str_dup(cnf_srv_addr + sep + 1);
        cnf_srv_addr[sep] = '\0';
    }

    /* Just one mode can exist (for now) */
    if (cnf_srv_path && cnf_srv_addr) {
        mk_warn("[fastcgi] Use ServerAddr or ServerPath, not both");
        return -1;
    }

    /* Unix socket path */
    if (cnf_srv_path) {
        ret = mk_api->file_get_info(cnf_srv_path, &finfo, MK_FILE_READ);
        if (ret == -1) {
            mk_warn("[fastcgi] Cannot open unix socket: %s", cnf_srv_path);
            return -1;
        }
    }

    /* Set the global configuration */
    fcgi_conf.server_name = cnf_srv_name;
    fcgi_conf.server_addr = cnf_srv_addr;
    fcgi_conf.server_port = cnf_srv_port;
    fcgi_conf.server_path = cnf_srv_path;

    return 0;
}


/* Entry point for thread/co-routine */
static void mk_fastcgi_stage30_thread(struct mk_plugin *plugin,
                                      struct mk_http_session *cs,
                                      struct mk_http_request *sr,
                                      int n_params,
                                      struct mk_list *params)
{
    struct fcgi_handler *handler;
    (void) plugin;
    (void) n_params;
    (void) params;

    printf("entering thread\n");
    handler = fcgi_handler_new(cs, sr);
    if (!handler) {
        fprintf(stderr, "Could not create handler");
    }
}

/* Callback handler */
int mk_fastcgi_stage30(struct mk_plugin *plugin,
                       struct mk_http_session *cs,
                       struct mk_http_request *sr,
                       int n_params,
                       struct mk_list *params)
{
    (void) n_params;
    (void) params;
    struct fcgi_handler *handler;

    /*
     * This plugin uses the Monkey Thread model (co-routines), for hence
     * upon return MK_PLUGIN_RET_CONTINUE, Monkey core will create a
     * new thread (co-routine) and defer the control to the stage30_thread
     * callback function (mk_fastcgi_stage30_thread).
     *
     * We don't do any validation, so we are OK with MK_PLUGIN_RET_CONTINUE.
     */

    return MK_PLUGIN_RET_CONTINUE;

    ret = mk_fastcgi_start_processing(cs, sr);
    if (ret == 0) {
        return MK_PLUGIN_RET_CONTINUE;
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_fastcgi_stage30_hangup(struct mk_plugin *plugin,
                              struct mk_http_session *cs,
                              struct mk_http_request *sr)
{
    (void) plugin;
    (void) cs;
    struct fcgi_handler *handler;

    handler = sr->handler_data;
    if (!handler) {
        return -1;
    }

    if (handler->hangup == MK_TRUE) {
        return 0;
    }

    handler->active = MK_FALSE;
    handler->hangup = MK_TRUE;

    fcgi_exit(sr->handler_data);

    return 0;
}

int mk_fastcgi_plugin_init(struct plugin_api **api, char *confdir)
{
    int ret;

    mk_api = *api;

    /* read global configuration */
    ret = mk_fastcgi_config(confdir);
    if (ret == -1) {
        mk_warn("[fastcgi] configuration error/missing, plugin disabled.");
    }
	return ret;
}

int mk_fastcgi_plugin_exit()
{
    return 0;
}

int mk_fastcgi_master_init(struct mk_server *server)
{
    (void) server;
    return 0;
}

void mk_fastcgi_worker_init()
{
}

struct mk_plugin_stage mk_plugin_stage_fastcgi = {
    .stage30        = &mk_fastcgi_stage30,
    .stage30_thread = &mk_fastcgi_stage30_thread,
    .stage30_hangup = &mk_fastcgi_stage30_hangup
};

struct mk_plugin mk_plugin_fastcgi = {
    /* Identification */
    .shortname     = "fastcgi",
    .name          = "FastCGI Client",
    .version       = "1.0",
    .hooks         = MK_PLUGIN_STAGE,

    /* Init / Exit */
    .init_plugin   = mk_fastcgi_plugin_init,
    .exit_plugin   = mk_fastcgi_plugin_exit,

    /* Init Levels */
    .master_init   = mk_fastcgi_master_init,
    .worker_init   = mk_fastcgi_worker_init,

    /* Type */
    .stage         = &mk_plugin_stage_fastcgi,

    /* Flags */
    .flags         = MK_PLUGIN_THREAD
};
