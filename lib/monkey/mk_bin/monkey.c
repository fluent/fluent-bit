/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#include <monkey/monkey.h>
#include "mk_signals.h"

#include <getopt.h>

#if defined(__DATE__) && defined(__TIME__)
static const char MONKEY_BUILT[] = __DATE__ " " __TIME__;
#else
static const char MONKEY_BUILT[] = "Unknown";
#endif


static void mk_version(void)
{
    printf("Monkey HTTP Server v%s\n", MK_VERSION_STR);
    printf("Built : %s (%s %i.%i.%i)\n",
           MONKEY_BUILT, CC, __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
    printf("Home  : http://monkey-project.com\n");
    fflush(stdout);
}

static void mk_build_info(void)
{
    struct mk_list *head;
    struct mk_plugin *p;

    mk_version();

    printf("\n");
    printf("%s[system: %s]%s\n", ANSI_BOLD, MK_BUILD_OS, ANSI_RESET);
    printf("%s", MK_BUILD_UNAME);

    printf("\n\n%s[configure]%s\n", ANSI_BOLD, ANSI_RESET);
    printf("%s", MK_BUILD_CMD);

    printf("\n\n%s[setup]%s\n", ANSI_BOLD, ANSI_RESET);
    printf("configuration dir: %s\n", MK_PATH_CONF);

    /* Initialize list */
    mk_config = mk_mem_malloc(sizeof(struct mk_server_config));
    mk_list_init(&mk_config->plugins);
    mk_plugin_load_static();

    printf("\n\n%s[built-in plugins]%s\n", ANSI_BOLD, ANSI_RESET);
    mk_list_foreach(head, &mk_config->plugins) {
        p = mk_list_entry(head, struct mk_plugin, _head);
        printf("%-20s%s\n", p->shortname, p->name);
    }
    mk_mem_free(mk_config);
    printf("\n");
}

static void mk_help(int rc)
{
    printf("Usage : monkey [OPTION]\n\n");
    printf("%sAvailable Options%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  -c, --configdir=DIR\t\t\tspecify configuration files directory\n");
    printf("  -s, --serverconf=FILE\t\t\tspecify main server configuration file\n");
    printf("  -D, --daemon\t\t\t\trun Monkey as daemon (background mode)\n");
    printf("  -I, --pid-file\t\t\tset full path for the PID file (override config)\n");
    printf("  -p, --port=PORT\t\t\tset listener TCP port (override config)\n");
    printf("  -o, --one-shot=DIR\t\t\tone-shot, serve a single directory\n");
    printf("  -t, --transport=TRANSPORT\t\tspecify transport layer (override config)\n");
    printf("  -w, --workers=N\t\t\tset number of workers (override config)\n");
    printf("  -m, --mimes-conf-file=FILE\t\tspecify mimes configuration file\n");
    printf("  -l, --plugins-load-conf-file=FILE\tspecify plugins.load configuration file\n");
    printf("  -S, --sites-conf-dir=dir\t\tspecify sites configuration directory\n");
    printf("  -P, --plugins-conf-dir=dir\t\tspecify plugin configuration directory\n");
    printf("  -B, --balancing-mode\t\t\tforce old balancing mode\n");
    printf("  -T, --allow-shared-sockets\t\tif Listen is busy, try shared TCP sockets\n\n");

    printf("%sInformational%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  -b, --build\t\t\t\tprint build information\n");
    printf("  -v, --version\t\t\t\tshow version number\n");
    printf("  -h, --help\t\t\t\tprint this help\n\n");

    printf("%sDocumentation%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  http://monkey-project.com/documentation\n\n");

    exit(rc);
}

/* MAIN */
int main(int argc, char **argv)
{
    int opt;
    char *port_override = NULL;
    int workers_override = -1;
    int run_daemon = 0;
    int balancing_mode = MK_FALSE;
    int allow_shared_sockets = MK_FALSE;
    char *one_shot = NULL;
    char *pid_file = NULL;
    char *transport_layer = NULL;
    char *path_config = NULL;
    char *server_conf_file = NULL;
    char *plugin_load_conf_file = NULL;
    char *sites_conf_dir = NULL;
    char *plugins_conf_dir = NULL;
    char *mimes_conf_file = NULL;

    static const struct option long_opts[] = {
        { "configdir",              required_argument,  NULL, 'c' },
        { "serverconf",             required_argument,  NULL, 's' },
        { "build",                  no_argument,        NULL, 'b' },
        { "daemon",                 no_argument,        NULL, 'D' },
        { "pid-file",               required_argument,  NULL, 'I' },
        { "port",                   required_argument,  NULL, 'p' },
        { "one-shot",               required_argument,  NULL, 'o' },
        { "transport",              required_argument,  NULL, 't' },
        { "workers",                required_argument,  NULL, 'w' },
        { "version",                no_argument,        NULL, 'v' },
        { "help",                   no_argument,        NULL, 'h' },
        { "mimes-conf-file",        required_argument,  NULL, 'm' },
        { "plugin-load-conf-file",  required_argument,  NULL, 'l' },
        { "plugins-conf-dir",       required_argument,  NULL, 'P' },
        { "sites-conf-dir",         required_argument,  NULL, 'S' },
        { "balancing-mode",         no_argument,        NULL, 'B' },
        { "allow-shared-sockets",   no_argument,        NULL, 'T' },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "bDI:Svhp:o:t:w:c:s:m:l:P:S:BT",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'b':
            mk_build_info();
            exit(EXIT_SUCCESS);
        case 'v':
            mk_version();
            exit(EXIT_SUCCESS);
        case 'h':
            mk_help(EXIT_SUCCESS);
        case 'D':
            run_daemon = 1;
            break;
        case 'I':
            pid_file = optarg;
            break;
        case 'p':
            port_override = optarg;
            break;
        case 'o':
            one_shot = optarg;
            break;
        case 't':
            transport_layer = mk_string_dup(optarg);
            break;
        case 'w':
            workers_override = atoi(optarg);
            break;
        case 'c':
            path_config = optarg;
            break;
        case 's':
            server_conf_file = optarg;
            break;
        case 'm':
            mimes_conf_file = optarg;
            break;
        case 'P':
            plugins_conf_dir = optarg;
            break;
        case 'S':
            sites_conf_dir = optarg;
            break;
        case 'B':
            balancing_mode = MK_TRUE;
            break;
        case 'T':
            allow_shared_sockets = MK_TRUE;
            break;
        case 'l':
            plugin_load_conf_file = optarg;
            break;
        case '?':
            mk_help(EXIT_FAILURE);
        }
    }

    /*
     * Initialize global configuration context. The variable mk_config
     * is provided by mk_server and it's unique. You don't need multiple
     * Monkey instances when Monkey already support multi ports and flexible
     * configuration.
     *
     * Once is created, we need to start populating some relevant configuration
     * fields that will affect the server behavior.
     */
    mk_config = mk_server_init();

    /* set configuration path */
    if (!path_config) {
        mk_config->path_config = MK_PATH_CONF;
    }
    else {
        mk_config->path_config = path_config;
    }

    /* set target configuration file for the server */
    if (!server_conf_file) {
        mk_config->server_conf_file = MK_DEFAULT_CONFIG_FILE;
    }
    else {
        mk_config->server_conf_file = server_conf_file;
    }

    if (!pid_file) {
        mk_config->pid_file_path = NULL;
    }
    else {
        mk_config->pid_file_path = pid_file;
    }

    if (run_daemon) {
        mk_config->is_daemon = MK_TRUE;
    }
    else {
        mk_config->is_daemon = MK_FALSE;
    }

    if (!mimes_conf_file) {
        mk_config->mimes_conf_file = MK_DEFAULT_MIMES_CONF_FILE;
    }
    else {
        mk_config->mimes_conf_file = mimes_conf_file;
    }

    if (!plugin_load_conf_file) {
        mk_config->plugin_load_conf_file = MK_DEFAULT_PLUGIN_LOAD_CONF_FILE;
    }
    else {
        mk_config->plugin_load_conf_file = plugin_load_conf_file;
    }

    if (!sites_conf_dir) {
        mk_config->sites_conf_dir = MK_DEFAULT_SITES_CONF_DIR;
    }
    else {
        mk_config->sites_conf_dir = sites_conf_dir;
    }

    if (!plugins_conf_dir) {
        mk_config->plugins_conf_dir = MK_DEFAULT_PLUGINS_CONF_DIR;
    }
    else {
        mk_config->plugins_conf_dir = plugins_conf_dir;
    }

    /* Override some configuration */
    mk_config->one_shot = one_shot;
    mk_config->port_override = port_override;
    mk_config->transport_layer = transport_layer;

    mk_version();
    mk_signal_init();

    /* Override number of thread workers */
    if (workers_override >= 0) {
        mk_config->workers = workers_override;
    }
    else {
        mk_config->workers = -1;
    }

    if (balancing_mode == MK_TRUE) {
        mk_config->scheduler_mode = MK_SCHEDULER_FAIR_BALANCING;
    }


    /* Running Monkey as daemon */
    if (mk_config->is_daemon == MK_TRUE) {
        mk_utils_set_daemon();
    }

    if (mk_config->scheduler_mode == MK_SCHEDULER_REUSEPORT &&
        mk_config_listen_check_busy(mk_config) == MK_TRUE &&
        allow_shared_sockets == MK_FALSE) {
        mk_warn("Some Listen interface is busy, re-try using -T. Aborting.");
        exit(EXIT_FAILURE);
    }

    /*
     * Once the all configuration is set, let mk_server configure the
     * internals. Not accepting connections yet.
     */
    mk_server_setup();

    /* Register PID of Monkey */
    mk_utils_register_pid(mk_config->pid_file_path);

    /* Print server details */
    mk_server_info();

    /* Change process owner */
    mk_user_set_uidgid();

    /* Server loop, let's listen for incomming clients */
    mk_server_loop();

    mk_mem_free(mk_config);

    return 0;
}
