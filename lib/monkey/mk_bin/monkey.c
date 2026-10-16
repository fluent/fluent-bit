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

#include "monkey.h"
#include "mk_signals.h"

#include <signal.h>
#include <getopt.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

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
    printf("Home  : https://monkeywebserver.com\n");
    fflush(stdout);
}

static void mk_build_info(void)
{
    struct mk_list *head;
    struct mk_plugin *p;
    struct mk_server *server;

    mk_version();

    printf("\n");
    printf("%s[system: %s]%s\n", ANSI_BOLD, MK_BUILD_OS, ANSI_RESET);
    printf("%s", MK_BUILD_UNAME);

    printf("\n\n%s[configure]%s\n", ANSI_BOLD, ANSI_RESET);
    printf("%s", MK_BUILD_CMD);

    printf("\n\n%s[setup]%s\n", ANSI_BOLD, ANSI_RESET);
    printf("configuration dir: %s\n", MK_PATH_CONF);

    /* Initialize list */
    server  = mk_mem_alloc(sizeof(struct mk_server));
    mk_list_init(&server->plugins);
    mk_plugin_load_static(server);

    printf("\n\n%s[built-in plugins]%s\n", ANSI_BOLD, ANSI_RESET);
    mk_list_foreach(head, &server->plugins) {
        p = mk_list_entry(head, struct mk_plugin, _head);
        printf("%-20s%s\n", p->shortname, p->name);
    }
    mk_mem_free(server);
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
    printf("      --https\t\t\t\tenable HTTPS on configured listeners\n");
    printf("      --tls-cert=FILE\t\t\tset TLS certificate file\n");
    printf("      --tls-key=FILE\t\t\tset TLS private key file\n");
    printf("      --tls-chain=FILE\t\t\tset TLS certificate chain file\n");
    printf("      --tls-dh=FILE\t\t\tset TLS DH parameters file\n");
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
    printf("  https://monkeywebserver.com/documentation\n\n");

    exit(rc);
}

static int mk_dir_exists(const char *path)
{
    struct stat st;

    if (path == NULL || path[0] == '\0') {
        return MK_FALSE;
    }

    if (stat(path, &st) == -1) {
        return MK_FALSE;
    }

    if (S_ISDIR(st.st_mode) == 0) {
        return MK_FALSE;
    }

    return MK_TRUE;
}

static const char *mk_default_config_dir(char *buf, size_t size, const char *argv0)
{
    char exe_path[PATH_MAX];
    char candidate[PATH_MAX];
    char *last_slash;
    int written;
    ssize_t len;

    if (mk_dir_exists("conf") == MK_TRUE) {
        if (realpath("conf", buf) != NULL) {
            return buf;
        }

        written = snprintf(buf, size, "%s", "conf");
        if (written < 0 || (size_t) written >= size) {
            return NULL;
        }
        return buf;
    }

    if (MK_PATH_CONF[0] != '\0' && mk_dir_exists(MK_PATH_CONF) == MK_TRUE) {
        written = snprintf(buf, size, "%s", MK_PATH_CONF);
        if (written < 0 || (size_t) written >= size) {
            return NULL;
        }
        return buf;
    }

    len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
    }
    else if (argv0 != NULL && realpath(argv0, exe_path) != NULL) {
        len = strlen(exe_path);
    }
    else {
        return NULL;
    }

    last_slash = strrchr(exe_path, '/');
    if (last_slash == NULL) {
        return NULL;
    }
    *last_slash = '\0';

    written = snprintf(candidate, sizeof(candidate), "%s/../conf", exe_path);
    if (written < 0 || (size_t) written >= sizeof(candidate)) {
        return NULL;
    }
    if (mk_dir_exists(candidate) == MK_TRUE) {
        if (realpath(candidate, buf) != NULL) {
            return buf;
        }

        written = snprintf(buf, size, "%s", candidate);
        if (written < 0 || (size_t) written >= size) {
            return NULL;
        }
        return buf;
    }

    written = snprintf(candidate, sizeof(candidate), "%s/conf", exe_path);
    if (written < 0 || (size_t) written >= sizeof(candidate)) {
        return NULL;
    }
    if (mk_dir_exists(candidate) == MK_TRUE) {
        if (realpath(candidate, buf) != NULL) {
            return buf;
        }

        written = snprintf(buf, size, "%s", candidate);
        if (written < 0 || (size_t) written >= size) {
            return NULL;
        }
        return buf;
    }

    return NULL;
}

/* MAIN */
int main(int argc, char **argv)
{
    int opt;
    int enable_https = MK_FALSE;
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
    char *tls_cert_file = NULL;
    char *tls_key_file = NULL;
    char *tls_chain_file = NULL;
    char *tls_dh_file = NULL;
    char default_config_dir[PATH_MAX];
    const char *resolved_config_dir;
    struct mk_server *server;

    enum {
        MK_OPT_HTTPS = 1000,
        MK_OPT_TLS_CERT,
        MK_OPT_TLS_KEY,
        MK_OPT_TLS_CHAIN,
        MK_OPT_TLS_DH
    };

    static const struct option long_opts[] = {
        { "configdir",              required_argument,  NULL, 'c' },
        { "serverconf",             required_argument,  NULL, 's' },
        { "build",                  no_argument,        NULL, 'b' },
        { "daemon",                 no_argument,        NULL, 'D' },
        { "https",                  no_argument,        NULL, MK_OPT_HTTPS },
        { "pid-file",               required_argument,  NULL, 'I' },
        { "port",                   required_argument,  NULL, 'p' },
        { "one-shot",               required_argument,  NULL, 'o' },
        { "tls-cert",               required_argument,  NULL, MK_OPT_TLS_CERT },
        { "tls-key",                required_argument,  NULL, MK_OPT_TLS_KEY },
        { "tls-chain",              required_argument,  NULL, MK_OPT_TLS_CHAIN },
        { "tls-dh",                 required_argument,  NULL, MK_OPT_TLS_DH },
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
            break;
        case 'D':
            run_daemon = 1;
            break;
        case MK_OPT_HTTPS:
            enable_https = MK_TRUE;
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
        case MK_OPT_TLS_CERT:
            tls_cert_file = mk_string_dup(optarg);
            break;
        case MK_OPT_TLS_KEY:
            tls_key_file = mk_string_dup(optarg);
            break;
        case MK_OPT_TLS_CHAIN:
            tls_chain_file = mk_string_dup(optarg);
            break;
        case MK_OPT_TLS_DH:
            tls_dh_file = mk_string_dup(optarg);
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
     * Initialize Monkey Server context. Once is created, we need to start
     * populating some relevant configuration fields that will affect the
     * server behavior.
     */
    server = mk_server_create();

    /* set configuration path */
    if (path_config != NULL) {
        server->path_conf_root = path_config;
    }
    else {
        resolved_config_dir = mk_default_config_dir(default_config_dir,
                                                    sizeof(default_config_dir),
                                                    argv[0]);
        server->path_conf_root = (char *) resolved_config_dir;
    }

    /* set target configuration file for the server */
    if (!server_conf_file) {
        server->conf_main = MK_DEFAULT_CONFIG_FILE;
    }
    else {
        server->conf_main = server_conf_file;
    }

    if (!pid_file) {
        server->path_conf_pidfile = NULL;
    }
    else {
        server->path_conf_pidfile = pid_file;
    }

    if (run_daemon) {
        server->is_daemon = MK_TRUE;
    }
    else {
        server->is_daemon = MK_FALSE;
    }

    if (!mimes_conf_file) {
        server->conf_mimetype = MK_DEFAULT_MIMES_CONF_FILE;
    }
    else {
        server->conf_mimetype = mimes_conf_file;
    }

    if (!plugin_load_conf_file) {
        server->conf_plugin_load = MK_DEFAULT_PLUGIN_LOAD_CONF_FILE;
    }
    else {
        server->conf_plugin_load = plugin_load_conf_file;
    }

    if (!sites_conf_dir) {
        server->conf_sites = MK_DEFAULT_SITES_CONF_DIR;
    }
    else {
        server->conf_sites = sites_conf_dir;
    }

    if (!plugins_conf_dir) {
        server->conf_plugins = MK_DEFAULT_PLUGINS_CONF_DIR;
    }
    else {
        server->conf_plugins = plugins_conf_dir;
    }

    /* Override some configuration */
    server->one_shot = one_shot;
    server->port_override = port_override;
    server->transport_layer = transport_layer;
    server->tls_mode = enable_https;
    server->tls_cert_file = tls_cert_file;
    server->tls_cert_chain_file = tls_chain_file;
    server->tls_key_file = tls_key_file;
    server->tls_dh_param_file = tls_dh_file;

    mk_version();
    mk_signal_init(server);

    /* Override number of thread workers */
    if (workers_override >= 0) {
        server->workers = workers_override;
    }
    else {
        server->workers = -1;
    }

    if (balancing_mode == MK_TRUE) {
        server->scheduler_mode = MK_SCHEDULER_FAIR_BALANCING;
    }


    /* Running Monkey as daemon */
    if (server->is_daemon == MK_TRUE) {
        mk_utils_set_daemon();
    }

    if (server->scheduler_mode == MK_SCHEDULER_REUSEPORT &&
        mk_config_listen_check_busy(server) == MK_TRUE &&
        allow_shared_sockets == MK_FALSE) {
        mk_warn("Some Listen interface is busy, re-try using -T. Aborting.");
        exit(EXIT_FAILURE);
    }

    /*
     * Once the all configuration is set, let mk_server configure the
     * internals. Not accepting connections yet.
     */
    if (mk_server_setup(server) != 0) {
        mk_err("Startup aborted due to configuration/setup failure.");
        return EXIT_FAILURE;
    }

    /* Register PID of Monkey */
    mk_utils_register_pid(server->path_conf_pidfile);

    /* Print server details */
    mk_server_info(server);

    /* Change process owner */
    mk_user_set_uidgid(server);

    /* Server loop, let's listen for incomming clients */
    mk_server_loop(server);

    /* Hang here, basically do nothing as threads are doing the job. */
    sigset_t mask;
    sigprocmask(0, NULL, &mask);
    sigsuspend(&mask);

    return 0;
}
