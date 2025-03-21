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

#include <sys/socket.h>
#include <sys/un.h>

/* Monkey Plugin Interface */
#include "cheetah.h"
#include "cutils.h"
#include "cmd.h"
#include "loop.h"

void mk_cheetah_loop_stdin(struct mk_server *server)
{
    int len;
    char cmd[200];
    char line[200];
    char *rcmd;

    mk_cheetah_welcome_msg();

    while (1) {
        CHEETAH_WRITE(MK_CHEETAH_PROMPT, ANSI_BOLD, ANSI_GREEN, ANSI_RESET);

        rcmd = fgets(line, sizeof(line), cheetah_input);
        if (!rcmd) {
            continue;
        }

        len = strlen(line);

        if (len == 0){
            CHEETAH_WRITE("\n");
            mk_cheetah_cmd_quit();
        }

        strncpy(cmd, line, len - 1);
        cmd[len - 1] = '\0';

        mk_cheetah_cmd(cmd, server);
        memset(line, '\0', sizeof(line));
    }
}

void mk_cheetah_loop_server(struct mk_server *server)
{
    int n, ret;
    int buf_len;
    unsigned long len;
    char buf[1024];
    char cmd[1024];
    int server_fd;
    int remote_fd;
    size_t address_length;
    struct sockaddr_un address;
    socklen_t socket_size = sizeof(struct sockaddr_in);
    struct mk_config_listener *listener;

    /* Create listening socket */
    server_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    listener = mk_list_entry_first(&mk_api->config->listeners,
                                   struct mk_config_listener,
                                 _head);
    cheetah_server = NULL;
    mk_api->str_build(&cheetah_server, &len, "/tmp/cheetah.%s",
                      listener->port);
    unlink(cheetah_server);

    address.sun_family = AF_UNIX;
    sprintf(address.sun_path, "%s", cheetah_server);
    address_length = sizeof(address.sun_family) + len + 1;

    if (bind(server_fd, (struct sockaddr *) &address, address_length) != 0) {
        perror("bind");
        mk_err("Cheetah: could not bind address %s", address.sun_path);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) != 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while (1) {
        /* Listen for incoming connections */
        remote_fd = accept(server_fd, (struct sockaddr *) &address, &socket_size);
        cheetah_socket = remote_fd;

        buf_len = 0;
        memset(buf, '\0', 1024);

        /* Send welcome message and prompt */
        mk_cheetah_welcome_msg();
        CHEETAH_WRITE(MK_CHEETAH_PROMPT, ANSI_BOLD, ANSI_GREEN, ANSI_RESET);

        while (1) {
            /* Read incoming data */
            n = read(remote_fd, buf+buf_len, 1024 - buf_len);
            if (n <= 0) {
                break;
            }
            else {
              buf_len += n;
              if (buf[buf_len-1] == '\n') {
                  /* Filter command */
                  strncpy(cmd, buf, buf_len - 1);
                  cmd[buf_len - 1] = '\0';

                  /* Run command */
                  ret = mk_cheetah_cmd(cmd, server);

                  if (ret == -1) {
                      break;
                  }

                  /* Write prompt */
                  CHEETAH_WRITE(MK_CHEETAH_PROMPT, ANSI_BOLD, ANSI_GREEN, ANSI_RESET);
                  buf_len = 0;
                  memset(buf, '\0', 1024);
              }
            }
        }

        close(remote_fd);
    }
}
