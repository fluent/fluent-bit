/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 *  Copyright (C) 2015 Treasure Data Inc.
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
 *
 *  Modified Work:
 *
 *  Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 *  This software product is a proprietary product of NVIDIA CORPORATION &
 *  AFFILIATES (the "Company") and all right, title, and interest in and to the
 *  software product, including all associated intellectual property rights, are
 *  and shall remain exclusively with the Company.
 *
 *  This software product is governed by the End User License Agreement
 *  provided with the software product.
 *
 */

#include <fluent-bit.h>

#define _OPEN_SYS_ITOA_EXT
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>


// #define VERBOSE
#define SERVER_SOCK_PATH "/tmp/fb_sock_server"
#define CLIENT_SOCK_PATH "/tmp/fb_sock_client"


// structures for list on key/val pairs of plugin parameters
typedef struct param_pair_t {
    char* name;
    char* val;
} param_pair_t;

typedef struct plugin_params_t {
    int num_params;
    param_pair_t* params;
} plugin_params_t;
// =====================================

typedef struct in_plugin_data_t {
    char * buffer_ptr;
    char * server_addr;
} in_plugin_data_t;


void get_socket_path(const char* name, const char* postfix, char* result) {
    sprintf(result, "%s_%d_%s", name, getpid(), postfix);
}


typedef struct raw_msgpack_api_context_t {
    char client_addr[256];
    char server_addr[256];

    flb_ctx_t *ctx;
    // struct flb_input_instance *i_ins;

    int in_ffd;
    int out_ffd;

    int doorbell_cli;
} raw_msgpack_api_context_t;


typedef struct doorbell_msg_t {
    int   data_len;
    char* buffer;
} doorbell_msg_t;


#if 1
#include <stdio.h>

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
#endif


int ipc_unix_sock_cli_create(char *sock_path) {
    int socket_fd;
    struct sockaddr_un client_address;

    if ((socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
        printf("[Raw Msgpack API] Failed to create client unix sock\n");
        return -1;
    }
#ifdef VERBOSE
    printf("[Raw Msgpack API] Creating Unix Domain socket: %s,  socket=%d\n", sock_path, socket_fd);
#endif
    memset(&client_address, 0, sizeof(struct sockaddr_un));
    client_address.sun_family = AF_UNIX;
    strcpy(client_address.sun_path, sock_path);
    // strcpy(client_address.sun_path, "./UDSDGCLNT");

    unlink(sock_path);
    if (bind(socket_fd, (const struct sockaddr *) &client_address, sizeof(struct sockaddr_un)) < 0) {
        close(socket_fd);
        printf("[Raw Msgpack API] Failed to bind client unix sock\n");
        return -1;
    }
    return socket_fd;
}


bool ring_doorbell(raw_msgpack_api_context_t* raw_ctx, int client_fd, int data_len, char* data_buf) {
    doorbell_msg_t ring_msg;
    ring_msg.data_len = data_len;
    ring_msg.buffer   = data_buf;
    int msg_len = sizeof(ring_msg);

    socklen_t address_length = sizeof(struct sockaddr_un);
    struct sockaddr_un server_address;

    int bytes_sent;
    int bytes_received;

    memset(&server_address, 0, address_length);
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, raw_ctx->server_addr);

    bytes_sent     = sendto(client_fd,
                            (char *) &ring_msg, msg_len,
                            0, (struct sockaddr *) &server_address,
                            address_length);
    (void) bytes_sent;

    // printf("bytes_sent = %d \n", bytes_sent);

    bytes_received = recvfrom(client_fd,
                              (char *) &ring_msg, msg_len,
                              0, (struct sockaddr *) &(server_address),
                              &address_length);

    if (bytes_received != msg_len) {
        // printf("bytes_received: wrong size datagram\n");
        return false;
    }

    return true;
}


void prepare_socket_names(raw_msgpack_api_context_t* raw_ctx, const char* output_plugin_name,
                          const char * host, const char * port, const char * socket_prefix) {
    char postfix[128] = "";
    bool is_prefix = strlen(socket_prefix) > 0;
    bool is_plugin = strlen(output_plugin_name) > 0;
    bool is_host = strlen(host) > 0;
    bool is_port = strlen(port) > 0;

    sprintf(postfix, "%s_%s_%s_%s_%p",
            (is_prefix ? socket_prefix      : "-"),
            (is_plugin ? output_plugin_name : "defPluguin"),
            (is_host   ? host               : "defHost"),
            (is_port   ? port               : "defPort"),
            (void*) raw_ctx);

    get_socket_path(CLIENT_SOCK_PATH, postfix, raw_ctx->client_addr );
    get_socket_path(SERVER_SOCK_PATH, postfix, raw_ctx->server_addr);


#ifdef VERBOSE
    printf("[Raw Msgpack API] client socket path: \"%s\" -> \"%s\"\n", CLIENT_SOCK_PATH, raw_ctx->client_addr);
    printf("[Raw Msgpack API] server socket path: \"%s\" -> \"%s\"\n", SERVER_SOCK_PATH, raw_ctx->server_addr);
#endif
}


void* init(const char* output_plugin_name, const char * host, const char * port,
           void* plugin_params, const char * socket_prefix) {
#ifdef VERBOSE
    printf("[Raw Msgpack API] Initialization started.\n");
#endif

    plugin_params_t* params = (plugin_params_t *) plugin_params;
    raw_msgpack_api_context_t* raw_ctx = malloc(sizeof(raw_msgpack_api_context_t));

    prepare_socket_names(raw_ctx, output_plugin_name, host, port, socket_prefix);

    /* Initialize library */
    raw_ctx->ctx = flb_create();
    if (!raw_ctx->ctx) {
        printf("[Raw Msgpack API] could not create flb context. Returning Null.\n");
        return NULL;
    }
    flb_service_set(raw_ctx->ctx, "Flush", "0.1", NULL);
    flb_service_set(raw_ctx->ctx, "Grace", "1", NULL);

    // create a client socket here to be ready to ring to "doorbell"
    raw_ctx->doorbell_cli = ipc_unix_sock_cli_create(raw_ctx->client_addr);
#ifdef VERBOSE
    printf("[Raw Msgpack API] created client sock %d\n", raw_ctx->doorbell_cli);
#endif
    in_plugin_data_t *in_data = (in_plugin_data_t *) calloc(1, sizeof(in_plugin_data_t));

    in_data->server_addr = raw_ctx->server_addr;
    // raw_ctx->i_ins = flb_input_new(raw_ctx->ctx->config, "raw_msgpack", (void *) in_data, FLB_TRUE);
    // if (!raw_ctx->i_ins) {
    //     return NULL;
    // }
    raw_ctx->in_ffd = flb_input(raw_ctx->ctx, "raw_msgpack", (void *) in_data);

    raw_ctx->out_ffd = -1;
    if (strlen(output_plugin_name) > 0) {  // simple check for plugin name
        raw_ctx->out_ffd = flb_output(raw_ctx->ctx, output_plugin_name, NULL);
    }
    if (raw_ctx->out_ffd == -1) {
        // if cannot find 'output_plugin_name' plugin, use default 'forward'
        raw_ctx->out_ffd = flb_output(raw_ctx->ctx, "forward", NULL);
    }

    flb_output_set(raw_ctx->ctx, raw_ctx->out_ffd, "Host", host, NULL);
    flb_output_set(raw_ctx->ctx, raw_ctx->out_ffd, "Port", port, NULL);

    if (params != NULL) {
        int i;
        if (params->num_params > 0) {
            printf("\n[Raw Msgpack API] Setting '%s' ouptut plugin parameters:\n", output_plugin_name);
        }
        for (i = 0; i < params->num_params; i++) {
            printf("\t\t\t\t'%s' to '%s'\n", params->params[i].name, params->params[i].val);
	    if (strcmp(params->params[i].name, "tag_match_pair") != 0) {
                flb_output_set(raw_ctx->ctx, raw_ctx->out_ffd, params->params[i].name, params->params[i].val, NULL);
            } else {
                flb_input_set(raw_ctx->ctx, raw_ctx->in_ffd, "tag", params->params[i].val, NULL);
                flb_output_set(raw_ctx->ctx, raw_ctx->out_ffd, "match", params->params[i].val, NULL);
            }
        }
    }

    // Start the background worker
    flb_start(raw_ctx->ctx);
#ifdef VERBOSE
    printf("[Raw Msgpack API] init finished\n\n");
#endif
    free(in_data);
    return (void*) raw_ctx;
}


int add_data(void* api_ctx, void* data, int len) {
    if (api_ctx == NULL) {
        return -1;
    }

    raw_msgpack_api_context_t* raw_ctx = (raw_msgpack_api_context_t*) api_ctx;
    if (len == 0) {
        return 0;
    }
#ifdef VERBOSE
    //printf("Append raw data of len %d\n", len);
    // DumpHex(data, len);
#endif
    ring_doorbell(raw_ctx, raw_ctx->doorbell_cli, len, (char*) data);
    return 0;
}


int finalize(void* api_ctx) {
    if (api_ctx == NULL) {
        return -1;
    }
    raw_msgpack_api_context_t* raw_ctx = (raw_msgpack_api_context_t*) api_ctx;

#ifdef VERBOSE
    printf("[Raw Msgpack API] finalize\n");
    // printf("\t\t\t\t\t\tserver_addr '%s'\n", raw_ctx->server_addr);
    // printf("\t\t\t\t\t\tbuffer_addr '%p'\n", raw_ctx->buffer);
#endif
    // clean up socket
    close(raw_ctx->doorbell_cli);
    unlink(raw_ctx->client_addr);
    // finilize fluent bit
    flb_stop(raw_ctx->ctx);
    flb_destroy(raw_ctx->ctx);
    return 0;
}
