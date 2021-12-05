/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Demo
 *  ===============
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
 *  limitations under the License
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


#define VERBOSE
#define SERVER_SOCK_PATH "/tmp/fb_sock_server"
#define CLIENT_SOCK_PATH "/tmp/fb_sock_client"

// To check sockets cleanup

typedef struct in_plugin_data_t {
    char * buffer_ptr;
    char * server_addr;
} in_plugin_data_t;

void get_socket_path(const char* name, const char* postfix, char* result) {
    char pid_str[16];
    sprintf(pid_str, "%d", getpid());
    strncpy(result, name, strlen(name));
    strcat(result, "_");
    strcat(result, pid_str);
    strcat(result, "_");
    strcat(result, postfix);
}



// TBD(romanpr): refactor
typedef struct raw_msgpack_api_context_t {
    char client_addr[256];
    char server_addr[256];

    flb_ctx_t *ctx;
    struct flb_input_instance *i_ins;

    int in_ffd;
    int out_ffd;

    int doorbell_cli;
    char *buffer;
} raw_msgpack_api_context_t;


typedef struct doorbell_msg_t {
    int data_len;
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
        printf("Failed to create client unix sock\n");
        return -1;
    }
#ifdef VERBOSE
    printf("Creating Unix Domain socket: %s,  socket=%d\n", sock_path, socket_fd);
#endif
    memset(&client_address, 0, sizeof(struct sockaddr_un));
    client_address.sun_family = AF_UNIX;
    strcpy(client_address.sun_path, sock_path);
    // strcpy(client_address.sun_path, "./UDSDGCLNT");

    unlink(sock_path);
    if (bind(socket_fd, (const struct sockaddr *) &client_address, sizeof(struct sockaddr_un)) < 0) {
        close(socket_fd);
        printf("Failed to bind client unix sock\n");
        return -1;
    }
    return socket_fd;
}


bool ring_doorbell(raw_msgpack_api_context_t* raw_ctx, int client_fd, int data_len) {
    doorbell_msg_t ring_msg;
    ring_msg.data_len = data_len;
    int msg_len = sizeof(ring_msg);

    socklen_t address_length = sizeof(struct sockaddr_un);
    struct sockaddr_un server_address;

    int bytes_sent;
    int bytes_received;

    memset(&server_address, 0, address_length);
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, raw_ctx->server_addr);

    // TBD(romanpr): to put timeout on socket
    bytes_sent     = sendto(client_fd,
                            (char *) &ring_msg, msg_len,
                            0, (struct sockaddr *) &server_address,
                            address_length);
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


void* init(const char* output_plugin_name, const char * host, const char * port, const char * socket_prefix) {
    raw_msgpack_api_context_t* raw_ctx = malloc(sizeof(raw_msgpack_api_context_t));

    char postfix[128] = "";
    if (strlen(socket_prefix) > 0) {
        strcpy(postfix, socket_prefix);
    } else {
        strcat(postfix, "-");
        printf("Warning: no socket prefix");
    }
    strcat(postfix, "_");
    if (strlen(output_plugin_name) > 0) {
        strcat(postfix, output_plugin_name);
    } else {
        strcat(postfix, "defPlugin");
    }
    strcat(postfix, "_");
    if (strlen(host) > 0) {
        strcat(postfix, host);
    } else {
        strcat(postfix, "defHost");
    }
    strcat(postfix, "_");
    if (strlen(host) > 0) {
        strcat(postfix, port);
    } else {
        strcat(postfix, "defPort");
    }
    get_socket_path(CLIENT_SOCK_PATH, postfix, raw_ctx->client_addr );
    get_socket_path(SERVER_SOCK_PATH, postfix, raw_ctx->server_addr);

    printf("API raw msgpack: init\n");
    printf("Input %s:%s\n\n", host, port);

#ifdef VERBOSE
    printf("hello-word-init\n");
    printf("input: %s:%s\n\n", host, port);

    printf("\n\n\n\nsocket path: \"%s\" -> \"%s\"\n", CLIENT_SOCK_PATH, raw_ctx->client_addr);
    printf("server path: \"%s\" -> \"%s\"\n\n", SERVER_SOCK_PATH, raw_ctx->server_addr);
#endif

    /* Initialize library */
    raw_ctx->ctx = flb_create();
#ifdef VERBOSE
    printf("ctx = %p\n", raw_ctx->ctx);
#endif
    if (!raw_ctx->ctx) {
        return NULL;
    }
    flb_service_set(raw_ctx->ctx, "Flush", "1", NULL); // to set flush timeout
    flb_service_set(raw_ctx->ctx, "Grace", "1", NULL);   // to set timeout before exit

    // TBD(romanpr): find out why does it not work (see cio_file.c and flb_input_chunk.c)
    // flb_service_set(ctx, "storage.path", "/labhome/romanpr/log/flb-storage", NULL);
    // flb_service_set(ctx, "storage.sync", "normal", NULL);
    // flb_service_set(ctx, "storage.checksum", "off", NULL);
    // flb_service_set(ctx, "storage.backlog.mem_limit", "1024M", NULL);

    // create a client socket here to be ready to ring to "doorbell"
    raw_ctx->doorbell_cli = ipc_unix_sock_cli_create(raw_ctx->client_addr);
#ifdef VERBOSE
    printf("created client sock %d\n", raw_ctx->doorbell_cli);
#endif
    in_plugin_data_t *in_data = (in_plugin_data_t *) calloc(1, sizeof(in_plugin_data_t));

    raw_ctx->buffer = (char*) calloc(8192 * 2, sizeof(char));
    in_data->buffer_ptr  = raw_ctx->buffer;
    in_data->server_addr = raw_ctx->server_addr;
    raw_ctx->i_ins = flb_input_new(raw_ctx->ctx->config, "raw_msgpack", (void *) in_data, FLB_TRUE);

#ifdef VERBOSE
    printf("i_ins = %p\n", raw_ctx->i_ins);
    printf("i_ins->data = %p\n", raw_ctx->i_ins->data);
#endif
    if (!raw_ctx->i_ins) {
        return NULL;
    }

    // TBD(romanpr): docs.fluentbit.io/manual/administration/buffering-and-storage
    // flb_input_set(ctx, i_ins->id, "storage.type", "filesystem", NULL);
    // TBD(romanpr): get the out plugin name from environment
    // TBD(romanpr): test with Elastic AND with InfluxDB

    raw_ctx->out_ffd = -1;
    if (strlen(output_plugin_name) > 0) {  // simple check for plugin name
        raw_ctx->out_ffd = flb_output(raw_ctx->ctx, output_plugin_name, NULL);
    }
    if (raw_ctx->out_ffd == -1) {
        // if cannot find 'output_plugin_name' plugin, use default 'forward'
        raw_ctx->out_ffd = flb_output(raw_ctx->ctx, "forward", NULL);
    }

#ifdef VERBOSE
    printf("out_ffd = %d\n", raw_ctx->out_ffd);
#endif
    // flb_output_set(ctx, out_ffd, "match", "test", NULL);

    flb_output_set(raw_ctx->ctx, raw_ctx->out_ffd, "Host", host, NULL);
    flb_output_set(raw_ctx->ctx, raw_ctx->out_ffd, "Port", port, NULL);

    // Start the background worker
    flb_start(raw_ctx->ctx);
#ifdef VERBOSE
    printf("init finished\n\n");
#endif
    return (void*) raw_ctx;
}


int add_data(void* api_raw_ctx, void* data, int len) {
    if (api_raw_ctx == NULL)
        return -1;

    raw_msgpack_api_context_t* raw_ctx = (raw_msgpack_api_context_t*) api_raw_ctx;
    if (len == 0)
        return 0;
#ifdef VERBOSE
    // printf("Append raw data of len %d:\n", len);
    // DumpHex(data, len);
#endif
    memcpy(raw_ctx->buffer, data, len);
    // TBD(romanpr): check this:  i_ins->context->p = data;

#ifdef VERBOSE
    //printf("ring the doorbell\n");
#endif
    ring_doorbell(raw_ctx, raw_ctx->doorbell_cli, len);

    return 0;
}


int finalize(void* api_raw_ctx) {
    if (api_raw_ctx == NULL)
        return -1;
    raw_msgpack_api_context_t* raw_ctx = (raw_msgpack_api_context_t*) api_raw_ctx;

#ifdef VERBOSE
    printf("API raw msgpack: finalize\n");
    printf("\t\t\t\t\t\tserver_addr '%s'\n", raw_ctx->server_addr);
    printf("\t\t\t\t\t\tbuffer_addr '%p'\n", raw_ctx->buffer);
#endif
    // clean up socket
    unlink(raw_ctx->client_addr);
    close(raw_ctx->doorbell_cli);
    // finilize fluent bit
    flb_stop(raw_ctx->ctx);

    if (raw_ctx->buffer)
        free(raw_ctx->buffer);
    flb_destroy(raw_ctx->ctx);
    return 0;
}


// msgpack_sbuffer generate_message_pack(n) {
//     msgpack_sbuffer sbuf;
//     msgpack_sbuffer_init(&sbuf);

//     /* serialize values into the buffer using msgpack_sbuffer_write callback function. */
//     msgpack_packer pk;
//     msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

//     // pack array what will contain (n+2) values(ints/booleans/strings)
//     msgpack_pack_array(&pk, n + 2);

//     int i;
//     for (i = 0; i < n; i++)
//         msgpack_pack_int(&pk, i);

//     // pack the boolean
//     msgpack_pack_true(&pk);

//     // pack string (size and body)
//     msgpack_pack_str(&pk, 11);
//     msgpack_pack_str_body(&pk, "test_plugin", 11);

//     return sbuf;
// }

// void dump_packed_message(msgpack_sbuffer sbuf, FILE *out) {
//     /* deserialize the buffer into msgpack_object instance. */
//     /* deserialized object is valid during the msgpack_zone instance alive. */
//     msgpack_zone mempool;
//     msgpack_zone_init(&mempool, 2048);

//     msgpack_object deserialized;
//     msgpack_unpack(sbuf.data, sbuf.size, NULL, &mempool, &deserialized);

//     /* print the deserialized object. */
//     msgpack_object_print(out, deserialized);
//     puts("");

//     msgpack_zone_destroy(&mempool);
// }

// int main()
// {
//     return 0;
// }
