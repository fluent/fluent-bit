/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_parser.h>
#include <msgpack.h>

#ifdef FLB_HAVE_UNIX_SOCKET
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include "docker_events.h"
#include "docker_events_config.h"

static char *teststring = "{\"status\":\"destroy\"}}";
//,\"id\":\"96351167acbe7f780e2b61b1278d6101638d491f47c322cd06cfb833c2e2fee5\",\"from\":\"f320942d9673\",\"Type\":\"container\",\"Action\":\"destroy\"}";

static const char *tag = "docker_events";

#ifdef FLB_HAVE_UNIX_SOCKET
static int de_unix_create( struct flb_in_de_config *ctx )
{
   flb_sockfd_t fd = -1;
   unsigned long len;
   size_t address_length;
   struct sockaddr_un address;
   char request[512];

   fd = flb_net_socket_create(AF_UNIX, FLB_TRUE);
   if ( fd == -1 )
   {
      return -1;
   }

   ctx->fd = fd;

   /* Prepare the unix socket path */
   unlink(ctx->unix_path);
   len = strlen(ctx->unix_path);

   address.sun_family = AF_UNIX;
   sprintf(address.sun_path, "%s", ctx->unix_path);
   address_length = sizeof(address.sun_family) + len + 1;

   if ( connect(fd, (struct sockaddr *)&address, address_length) == -1 )
   {
      flb_errno();
      close(fd);
      return -1;
   }

   strcpy(request, "GET /events HTTP/1.0\r\n\r\n");

   flb_plg_info(ctx->ins, "writing to socket %s", request);

   write(fd, request, strlen(request));

   read(ctx->fd, ctx->buf, ctx->buf_size - 1);

   return 0;
}
#endif

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new FW instance which will wait for
 * MessagePack records.
 */
static int in_de_collect( struct flb_input_instance *ins,
                          struct flb_config *config, void *in_context )
{
   struct de_conn *conn;
   struct flb_in_de_config *ctx = in_context;
   msgpack_packer mp_pck;
   msgpack_sbuffer mp_sbuf;
   size_t str_len = 0;

   /* variables for parser */
   int parser_ret = -1;
   void *out_buf = NULL;
   size_t out_size = 0;
   struct flb_time out_time;

   flb_plg_trace(ctx->ins, "Entering...");

#if 1
   memset(ctx->buf, 0, ctx->buf_size);
   if ( read(ctx->fd, ctx->buf, ctx->buf_size - 1) != 0 )
   {
      str_len = strnlen(ctx->buf, ctx->buf_size);

      flb_plg_trace(ctx->ins, "str_len: %d sizeof(tag): %d", str_len, strlen(tag));

      //ctx->buf[str_len] = '\0'; /* chomp */

      /* Initialize local msgpack buffer */
#if 1
      msgpack_sbuffer_init(&mp_sbuf);
      msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

      msgpack_pack_array(&mp_pck, 2);
      flb_pack_time_now(&mp_pck);
      msgpack_pack_map(&mp_pck, 1);

      msgpack_pack_str(&mp_pck, strlen(tag));
      msgpack_pack_str_body(&mp_pck, tag, strlen(tag));
      msgpack_pack_str(&mp_pck, str_len);
      msgpack_pack_str_body(&mp_pck, ctx->buf, str_len);

      flb_input_chunk_append_raw(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);

      msgpack_sbuffer_destroy(&mp_sbuf);
#else
      in_stream_processor_add_chunk(ctx->buf, str_len, ins);

#endif

   }

#else

   memset(ctx->buf, 0, ctx->buf_size);
   if ( read(ctx->fd, ctx->buf, ctx->buf_size - 1) != 0 )
   {
      //memset(ctx->buf, 0, ctx->buf_size);
      //strncpy(ctx->buf, teststring, ctx->buf_size);
      str_len = strnlen(ctx->buf, ctx->buf_size);

      flb_plg_info(ctx->ins, "str_len: %d", str_len);

      //ctx->buf[str_len] = '}';

      //fprintf(stderr, "%s\n", ctx->buf);

      flb_time_get(&out_time);
      parser_ret = flb_parser_do(ctx->parser, ctx->buf, str_len,
                                 &out_buf, &out_size, &out_time);
      if ( parser_ret >= 0 )
      {
         if ( flb_time_to_double(&out_time) == 0.0 )
         {
            flb_time_get(&out_time);
         }

         /* Initialize local msgpack buffer */
         msgpack_sbuffer_init(&mp_sbuf);
         msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

         msgpack_pack_array(&mp_pck, 2);
         flb_time_append_to_msgpack(&out_time, &mp_pck, 0);
         msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);

         flb_input_chunk_append_raw(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
         msgpack_sbuffer_destroy(&mp_sbuf);
         flb_free(out_buf);
      }
      else {
          flb_plg_trace(ctx->ins, "tried to parse '%s'", ctx->buf);
          flb_plg_trace(ctx->ins, "buf_size %zu", ctx->buf_size);
          flb_plg_error(ctx->ins, "parser returned an error: %d", parser_ret);
      }
   }
#endif

   flb_plg_trace(ctx->ins, "Exiting...");

   return 0;
}

/* Initialize plugin */
static int in_de_init( struct flb_input_instance *ins,
                       struct flb_config *config, void *data )
{
   int ret;
   struct flb_in_de_config *ctx;
   (void)data;
   const char *pval = NULL;

   /* Allocate space for the configuration */
   ctx = de_config_init(ins);
   if ( !ctx )
   {
      return -1;
   }
   ctx->ins = ins;

   /* Set the context */
   flb_input_set_context(ins, ctx);

   /* Unix Socket mode */
   ret = de_unix_create(ctx);
   if ( ret != 0 )
   {
      flb_plg_error(ctx->ins, "could not listen on unix://%s", ctx->unix_path);
      de_config_destroy(ctx);
      return -1;
   }
   flb_net_socket_nonblocking(ctx->fd);

   ctx->parser = malloc(sizeof(struct flb_parser));
   memset(ctx->parser, 0, sizeof(struct flb_parser));
   ctx->parser->type = FLB_PARSER_JSON;

   /* Collect upon data available on the standard input */
   ret = flb_input_set_collector_socket(ins,
                                        in_de_collect,
                                        ctx->fd,
                                        config);
   if ( ret == -1 )
   {
      flb_plg_error(ctx->ins, "could not set collector for IN_DOCKER_EVENTS input plugin");
      de_config_destroy(ctx);
      return -1;
   }

   return 0;
}

static int in_de_exit( void *data, struct flb_config *config )
{
   (void)*config;
   struct flb_in_de_config *ctx = data;

   de_config_destroy(ctx);
   return 0;
}

/* Plugin reference */
struct flb_input_plugin in_docker_events_plugin = {
   .name          = "docker_events",
   .description   = "Docker events",
   .cb_init       = in_de_init,
   .cb_pre_run    = NULL,
   .cb_collect    = in_de_collect,
   .cb_flush_buf  = NULL,
   .cb_exit       = in_de_exit,
   .flags         = FLB_INPUT_NET
};
