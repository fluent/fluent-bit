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

#include <stdlib.h>
#include <fluent-bit/flb_utils.h>

#include "docker_events.h"
#include "docker_events_config.h"

struct flb_in_de_config* de_config_init( struct flb_input_instance *i_ins )
{
   const char *buffer_size;
   const char *p;
   struct flb_in_de_config *config;

   config = flb_calloc(1, sizeof(struct flb_in_de_config));
   if ( !config )
   {
      flb_errno();
      return NULL;
   }

   p = flb_input_get_property("unix_path", i_ins);
   if ( p )
   {
      config->unix_path = flb_strdup(p);
   }

   /* Buffer size */
   buffer_size = flb_input_get_property("buffer_size", i_ins);
   if ( !buffer_size )
   {
      config->buf_size = DEFAULT_BUF_SIZE;
   }
   else
   {
      /* Convert KB unit to Bytes */
      config->buf_size = flb_utils_size_to_bytes(buffer_size);
   }

   config->buf = flb_malloc(config->buf_size);

   return config;
}

int de_config_destroy( struct flb_in_de_config *config )
{
   if ( config->unix_path )
   {
      unlink(config->unix_path);
      flb_free(config->unix_path);
   }
   if ( config->buf )
   {
      flb_free(config->buf);
   }

   flb_free(config);

   return 0;
}
