/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>

/* Creates a parser for Docker */
static struct flb_parser *docker_parser_create(struct flb_config *config)
{
    struct flb_parser *p;

    p = flb_parser_create("_ml_json_docker",      /* parser name */
                          "json",                 /* backend type */
                          NULL,                   /* regex */
                          FLB_TRUE,               /* skip_empty */
                          "%Y-%m-%dT%H:%M:%S.%L", /* time format */
                          "time",                 /* time key */
                          NULL,                   /* time offset */
                          FLB_TRUE,               /* time keep */
                          FLB_FALSE,              /* time strict */
                          FLB_FALSE,              /* time system timezone */
                          FLB_FALSE,              /* no bare keys */
                          NULL,                   /* parser types */
                          0,                      /* types len */
                          NULL,                   /* decoders */
                          config);                /* Fluent Bit context */
    return p;
}

/* Our first multiline mode: 'docker' */
struct flb_ml_parser *flb_ml_parser_docker(struct flb_config *config)
{
    struct flb_parser *parser;
    struct flb_ml_parser *mlp;

    /* Create a Docker parser */
    parser = docker_parser_create(config);
    if (!parser) {
        return NULL;
    }

    /*
     * Let's explain this multiline mode, then you (the reader) might want
     * to submit a PR with new built-in modes :)
     *
     * Containerized apps under Docker writes logs to stdout/stderr. These streams
     * (stdout/stderr) are handled by Docker, in most of cases the content is
     * stored in a .json file in your file system. A message like "hey!" gets into
     * a JSON map like this:
     *
     * {"log": "hey!\n", "stream": "stdout", "time": "2021-02-01T01:40:03.53412Z"}
     *
     * By Docker log spec, any 'log' key that "ends with a \n" it's a complete
     * log record, but Docker also limits the log record size to 16KB, so a long
     * message that does not fit into 16KB can be split in multiple JSON lines,
     * the following example use short words to describe the context:
     *
     * - original message: 'one, two, three\n'
     *
     * Docker log interpretation:
     *
     * - {"log": "one, ", "stream": "stdout", "time": "2021-02-01T01:40:03.53413Z"}
     * - {"log": "two, ", "stream": "stdout", "time": "2021-02-01T01:40:03.53414Z"}
     * - {"log": "three\n", "stream": "stdout", "time": "2021-02-01T01:40:03.53415Z"}
     *
     * So every 'log' key that does not ends with '\n', it's a partial log record
     * and for logging purposes it needs to be concatenated with further messages
     * until a final '\n' is found.
     *
     * We setup the Multiline mode as follows:
     *
     * - Use the type 'FLB_ML_ENDSWITH' to specify that we expect the 'log'
     *   key must ends with a '\n' for complete messages, otherwise it means is
     *   a continuation message. In case a message is not complete just wait until
     *   500 milliseconds (0.5 second) and flush the buffer.
     */
    mlp = flb_ml_parser_create(config,                  /* Fluent Bit context */
                               "docker",                /* name           */
                               FLB_ML_ENDSWITH,         /* type           */
                               "\n",                    /* match_str      */
                               FLB_FALSE,               /* negate         */
                               FLB_ML_FLUSH_TIMEOUT,    /* flush_ms  */
                               "log",                   /* key_content    */
                               "stream",                /* key_group      */
                               NULL,                    /* key_pattern    */
                               parser,                  /* parser ctx     */
                               NULL);                   /* parser name    */
    if (!mlp) {
        flb_error("[multiline] could not create 'docker mode'");
        return NULL;
    }

    return mlp;
}
