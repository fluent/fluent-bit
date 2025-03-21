/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit / xxd-c
 *  ==================
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

/*
 * xxd-c is a really simple tool to convert text files to C static
 * arrays definitions, it emulate the behavior of 'xxd -i' but with
 * some other features required by Fluent Bit to ingest static
 * configuration files and do registration in a proper way.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <monkey/mk_core/mk_getopt.h>

#define XXDC_CHUNK    1024

int xxdc_verbose;

static void xxdc_help(int rc)
{
    fprintf(stderr, "Usage: xxd-c -i FILE_INPUT [-o FILE_OUTPUT] "
            "[-s NAME]\n\n");
    fprintf(stderr, "  -i  input text file\n");
    fprintf(stderr, "  -o  output C header file\n");
    fprintf(stderr, "  -s  C struct array name name\n");
    fprintf(stderr, "  -h  print this help\n\n");
    exit(rc);
}

static char *xxdc_struct_name(char *in, char *name)
{
    int i;
    int len;
    char *p;
    char *sname = NULL;

    if (name) {
        sname = strdup(name);
    }
    else {
        p = strrchr(in, '/');
        if (!p) {
            sname = strdup(in);
        }
        else {
            sname = strdup(p);
        }
    }

    if (!sname) {
        perror("strdup");
        return NULL;
    }

    /* sanitize name */
    len = strlen(sname);
    for (i = 0; i < len; i++) {
        if (sname[i] == '-' || sname[i] == '.') {
            sname[i] = '_';
        }
    }
    return sname;
}

static int xxdc_convert(char *in, char *out, char *name)
{
    int i;
    int len;
    size_t size;
    char tmp[128];
    char *sname;
    char buf[XXDC_CHUNK];
    FILE *f_in;
    FILE *f_out;

    /* If no output file is given just print to stdout */
    if (!out) {
        f_out = stdout;
    }
    else {
        f_out = fopen(out, "w");
        if (!f_out) {
            perror("fopen");
            fprintf(stderr, "error opening output file: %s\n", out);
            return -1;
        }
    }

    f_in = fopen(in, "r");
    if (!f_in) {
        perror("fopen");
        fprintf(stderr, "error opening input file: %s\n", in);
        if (out) {
            fclose(f_out);
        }
        return -1;
    }

    /* Get target struct name */
    sname = xxdc_struct_name(in, name);
    if (!sname) {
        fclose(f_in);
        if (out) {
            fclose(f_out);
        }
        return -1;
    }

    /* Pre-processor header */
    len = snprintf(tmp, sizeof(tmp) - 1,
                   "#ifndef XXD_C_%s\n"
                   "#define XXD_C_%s\n\n", sname, sname);
    fwrite(tmp, len, 1, f_out);

    /* Define byte array */
    len = snprintf(tmp, sizeof(tmp) - 1,
                   "static unsigned char __%s[] = {", sname);
    fwrite(tmp, len, 1, f_out);

    /* Write bytes */
    while ((size = fread(buf, sizeof(char), XXDC_CHUNK, f_in)) > 0) {
        for (i = 0; i < size; i++) {
            if (i % 12 == 0) {
                fwrite("\n    ", 5, 1, f_out);
            }
            len = snprintf(tmp, sizeof(tmp) - 1,
                           "0x%02x%s ", buf[i], ",");
            fwrite(tmp, len, 1, f_out);
        }
    }
    fwrite("\n};\n\n#endif\n", 12, 1, f_out);
    free(sname);
    fclose(f_in);

    if (out) {
        fclose(f_out);
    }

    if (xxdc_verbose) {
        fprintf(stderr, "[xxdc] converted '%s' to '%s'\n",
                in, out ? out: "STDOUT");
    }
    return 0;
}

int main(int argc, char **argv)
{
    int opt;
    int ret;
    char *in = NULL;
    char *out = NULL;
    char *stname = NULL;

    /* Setup long-options */
    static const struct option long_opts[] = {
        { "input",    required_argument, NULL, 'i' },
        { "output",   optional_argument, NULL, 'o' },
        { "stname",   optional_argument, NULL, 's' },
        { "verbose",  no_argument      , NULL, 'v' },
        { "help",     required_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    xxdc_verbose = 0;

    while ((opt = getopt_long(argc, argv, "i:o:s:vh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            in = strdup(optarg);
            break;
        case 'o':
            out = strdup(optarg);
            break;
        case 's':
            stname = strdup(optarg);
            break;
        case 'v':
            xxdc_verbose = 1;
            break;
        case 'h':
            xxdc_help(EXIT_SUCCESS);
        default:
            xxdc_help(EXIT_FAILURE);
        }
    }

    if (!in) {
        fprintf(stderr, "Error: input file not set\n\n");
        xxdc_help(EXIT_FAILURE);
    }

    ret = xxdc_convert(in, out, stname);

    free(in);
    free(out);
    free(stname);

    return ret;
}
