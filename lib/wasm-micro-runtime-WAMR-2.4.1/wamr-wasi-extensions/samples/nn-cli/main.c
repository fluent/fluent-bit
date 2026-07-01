/*
 * Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <wamr/wasi_ephemeral_nn.h>

#include "fileio.h"
#include "map.h"

static struct map graphs;
static struct map contexts;

static void
load_graph(char *options)
{
    int target = wasi_ephemeral_nn_target_cpu;
    int encoding = wasi_ephemeral_nn_encoding_openvino;
    const char *id = "default";
    wasi_ephemeral_nn_graph_builder *builders = NULL;
    size_t nbuilders = 0;
    const char *name = NULL;
    enum {
        opt_id,
        opt_file,
        opt_name,
        opt_encoding,
        opt_target,
    };
    static char *const keylistp[] = {
        [opt_id] = "id",         [opt_file] = "file",
        [opt_name] = "name",     [opt_encoding] = "encoding",
        [opt_target] = "target", NULL,
    };
    while (*options) {
        extern char *suboptarg;
        char *value;
        const char *saved = options;
        switch (getsubopt(&options, keylistp, &value)) {
            case opt_id:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                id = value;
                break;
            case opt_file:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                builders =
                    realloc(builders, (nbuilders + 1) * sizeof(*builders));
                if (builders == NULL) {
                    exit(1);
                }
                wasi_ephemeral_nn_graph_builder *b = &builders[nbuilders++];
                int ret = map_file(value, (void *)&b->buf, (void *)&b->size);
                if (ret != 0) {
                    fprintf(stderr, "map_file \"%s\" failed: %s\n", value,
                            strerror(ret));
                    exit(1);
                }
                break;
            case opt_name:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                name = value;
                break;
            case opt_encoding:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                encoding = atoi(value);
                break;
            case opt_target:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                target = atoi(value);
                break;
            case -1:
                fprintf(stderr, "unknown subopt %s\n", saved);
                exit(2);
        }
    }

    if (name != NULL && nbuilders != 0) {
        fprintf(stderr, "name and file are exclusive\n");
        exit(1);
    }

    wasi_ephemeral_nn_error nnret;
    wasi_ephemeral_nn_graph g;
    if (name != NULL) {
        /* we ignore encoding and target */
        nnret = wasi_ephemeral_nn_load_by_name(name, strlen(name), &g);
    }
    else {
        nnret =
            wasi_ephemeral_nn_load(builders, nbuilders, encoding, target, &g);
        size_t i;
        for (i = 0; i < nbuilders; i++) {
            wasi_ephemeral_nn_graph_builder *b = &builders[i];
            unmap_file(b->buf, b->size);
        }
    }
    if (nnret != wasi_ephemeral_nn_error_success) {
        fprintf(stderr, "load failed with %d\n", (int)nnret);
        exit(1);
    }
    map_set(&graphs, id, g);
}

static void
init_execution_context(char *options)
{
    const char *id = "default";
    const char *graph_id = "default";
    enum {
        opt_id,
        opt_graph_id,
    };
    static char *const keylistp[] = {
        [opt_id] = "id",
        [opt_graph_id] = "graph-id",
        NULL,
    };
    while (*options) {
        extern char *suboptarg;
        char *value;
        const char *saved = options;
        switch (getsubopt(&options, keylistp, &value)) {
            case opt_id:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                id = value;
                break;
            case opt_graph_id:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                graph_id = value;
                break;
            case -1:
                fprintf(stderr, "unknown subopt %s\n", saved);
                exit(2);
        }
    }

    wasi_ephemeral_nn_graph g = map_get(&graphs, graph_id);
    wasi_ephemeral_nn_graph_execution_context c;
    wasi_ephemeral_nn_error nnret;
    nnret = wasi_ephemeral_nn_init_execution_context(g, &c);
    if (nnret != wasi_ephemeral_nn_error_success) {
        fprintf(stderr, "init_execution_context failed with %d\n", (int)nnret);
        exit(1);
    }
    map_set(&contexts, id, c);
}

static void
set_input(char *options)
{
    int ret;
    const char *context_id = "default";
    uint32_t idx = 0;
    wasi_ephemeral_nn_tensor tensor = {
        .dimensions = { .buf = NULL, .size = 0, },
        .type = wasi_ephemeral_nn_type_fp32,
        .data = NULL,
    };
    void *buf = NULL;
    size_t sz = 0;
    enum {
        opt_context_id,
        opt_dim,
        opt_type,
        opt_idx,
        opt_file,
    };
    static char *const keylistp[] = {
        [opt_context_id] = "context-id",
        [opt_dim] = "dim",
        [opt_type] = "type",
        [opt_idx] = "idx",
        [opt_file] = "file",
        NULL,
    };
    while (*options) {
        extern char *suboptarg;
        char *value;
        const char *saved = options;
        switch (getsubopt(&options, keylistp, &value)) {
            case opt_context_id:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                context_id = value;
                break;
            case opt_dim:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                wasi_ephemeral_nn_tensor_dimensions *dims = &tensor.dimensions;

                dims->buf =
                    realloc(dims->buf, (dims->size + 1) * sizeof(*dims->buf));
                if (dims->buf == NULL) {
                    exit(1);
                }
                dims->buf[dims->size++] = atoi(value);
                break;
            case opt_type:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                tensor.type = atoi(value);
                break;
            case opt_file:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                if (buf != NULL) {
                    fprintf(stderr, "duplicated tensor data\n");
                    exit(2);
                }
                ret = map_file(value, &buf, &sz);
                if (ret != 0) {
                    fprintf(stderr, "map_file \"%s\" failed: %s\n", value,
                            strerror(ret));
                    exit(1);
                }
                break;
            case opt_idx:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                idx = atoi(value);
                break;
            case -1:
                fprintf(stderr, "unknown subopt %s\n", saved);
                exit(2);
        }
    }

    if (tensor.dimensions.size == 0) {
        fprintf(stderr, "no dimension is given\n");
        exit(2);
    }
    if (buf == NULL) {
        fprintf(stderr, "no tensor is given\n");
        exit(2);
    }

    /*
     * REVISIT: we can check the tensor size against type/dimensions
     * and warn the user if unexpected.
     */

    wasi_ephemeral_nn_error nnret;
    wasi_ephemeral_nn_graph_execution_context c =
        map_get(&contexts, context_id);
    tensor.data.buf = buf;
    tensor.data.size = sz;
    nnret = wasi_ephemeral_nn_set_input(c, idx, &tensor);
    unmap_file(buf, sz);
    if (nnret != wasi_ephemeral_nn_error_success) {
        fprintf(stderr, "set_input failed with %d\n", (int)nnret);
        exit(1);
    }
}

static void
compute(char *options)
{
    const char *context_id = "default";
    enum {
        opt_context_id,
    };
    static char *const keylistp[] = {
        [opt_context_id] = "context-id",
        NULL,
    };
    while (*options) {
        extern char *suboptarg;
        char *value;
        const char *saved = options;
        switch (getsubopt(&options, keylistp, &value)) {
            case opt_context_id:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                context_id = value;
                break;
            case -1:
                fprintf(stderr, "unknown subopt %s\n", saved);
                exit(2);
        }
    }

    wasi_ephemeral_nn_graph_execution_context c =
        map_get(&contexts, context_id);
    wasi_ephemeral_nn_error nnret;
    nnret = wasi_ephemeral_nn_compute(c);
    if (nnret != wasi_ephemeral_nn_error_success) {
        fprintf(stderr, "compute failed with %d\n", (int)nnret);
        exit(1);
    }
}

static void
get_output(char *options)
{
    int ret;
    const char *outfile = NULL;
    const char *context_id = "default";
    uint32_t idx = 0;
    enum {
        opt_context_id,
        opt_idx,
        opt_file,
    };
    static char *const keylistp[] = {
        [opt_context_id] = "context-id",
        [opt_idx] = "idx",
        [opt_file] = "file",
        NULL,
    };
    while (*options) {
        extern char *suboptarg;
        char *value;
        const char *saved = options;
        switch (getsubopt(&options, keylistp, &value)) {
            case opt_context_id:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                context_id = value;
                break;
            case opt_file:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                outfile = value;
                break;
            case opt_idx:
                if (value == NULL) {
                    fprintf(stderr, "no value for %s\n", saved);
                    exit(2);
                }
                idx = atoi(value);
                break;
            case -1:
                fprintf(stderr, "unknown subopt %s\n", saved);
                exit(2);
        }
    }

    int outfd = -1;
    if (outfile != NULL) {
        outfd = open(outfile, O_CREAT | O_TRUNC | O_WRONLY);
        if (outfd == -1) {
            fprintf(stderr, "failed to open output file \"%s\": %s\n", outfile,
                    strerror(errno));
            exit(1);
        }
    }

    wasi_ephemeral_nn_error nnret;
    wasi_ephemeral_nn_graph_execution_context c =
        map_get(&contexts, context_id);
    void *resultbuf = NULL;
    size_t resultbufsz = 256;
    uint32_t resultsz;
retry:
    resultbuf = realloc(resultbuf, resultbufsz);
    if (resultbuf == NULL) {
        exit(1);
    }
    nnret =
        wasi_ephemeral_nn_get_output(c, 0, resultbuf, resultbufsz, &resultsz);
    if (nnret == wasi_ephemeral_nn_error_too_large) {
        resultbufsz *= 2;
        goto retry;
    }
    if (nnret != wasi_ephemeral_nn_error_success) {
        fprintf(stderr, "get_output failed with %d\n", (int)nnret);
        exit(1);
    }
    if (outfd != -1) {
        ssize_t written = write(outfd, resultbuf, resultsz);
        if (written == -1) {
            fprintf(stderr, "failed to write: %s\n", strerror(errno));
            exit(1);
        }
        if (written == -1) {
            fprintf(stderr, "unexpetecd write length %zu (expected %zu)\n",
                    written, (size_t)resultsz);
            exit(1);
        }
        ret = close(outfd);
        if (ret != 0) {
            fprintf(stderr, "failed to close: %s\n", strerror(errno));
            exit(1);
        }
    }
    else {
        fprintf(stderr, "WARNING: discarding %zu bytes output\n",
                (size_t)resultsz);
    }
}

enum longopt {
    opt_load_graph = 0x100,
    opt_init_execution_context,
    opt_set_input,
    opt_compute,
    opt_get_output,
};

static const struct option longopts[] = {
    {
        "load-graph",
        required_argument,
        NULL,
        opt_load_graph,
    },
    {
        "init-execution-context",
        optional_argument,
        NULL,
        opt_init_execution_context,
    },
    {
        "set-input",
        required_argument,
        NULL,
        opt_set_input,
    },
    {
        "compute",
        optional_argument,
        NULL,
        opt_compute,
    },
    {
        "get-output",
        optional_argument,
        NULL,
        opt_get_output,
    },
    {
        NULL,
        0,
        NULL,
        0,
    },
};

int
main(int argc, char **argv)
{
    extern char *optarg;
    int ch;
    int longidx;
    while ((ch = getopt_long(argc, argv, "", longopts, &longidx)) != -1) {
        switch (ch) {
            case opt_load_graph:
                load_graph(optarg);
                break;
            case opt_init_execution_context:
                init_execution_context(optarg ? optarg : "");
                break;
            case opt_set_input:
                set_input(optarg);
                break;
            case opt_compute:
                compute(optarg ? optarg : "");
                break;
            case opt_get_output:
                get_output(optarg ? optarg : "");
                break;
            default:
                exit(2);
        }
    }
    exit(0);
}
