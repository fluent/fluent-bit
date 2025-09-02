/*
 * Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <wamr/wasi_ephemeral_nn.h>

/*
 * what this application does is basically same as:
 * https://github.com/bytecodealliance/wasmtime/tree/efa236e58d09570baaf27865da33fb852fcf40a5/crates/wasi-nn/examples/classification-example
 *
 * map_file/unmap_file are copy-and-pasted from:
 * https://github.com/yamt/toywasm/blob/0eaad8cacd0cc7692946ff19b25994f106113be8/lib/fileio.c
 */

int
map_file(const char *path, void **pp, size_t *sizep)
{
    void *p;
    size_t size;
    ssize_t ssz;
    int fd;
    int ret;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        ret = errno;
        assert(ret != 0);
        return ret;
    }
    struct stat st;
    ret = fstat(fd, &st);
    if (ret == -1) {
        ret = errno;
        assert(ret != 0);
        close(fd);
        return ret;
    }
    size = st.st_size;
    if (size > 0) {
        p = malloc(size);
    }
    else {
        /* Avoid a confusing error */
        p = malloc(1);
    }
    if (p == NULL) {
        close(fd);
        return ENOMEM;
    }
    ssz = read(fd, p, size);
    if (ssz != size) {
        ret = errno;
        assert(ret != 0);
        close(fd);
        return ret;
    }
    close(fd);
    *pp = p;
    *sizep = size;
    return 0;
}

void
unmap_file(void *p, size_t sz)
{
    free(p);
}

static void
print_result(const float *result, size_t sz)
{
    /*
     * just dump the raw result.
     * you can postprocess the output with eg. "sort -k2nr | head"
     */
    int i;
    for (i = 0; i < sz / sizeof(float); i++) {
        printf("%d %f\n", i, result[i]);
    }
}

int
main(int argc, char **argv)
{
    wasi_ephemeral_nn_error nnret;
    int ret;
    void *xml;
    size_t xmlsz;
    ret = map_file("fixture/model.xml", &xml, &xmlsz);
    if (ret != 0) {
        fprintf(stderr, "failed to load fixture/model.xml: %s\n",
                strerror(ret));
        exit(1);
    }
    void *weights;
    size_t weightssz;
    ret = map_file("fixture/model.bin", &weights, &weightssz);
    if (ret != 0) {
        fprintf(stderr, "failed to load fixture/model.bin: %s\n",
                strerror(ret));
        exit(1);
    }
    /* note: openvino takes two buffers, namely IR and weights */
    wasi_ephemeral_nn_graph_builder builders[2] = { {
                                                        .buf = xml,
                                                        .size = xmlsz,
                                                    },
                                                    {
                                                        .buf = weights,
                                                        .size = weightssz,
                                                    } };
    wasi_ephemeral_nn_graph g;
    nnret =
        wasi_ephemeral_nn_load(builders, 2, wasi_ephemeral_nn_encoding_openvino,
                               wasi_ephemeral_nn_target_cpu, &g);
    unmap_file(xml, xmlsz);
    unmap_file(weights, weightssz);
    if (nnret != wasi_ephemeral_nn_error_success) {
        fprintf(stderr, "load failed with %d\n", (int)nnret);
        exit(1);
    }
    wasi_ephemeral_nn_graph_execution_context ctx;
    nnret = wasi_ephemeral_nn_init_execution_context(g, &ctx);
    if (nnret != wasi_ephemeral_nn_error_success) {
        fprintf(stderr, "init_execution_context failed with %d\n", (int)nnret);
        exit(1);
    }
    void *tensordata;
    size_t tensordatasz;
    ret = map_file("fixture/tensor.bgr", &tensordata, &tensordatasz);
    if (ret != 0) {
        fprintf(stderr, "failed to load fixture/tensor.bgr: %s\n",
                strerror(ret));
        exit(1);
    }
    wasi_ephemeral_nn_tensor tensor = {
        .dimensions = { .buf = (uint32_t[]){1, 3, 224, 224,}, .size = 4, },
        .type = wasi_ephemeral_nn_type_fp32,
        .data.buf = tensordata,
        .data.size = tensordatasz,
    };
    nnret = wasi_ephemeral_nn_set_input(ctx, 0, &tensor);
    unmap_file(tensordata, tensordatasz);
    if (nnret != wasi_ephemeral_nn_error_success) {
        fprintf(stderr, "set_input failed with %d\n", (int)nnret);
        exit(1);
    }
    nnret = wasi_ephemeral_nn_compute(ctx);
    if (nnret != wasi_ephemeral_nn_error_success) {
        fprintf(stderr, "compute failed with %d\n", (int)nnret);
        exit(1);
    }
    float result[1001];
    uint32_t resultsz;
    nnret = wasi_ephemeral_nn_get_output(ctx, 0, (void *)result, sizeof(result),
                                         &resultsz);
    if (nnret != wasi_ephemeral_nn_error_success) {
        fprintf(stderr, "get_output failed with %d\n", (int)nnret);
        exit(1);
    }
    print_result(result, resultsz);
}
