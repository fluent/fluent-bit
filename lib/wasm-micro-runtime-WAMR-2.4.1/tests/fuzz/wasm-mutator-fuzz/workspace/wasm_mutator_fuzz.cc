// Copyright (C) 2019 Intel Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "wasm_runtime_common.h"
#include "wasm_export.h"
#include "bh_read_file.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <iostream>
#include <vector>

using namespace std;

extern "C" WASMModuleCommon *
wasm_runtime_load(uint8 *buf, uint32 size, char *error_buf,
                  uint32 error_buf_size);

extern "C" WASMModuleInstanceCommon *
wasm_runtime_instantiate(WASMModuleCommon *module, uint32 stack_size,
                         uint32 heap_size, char *error_buf,
                         uint32 error_buf_size);

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    /* libfuzzer don't allow us to modify the given Data, so we copy the data
     * here */
    std::vector<uint8_t> myData(Data, Data + Size);
    /* init runtime environment */
    wasm_runtime_init();
    wasm_module_t module =
        wasm_runtime_load((uint8_t *)myData.data(), Size, nullptr, 0);
    if (module) {
        wasm_runtime_unload(module);
    }
    /* destroy runtime environment */
    wasm_runtime_destroy();

    return 0; /* Values other than 0 and -1 are reserved for future use. */
}

/* Forward-declare the libFuzzer's mutator callback. */
extern "C" size_t
LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

/* The custom mutator: */
#ifdef CUSTOM_MUTATOR
extern "C" size_t
LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize,
                        unsigned int Seed)
{
    if ((NULL != Data) && (Size > 10)) {
        int mutate_ret = -1;
        /* delete */
        if (access("./cur.wasm", 0) == 0) {
            remove("./cur.wasm");
        }

        /* 1.write data to cur.wasm */
        FILE *fwrite_fp = fopen("./cur.wasm", "wb");
        if (NULL == fwrite_fp) {
            printf("Faild to open cur.wasm file!\n");
            return 0;
        }
        fwrite(Data, sizeof(uint8_t), Size, fwrite_fp);
        fclose(fwrite_fp);
        fwrite_fp = NULL;

        /* 2.wasm-tools mutate modify cur.wasm */
        char cmd_tmp[150] = { 0 };

        /* clang-format off */
        const char *preserve_semantic = (Seed % 2) ? "--preserve-semantics" : "";
        sprintf(cmd_tmp, "wasm-tools mutate cur.wasm --seed %d -o modified.wasm %s > /dev/null 2>&1", Seed, preserve_semantic);
        /* clang-format on */
        mutate_ret = system(cmd_tmp);
        memset(cmd_tmp, 0, sizeof(cmd_tmp));

        if (mutate_ret != 0) {
            /* If source file not valid, use libfuzzer's own modifier */
            return LLVMFuzzerMutate(Data, Size, MaxSize);
        }

        /* 3.read modified file */
        int read_len = 0;
        int file_len = 0;
        int res = 0;
        uint8_t *buf = NULL;
        FILE *fread_fp = fopen("./modified.wasm", "rb");
        if (NULL == fread_fp) {
            printf("Faild to open modified.wasm file!\n");
            exit(0);
        }

        fseek(fread_fp, 0, SEEK_END); /* location to file end */
        file_len = ftell(fread_fp);   /* get file size */
        buf = (uint8_t *)malloc(file_len);

        if (NULL != buf) {
            fseek(fread_fp, 0, SEEK_SET); /* location to file start */
            read_len = fread(buf, 1, file_len, fread_fp);
            if ((read_len == file_len) && (read_len < MaxSize)) {
                /* 4.fill Data buffer */
                memcpy(Data, buf, read_len);
                res = read_len;
            }
            else {
                res = 0;
            }
        }
        else {
            res = 0;
        }

        memset(buf, 0, file_len);
        free(buf);
        fclose(fread_fp);
        fread_fp = NULL;

        return res;
    }
    else {
        if (access("./modified.wasm", 0) == 0) {
            remove("./modified.wasm");
        }
        memset(Data, 0, Size);
        Size = 0;
        return 0;
    }
}
#endif // CUSTOM_MUTATOR
