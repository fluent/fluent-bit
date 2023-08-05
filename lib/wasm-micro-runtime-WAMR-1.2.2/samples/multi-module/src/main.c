#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bh_read_file.h"
#include "platform_common.h"
#include "wasm_export.h"

static char *
build_module_path(const char *module_name)
{
    const char *module_search_path = ".";
    const char *format = "%s/%s.wasm";
    int sz = strlen(module_search_path) + strlen("/") + strlen(module_name)
             + strlen(".wasm") + 1;
    char *wasm_file_name = BH_MALLOC(sz);
    if (!wasm_file_name) {
        return NULL;
    }

    snprintf(wasm_file_name, sz, format, module_search_path, module_name);
    return wasm_file_name;
}

static bool
module_reader_cb(const char *module_name, uint8 **p_buffer, uint32 *p_size)
{
    char *wasm_file_path = build_module_path(module_name);
    if (!wasm_file_path) {
        return false;
    }

    printf("- bh_read_file_to_buffer %s\n", wasm_file_path);
    *p_buffer = (uint8_t *)bh_read_file_to_buffer(wasm_file_path, p_size);
    BH_FREE(wasm_file_path);
    return *p_buffer != NULL;
}

static void
module_destroyer_cb(uint8 *buffer, uint32 size)
{
    printf("- release the read file buffer\n");
    if (!buffer) {
        return;
    }

    BH_FREE(buffer);
    buffer = NULL;
}

/* 10M */
static char sandbox_memory_space[10 * 1024 * 1024] = { 0 };
int
main()
{
    bool ret = false;
    /* 16K */
    const uint32 stack_size = 16 * 1024;
    const uint32 heap_size = 16 * 1024;

    RuntimeInitArgs init_args = { 0 };
    char error_buf[128] = { 0 };
    /* parameters and return values */
    char *args[1] = { 0 };

    uint8 *file_buf = NULL;
    uint32 file_buf_size = 0;
    wasm_module_t module = NULL;
    wasm_module_t module1;
    wasm_module_inst_t module_inst = NULL;

    /* all malloc() only from the given buffer */
    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = sandbox_memory_space;
    init_args.mem_alloc_option.pool.heap_size = sizeof(sandbox_memory_space);

    printf("- wasm_runtime_full_init\n");
    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        goto EXIT;
    }

#if WASM_ENABLE_MULTI_MODULE != 0
    printf("- wasm_runtime_set_module_reader\n");
    /* set module reader and destroyer */
    wasm_runtime_set_module_reader(module_reader_cb, module_destroyer_cb);
#endif

    /* load WASM byte buffer from WASM bin file */
    if (!module_reader_cb("mC", &file_buf, &file_buf_size)) {
        goto RELEASE_RUNTIME;
    }

    /* load mC and let WAMR load mA and mB */
    printf("- wasm_runtime_load\n");
    if (!(module = wasm_runtime_load(file_buf, file_buf_size, error_buf,
                                     sizeof(error_buf)))) {
        printf("%s\n", error_buf);
        goto RELEASE_BINARY;
    }

    /* instantiate the module */
    printf("- wasm_runtime_instantiate\n");
    if (!(module_inst = wasm_runtime_instantiate(
              module, stack_size, heap_size, error_buf, sizeof(error_buf)))) {
        printf("%s\n", error_buf);
        goto UNLOAD_MODULE;
    }

    /* call functions of mC */
    printf("\n----------------------------------------\n");
    printf("call \"C1\", it will return 0x1f:i32, ===> ");
    wasm_application_execute_func(module_inst, "C1", 0, args);
    printf("call \"C2\", it will call B1() of mB and return 0x15:i32, ===> ");
    wasm_application_execute_func(module_inst, "C2", 0, args);
    printf("call \"C3\", it will call A1() of mA and return 0xb:i32, ===> ");
    wasm_application_execute_func(module_inst, "C3", 0, args);
    printf("call \"C4\", it will call B2() of mB and call A1() of mA and "
           "return 0xb:i32, ===> ");
    wasm_application_execute_func(module_inst, "C4", 0, args);
    printf(
        "call \"C5\", it will be failed since it is a export function, ===> ");
    wasm_application_execute_func(module_inst, "C5", 0, args);

    /* examine module registration a bit */
    module1 = wasm_runtime_find_module_registered("mC");
    if (module1 != NULL) {
        printf("unexpected module mC %p != NULL\n", module1);
        goto UNLOAD_MODULE;
    }
    module1 = wasm_runtime_find_module_registered("mA");
    if (module1 == NULL) {
        printf("unexpected module mA\n");
        goto UNLOAD_MODULE;
    }
    module1 = wasm_runtime_find_module_registered("mB");
    if (module1 == NULL) {
        printf("unexpected module mB\n");
        goto UNLOAD_MODULE;
    }
    if (!wasm_runtime_register_module("mC", module, error_buf,
                                      sizeof(error_buf))) {
        printf("%s\n", error_buf);
        goto UNLOAD_MODULE;
    }
    module1 = wasm_runtime_find_module_registered("mC");
    if (module1 != module) {
        printf("unexpected module mC %p != %p\n", module1, module);
        goto UNLOAD_MODULE;
    }

    ret = true;

    printf("- wasm_runtime_deinstantiate\n");
    wasm_runtime_deinstantiate(module_inst);
UNLOAD_MODULE:
    printf("- wasm_runtime_unload\n");
    wasm_runtime_unload(module);
RELEASE_BINARY:
    module_destroyer_cb(file_buf, file_buf_size);
RELEASE_RUNTIME:
    printf("- wasm_runtime_destroy\n");
    wasm_runtime_destroy();
EXIT:
    return ret ? 0 : 1;
}
