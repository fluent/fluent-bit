/*
 * Copyright (c) 2021, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <rtthread.h>
#include "wasm_export.h"
#include "platform_api_vmcore.h"
#include <dfs.h>
#include <dfs_file.h>
#include <dfs_fs.h>

#ifdef WAMR_ENABLE_RTT_EXPORT

#ifdef WAMR_RTT_EXPORT_VPRINTF
static int
wasm_vprintf(wasm_exec_env_t env, const char *fmt, va_list va)
{
    return vprintf(fmt, va);
}

static int
wasm_vsprintf(wasm_exec_env_t env, char *buf, const char *fmt, va_list va)
{
    return vsprintf(buf, fmt, va);
}

static int
wasm_vsnprintf(wasm_exec_env_t env, char *buf, int n, const char *fmt,
               va_list va)
{
    return vsnprintf(buf, n, fmt, va);
}

#endif /* WAMR_RTT_EXPORT_VPRINTF */

#ifdef WAMR_RTT_EXPORT_DEVICE_OPS
static rt_device_t
wasm_rt_device_find(wasm_exec_env_t env, const char *name)
{
    return rt_device_find(name);
}

static rt_err_t
wasm_rt_device_open(wasm_exec_env_t env, rt_device_t dev, rt_uint16_t o_flag)
{
    return rt_device_open(dev, o_flag);
}

static rt_size_t
wasm_rt_device_write(wasm_exec_env_t env, rt_device_t dev, rt_off_t offset,
                     const void *buf, rt_size_t size)
{
    return rt_device_write(dev, offset, buf, size);
}

static rt_size_t
wasm_rt_device_read(wasm_exec_env_t env, rt_device_t dev, rt_off_t offset,
                    void *buf, rt_size_t size)
{
    return rt_device_read(dev, offset, buf, size);
}

static rt_err_t
wasm_rt_device_close(wasm_exec_env_t env, rt_device_t dev)
{
    return rt_device_close(dev);
}

static rt_err_t
wasm_rt_device_control(wasm_exec_env_t env, rt_device_t dev, int cmd, void *arg)
{
    return rt_device_control(dev, cmd, arg);
}

#endif /* WAMR_RTT_EXPORT_DEVICE_OPS */

/* clang-format off */
static NativeSymbol native_export_symbols[] = {
#ifdef WAMR_RTT_EXPORT_VPRINTF
    {
        "vprintf",
        wasm_vprintf,
        "($*)i"
    },
    {
        "vsprintf",
        wasm_vsprintf,
        "($$*)i"
    },
    {
        "vsnprintf",
        wasm_vsnprintf,
        "($i$*)i"
    },
#endif /* WAMR_RTT_EXPORT_VPRINTF */

#ifdef WAMR_RTT_EXPORT_DEVICE_OPS
    {
        "rt_device_find",
        wasm_rt_device_find,
        "($)i"
    },
    {
        "rt_device_open",
        wasm_rt_device_open,
        "(ii)i"
    },
    {
        "rt_device_write",
        wasm_rt_device_write,
        "(ii*~)i"
    },
    {
        "rt_device_read",
        wasm_rt_device_read,
        "(ii*~)i"
    },
    {
        "rt_device_close",
        wasm_rt_device_close,
        "(i)i"
    },
    {
        "rt_device_control",
        wasm_rt_device_control,
        "(ii*)i"
    },
#ifdef WAMR_RTT_EXPORT_DEVICE_OPS_CPP
    {
        "_Z15rt_device_closeP9rt_device",
        wasm_rt_device_close,
        "(i)i"
    },
    {
        "_Z14rt_device_readP9rt_devicejPvj",
        wasm_rt_device_read,
        "(ii*~)i"
    },
    {
        "_Z15rt_device_writeP9rt_devicejPKvj",
        wasm_rt_device_write,
        "(ii*~)i"
    },
    {
        "_Z14rt_device_openP9rt_devicet",
        wasm_rt_device_open,
        "(ii)i"
    },
    {
        "_Z14rt_device_findPKc",
        wasm_rt_device_find,
        "($)i"
    },
#endif /* WAMR_RTT_EXPORT_DEVICE_OPS_CPP */
#endif /* WAMR_RTT_EXPORT_DEVICE_OPS */
};
/* clang-format on */

#endif /* WAMR_ENABLE_RTT_EXPORT */

/**
 * run WASM module instance.
 * @param module_inst instance of wasm module
 * @param app_argc wasm argument count
 * @param app_argv wasm arguments
 * @return NULL
 */
static void *
app_instance_main(wasm_module_inst_t module_inst, int app_argc, char **app_argv)
{
    const char *exception;

    wasm_application_execute_main(module_inst, app_argc, app_argv);
    if ((exception = wasm_runtime_get_exception(module_inst)))
        rt_kprintf("%s\n", exception);
    return NULL;
}

rt_uint8_t *
my_read_file_to_buffer(char *filename, rt_uint32_t *size)
{
    struct stat f_stat;

    rt_uint8_t *buff = rt_malloc(f_stat.st_size);
    *size = 0;
    if (!buff) {
        rt_set_errno(-ENOMEM);
        return RT_NULL;
    }

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        rt_free(buff);
        rt_set_errno(fd);
        return RT_NULL;
    }

    *size = read(fd, buff, f_stat.st_size);

    close(fd);

    if (*size != f_stat.st_size) {
        rt_free(buff);
        rt_set_errno(-EBADF);
        return RT_NULL;
    }

    return buff;
}

void
iwasm_help(void)
{
#ifdef WAMR_ENABLE_IWASM_PARAMS
    rt_kputs("wrong input: iwasm [-t] [-m] [-s] <*.wasm> <wasm_args ...>\n"
             "             iwasm [-h]\n");
    rt_kputs("\t -h: show this tips.\n");
    rt_kputs("\t -t: show time taking to run this app.\n");
    rt_kputs("\t -m: show memory taking to run this app\n");
    rt_kputs("\t wasm file name and exec params must behind of all vm-param\n");
#else
    rt_kputs("wrong input: iwasm <*.wasm> <wasm_args ...>\n");
#endif /* WAMR_ENABLE_PARAMS */
}

int
iwasm(int argc, char **argv)
{
    rt_uint8_t *wasm_file_buf = NULL;
    rt_uint32_t wasm_file_size;
    rt_uint32_t stack_size = 4 * 1024, heap_size = 4 * 1024;
    wasm_module_t wasm_module = NULL;
    wasm_module_inst_t wasm_module_inst = NULL;
    RuntimeInitArgs init_args;
    static char error_buf[128] = { 0 };
    /* avoid stack overflow */

#ifdef WAMR_ENABLE_IWASM_PARAMS
    int i_arg_begin;
    bool show_mem = false;
    bool show_stack = false;
    bool show_time_exec = false;
    for (i_arg_begin = 1; i_arg_begin < argc; i_arg_begin++) {
        if (argv[i_arg_begin][0] != '-') {
            break;
        }

        if (argv[i_arg_begin][1] == 'm') {
            show_mem = true;
        }
        else if (argv[i_arg_begin][1] == 's') {
            show_stack = true;
        }
        else if (argv[i_arg_begin][1] == 't') {
            show_time_exec = true;
        }
        else if (argv[i_arg_begin][1] == 'h') {
            iwasm_help();
            return 0;
        }
        else if (argv[i_arg_begin][1] == 0x00) {
            continue;
        }
        else {
            rt_kprintf("[iwasm] unknown param: %s\n", argv[i_arg_begin]);
        }
    }
#else /* WAMR_ENABLE_PARAMS */
#define i_arg_begin 1
#endif /* WAMR_ENABLE_PARAMS */

    if (argc - i_arg_begin < 1) {
        iwasm_help();
        return -1;
    }

    rt_memset(&init_args, 0, sizeof(RuntimeInitArgs));
    init_args.mem_alloc_type = Alloc_With_Allocator;
    init_args.mem_alloc_option.allocator.malloc_func = os_malloc;
    init_args.mem_alloc_option.allocator.realloc_func = os_realloc;
    init_args.mem_alloc_option.allocator.free_func = os_free;
#ifdef WAMR_ENABLE_RTT_EXPORT
    init_args.native_symbols = native_export_symbols;
    init_args.n_native_symbols =
        sizeof(native_export_symbols) / sizeof(NativeSymbol);
    init_args.native_module_name = "env";
#endif /* WAMR_ENABLE_RTT_EXPORT */

#ifdef WAMR_ENABLE_IWASM_PARAMS
#if defined(RT_USING_HEAP) && defined(RT_USING_MEMHEAP_AS_HEAP)
    extern long list_memheap(void);
    if (show_mem) {
        list_memheap();
    }
#else
    rt_uint32_t total, max, used;
    if (show_mem) {
        rt_memory_info(&total, &used, &max);
    }
#endif
    rt_thread_t tid;
    if (show_stack) {
        tid = rt_thread_self();
        printf("thread stack addr: %p, size: %u, sp: %p\n", tid->stack_addr,
               tid->stack_size, tid->sp);
    }
#endif /* WAMR_ENABLE_PARAMS */

    if (wasm_runtime_full_init(&init_args) == false) {
        rt_kprintf("Init WASM runtime environment failed.\n");
        return -1;
    }

    wasm_file_buf = my_read_file_to_buffer(argv[i_arg_begin], &wasm_file_size);
    if (!wasm_file_buf) {
        rt_err_t err = rt_get_errno();
        rt_kprintf("WASM load file to RAM failed: %d\n", err);
        goto fail1;
    }
    rt_memset(error_buf, 0x00, sizeof(error_buf));
    wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size, error_buf,
                                    sizeof(error_buf));
    if (!wasm_module) {
        rt_kprintf("%s\n", error_buf);
        goto fail2;
    }
    rt_memset(error_buf, 0x00, sizeof(error_buf));
    wasm_module_inst = wasm_runtime_instantiate(
        wasm_module, stack_size, heap_size, error_buf, sizeof(error_buf));
    if (!wasm_module_inst) {
        rt_kprintf("%s\n", error_buf);
        goto fail3;
    }

#ifdef WAMR_ENABLE_IWASM_PARAMS
    rt_tick_t ticks_exec;
    if (show_time_exec) {
        ticks_exec = rt_tick_get();
    }
#endif /* WAMR_ENABLE_PARAMS */

    app_instance_main(wasm_module_inst, argc - i_arg_begin, &argv[i_arg_begin]);

#ifdef WAMR_ENABLE_IWASM_PARAMS
    if (show_time_exec) {
        ticks_exec = rt_tick_get() - ticks_exec;
        printf("[iwasm] execute ticks took: %u [ticks/s = %u]\n", ticks_exec,
               RT_TICK_PER_SECOND);
    }
#if defined(RT_USING_HEAP) && defined(RT_USING_MEMHEAP_AS_HEAP)
    if (show_mem) {
        list_memheap();
    }
#else
    rt_uint32_t total_after, max_after, used_after;
    if (show_mem) {
        rt_memory_info(&total_after, &used_after, &max_after);
        rt_kprintf("[iwasm] memory took: %u\n", used_after - used);
    }
#endif
    if (show_stack) {
        printf("[iwasm] thread stack addr: %p, size: %u, sp: %p\n",
               tid->stack_addr, tid->stack_size, tid->sp);
    }

#endif /* WAMR_ENABLE_PARAMS */

    /* destroy the module instance */
    wasm_runtime_deinstantiate(wasm_module_inst);

fail3:
    /* unload the module */
    wasm_runtime_unload(wasm_module);

fail2:
    /* free the file buffer */
    rt_free(wasm_file_buf);

fail1:
    /* destroy runtime environment */
    wasm_runtime_destroy();
    return 0;
}
MSH_CMD_EXPORT(iwasm, Embeded VM of WebAssembly);
