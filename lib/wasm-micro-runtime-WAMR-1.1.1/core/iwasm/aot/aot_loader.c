/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_runtime.h"
#include "bh_common.h"
#include "bh_log.h"
#include "aot_reloc.h"
#include "../common/wasm_runtime_common.h"
#include "../common/wasm_native.h"
#include "../compilation/aot.h"
#if WASM_ENABLE_JIT != 0
#include "../compilation/aot_llvm.h"
#include "../interpreter/wasm_loader.h"
#endif

#if WASM_ENABLE_DEBUG_AOT != 0
#include "debug/elf_parser.h"
#include "debug/jit_debug.h"
#endif

#define YMM_PLT_PREFIX "__ymm@"
#define XMM_PLT_PREFIX "__xmm@"
#define REAL_PLT_PREFIX "__real@"

static void
set_error_buf(char *error_buf, uint32 error_buf_size, const char *string)
{
    if (error_buf != NULL) {
        snprintf(error_buf, error_buf_size, "AOT module load failed: %s",
                 string);
    }
}

static void
set_error_buf_v(char *error_buf, uint32 error_buf_size, const char *format, ...)
{
    va_list args;
    char buf[128];

    if (error_buf != NULL) {
        va_start(args, format);
        vsnprintf(buf, sizeof(buf), format, args);
        va_end(args);
        snprintf(error_buf, error_buf_size, "AOT module load failed: %s", buf);
    }
}

#define exchange_uint8(p_data) (void)0

static void
exchange_uint16(uint8 *p_data)
{
    uint8 value = *p_data;
    *p_data = *(p_data + 1);
    *(p_data + 1) = value;
}

static void
exchange_uint32(uint8 *p_data)
{
    uint8 value = *p_data;
    *p_data = *(p_data + 3);
    *(p_data + 3) = value;

    value = *(p_data + 1);
    *(p_data + 1) = *(p_data + 2);
    *(p_data + 2) = value;
}

static void
exchange_uint64(uint8 *pData)
{
    uint32 value;

    value = *(uint32 *)pData;
    *(uint32 *)pData = *(uint32 *)(pData + 4);
    *(uint32 *)(pData + 4) = value;
    exchange_uint32(pData);
    exchange_uint32(pData + 4);
}

static union {
    int a;
    char b;
} __ue = { .a = 1 };

#define is_little_endian() (__ue.b == 1)

static bool
check_buf(const uint8 *buf, const uint8 *buf_end, uint32 length,
          char *error_buf, uint32 error_buf_size)
{
    if ((uintptr_t)buf + length < (uintptr_t)buf
        || (uintptr_t)buf + length > (uintptr_t)buf_end) {
        set_error_buf(error_buf, error_buf_size, "unexpect end");
        return false;
    }
    return true;
}

#define CHECK_BUF(buf, buf_end, length)                                    \
    do {                                                                   \
        if (!check_buf(buf, buf_end, length, error_buf, error_buf_size)) { \
            goto fail;                                                     \
        }                                                                  \
    } while (0)

static uint8 *
align_ptr(const uint8 *p, uint32 b)
{
    uintptr_t v = (uintptr_t)p;
    uintptr_t m = b - 1;
    return (uint8 *)((v + m) & ~m);
}

static inline uint64
GET_U64_FROM_ADDR(uint32 *addr)
{
    union {
        uint64 val;
        uint32 parts[2];
    } u;
    u.parts[0] = addr[0];
    u.parts[1] = addr[1];
    return u.val;
}

#define TEMPLATE_READ(p, p_end, res, type)              \
    do {                                                \
        if (sizeof(type) != sizeof(uint64))             \
            p = (uint8 *)align_ptr(p, sizeof(type));    \
        else                                            \
            /* align 4 bytes if type is uint64 */       \
            p = (uint8 *)align_ptr(p, sizeof(uint32));  \
        CHECK_BUF(p, p_end, sizeof(type));              \
        if (sizeof(type) != sizeof(uint64))             \
            res = *(type *)p;                           \
        else                                            \
            res = (type)GET_U64_FROM_ADDR((uint32 *)p); \
        if (!is_little_endian())                        \
            exchange_##type((uint8 *)&res);             \
        p += sizeof(type);                              \
    } while (0)

#define read_uint8(p, p_end, res) TEMPLATE_READ(p, p_end, res, uint8)
#define read_uint16(p, p_end, res) TEMPLATE_READ(p, p_end, res, uint16)
#define read_uint32(p, p_end, res) TEMPLATE_READ(p, p_end, res, uint32)
#define read_uint64(p, p_end, res) TEMPLATE_READ(p, p_end, res, uint64)

#define read_byte_array(p, p_end, addr, len) \
    do {                                     \
        CHECK_BUF(p, p_end, len);            \
        bh_memcpy_s(addr, len, p, len);      \
        p += len;                            \
    } while (0)

#define read_string(p, p_end, str)                                \
    do {                                                          \
        if (!(str = load_string((uint8 **)&p, p_end, module,      \
                                is_load_from_file_buf, error_buf, \
                                error_buf_size)))                 \
            goto fail;                                            \
    } while (0)

/* Legal values for bin_type */
#define BIN_TYPE_ELF32L 0 /* 32-bit little endian */
#define BIN_TYPE_ELF32B 1 /* 32-bit big endian */
#define BIN_TYPE_ELF64L 2 /* 64-bit little endian */
#define BIN_TYPE_ELF64B 3 /* 64-bit big endian */
#define BIN_TYPE_COFF32 4 /* 32-bit little endian */
#define BIN_TYPE_COFF64 6 /* 64-bit little endian */

/* Legal values for e_type (object file type). */
#define E_TYPE_NONE 0 /* No file type */
#define E_TYPE_REL 1  /* Relocatable file */
#define E_TYPE_EXEC 2 /* Executable file */
#define E_TYPE_DYN 3  /* Shared object file */
#define E_TYPE_XIP 4  /* eXecute In Place file */

/* Legal values for e_machine (architecture).  */
#define E_MACHINE_386 3             /* Intel 80386 */
#define E_MACHINE_MIPS 8            /* MIPS R3000 big-endian */
#define E_MACHINE_MIPS_RS3_LE 10    /* MIPS R3000 little-endian */
#define E_MACHINE_ARM 40            /* ARM/Thumb */
#define E_MACHINE_AARCH64 183       /* AArch64 */
#define E_MACHINE_ARC 45            /* Argonaut RISC Core */
#define E_MACHINE_IA_64 50          /* Intel Merced */
#define E_MACHINE_MIPS_X 51         /* Stanford MIPS-X */
#define E_MACHINE_X86_64 62         /* AMD x86-64 architecture */
#define E_MACHINE_ARC_COMPACT 93    /* ARC International ARCompact */
#define E_MACHINE_ARC_COMPACT2 195  /* Synopsys ARCompact V2 */
#define E_MACHINE_XTENSA 94         /* Tensilica Xtensa Architecture */
#define E_MACHINE_RISCV 243         /* RISC-V 32/64 */
#define E_MACHINE_WIN_I386 0x14c    /* Windows i386 architecture */
#define E_MACHINE_WIN_X86_64 0x8664 /* Windows x86-64 architecture */

/* Legal values for e_version */
#define E_VERSION_CURRENT 1 /* Current version */

static void *
loader_malloc(uint64 size, char *error_buf, uint32 error_buf_size)
{
    void *mem;

    if (size >= UINT32_MAX || !(mem = wasm_runtime_malloc((uint32)size))) {
        set_error_buf(error_buf, error_buf_size, "allocate memory failed");
        return NULL;
    }

    memset(mem, 0, (uint32)size);
    return mem;
}

static char *
const_str_set_insert(const uint8 *str, int32 len, AOTModule *module,
                     char *error_buf, uint32 error_buf_size)
{
    HashMap *set = module->const_str_set;
    char *c_str, *value;

    /* Create const string set if it isn't created */
    if (!set
        && !(set = module->const_str_set = bh_hash_map_create(
                 32, false, (HashFunc)wasm_string_hash,
                 (KeyEqualFunc)wasm_string_equal, NULL, wasm_runtime_free))) {
        set_error_buf(error_buf, error_buf_size,
                      "create const string set failed");
        return NULL;
    }

    /* Lookup const string set, use the string if found */
    if (!(c_str = loader_malloc((uint32)len + 1, error_buf, error_buf_size))) {
        return NULL;
    }

    bh_memcpy_s(c_str, (uint32)(len + 1), str, (uint32)len);
    c_str[len] = '\0';

    if ((value = bh_hash_map_find(set, c_str))) {
        wasm_runtime_free(c_str);
        return value;
    }

    if (!bh_hash_map_insert(set, c_str, c_str)) {
        set_error_buf(error_buf, error_buf_size,
                      "insert string to hash map failed");
        wasm_runtime_free(c_str);
        return NULL;
    }

    return c_str;
}

static char *
load_string(uint8 **p_buf, const uint8 *buf_end, AOTModule *module,
            bool is_load_from_file_buf, char *error_buf, uint32 error_buf_size)
{
    uint8 *p = *p_buf;
    const uint8 *p_end = buf_end;
    char *str;
    uint16 str_len;

    read_uint16(p, p_end, str_len);
    CHECK_BUF(p, p_end, str_len);

    if (str_len == 0) {
        str = "";
    }
    else if (p[str_len - 1] == '\0') {
        /* The string is terminated with '\0', use it directly */
        str = (char *)p;
    }
    else if (is_load_from_file_buf) {
        /* As the file buffer can be referred to after loading,
           we use the 2 bytes of size to adjust the string:
           move string 2 byte backward and then append '\0' */
        str = (char *)(p - 2);
        bh_memmove_s(str, (uint32)(str_len + 1), p, (uint32)str_len);
        str[str_len] = '\0';
    }
    else {
        /* Load from sections, the file buffer cannot be reffered to
           after loading, we must create another string and insert it
           into const string set */
        if (!(str = const_str_set_insert((uint8 *)p, str_len, module, error_buf,
                                         error_buf_size))) {
            goto fail;
        }
    }
    p += str_len;

    *p_buf = p;
    return str;
fail:
    return NULL;
}

static bool
get_aot_file_target(AOTTargetInfo *target_info, char *target_buf,
                    uint32 target_buf_size, char *error_buf,
                    uint32 error_buf_size)
{
    char *machine_type = NULL;
    switch (target_info->e_machine) {
        case E_MACHINE_X86_64:
        case E_MACHINE_WIN_X86_64:
            machine_type = "x86_64";
            break;
        case E_MACHINE_386:
        case E_MACHINE_WIN_I386:
            machine_type = "i386";
            break;
        case E_MACHINE_ARM:
        case E_MACHINE_AARCH64:
            machine_type = target_info->arch;
            break;
        case E_MACHINE_MIPS:
            machine_type = "mips";
            break;
        case E_MACHINE_XTENSA:
            machine_type = "xtensa";
            break;
        case E_MACHINE_RISCV:
            machine_type = "riscv";
            break;
        case E_MACHINE_ARC_COMPACT:
        case E_MACHINE_ARC_COMPACT2:
            machine_type = "arc";
            break;
        default:
            set_error_buf_v(error_buf, error_buf_size,
                            "unknown machine type %d", target_info->e_machine);
            return false;
    }
    if (strncmp(target_info->arch, machine_type, strlen(machine_type))) {
        set_error_buf_v(
            error_buf, error_buf_size,
            "machine type (%s) isn't consistent with target type (%s)",
            machine_type, target_info->arch);
        return false;
    }
    snprintf(target_buf, target_buf_size, "%s", target_info->arch);
    return true;
}

static bool
check_machine_info(AOTTargetInfo *target_info, char *error_buf,
                   uint32 error_buf_size)
{
    char target_expected[32], target_got[32];

    get_current_target(target_expected, sizeof(target_expected));

    if (!get_aot_file_target(target_info, target_got, sizeof(target_got),
                             error_buf, error_buf_size))
        return false;

    if (strncmp(target_expected, target_got, strlen(target_expected))) {
        set_error_buf_v(error_buf, error_buf_size,
                        "invalid target type, expected %s but got %s",
                        target_expected, target_got);
        return false;
    }

    return true;
}

static bool
load_target_info_section(const uint8 *buf, const uint8 *buf_end,
                         AOTModule *module, char *error_buf,
                         uint32 error_buf_size)
{
    AOTTargetInfo target_info;
    const uint8 *p = buf, *p_end = buf_end;
    bool is_target_little_endian, is_target_64_bit;

    read_uint16(p, p_end, target_info.bin_type);
    read_uint16(p, p_end, target_info.abi_type);
    read_uint16(p, p_end, target_info.e_type);
    read_uint16(p, p_end, target_info.e_machine);
    read_uint32(p, p_end, target_info.e_version);
    read_uint32(p, p_end, target_info.e_flags);
    read_uint32(p, p_end, target_info.reserved);
    read_byte_array(p, p_end, target_info.arch, sizeof(target_info.arch));

    if (p != buf_end) {
        set_error_buf(error_buf, error_buf_size, "invalid section size");
        return false;
    }

    /* Check target endian type */
    is_target_little_endian = target_info.bin_type & 1 ? false : true;
    if (is_little_endian() != is_target_little_endian) {
        set_error_buf_v(error_buf, error_buf_size,
                        "invalid target endian type, expected %s but got %s",
                        is_little_endian() ? "little endian" : "big endian",
                        is_target_little_endian ? "little endian"
                                                : "big endian");
        return false;
    }

    /* Check target bit width */
    is_target_64_bit = target_info.bin_type & 2 ? true : false;
    if ((sizeof(void *) == 8 ? true : false) != is_target_64_bit) {
        set_error_buf_v(error_buf, error_buf_size,
                        "invalid target bit width, expected %s but got %s",
                        sizeof(void *) == 8 ? "64-bit" : "32-bit",
                        is_target_64_bit ? "64-bit" : "32-bit");
        return false;
    }

    /* Check target elf file type */
    if (target_info.e_type != E_TYPE_REL && target_info.e_type != E_TYPE_XIP) {
        set_error_buf(error_buf, error_buf_size,
                      "invalid object file type, "
                      "expected relocatable or XIP file type but got others");
        return false;
    }

    /* Check machine info */
    if (!check_machine_info(&target_info, error_buf, error_buf_size)) {
        return false;
    }

    if (target_info.e_version != E_VERSION_CURRENT) {
        set_error_buf(error_buf, error_buf_size, "invalid elf file version");
        return false;
    }

    return true;
fail:
    return false;
}

static void *
get_native_symbol_by_name(const char *name)
{
    void *func = NULL;
    uint32 symnum = 0;
    SymbolMap *sym = NULL;

    sym = get_target_symbol_map(&symnum);

    while (symnum--) {
        if (strcmp(sym->symbol_name, name) == 0) {
            func = sym->symbol_addr;
            break;
        }
        sym++;
    }

    return func;
}

static bool
str2uint32(const char *buf, uint32 *p_res);

static bool
str2uint64(const char *buf, uint64 *p_res);

static bool
load_native_symbol_section(const uint8 *buf, const uint8 *buf_end,
                           AOTModule *module, bool is_load_from_file_buf,
                           char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    uint32 cnt;
    int32 i;
    const char *symbol;

    read_uint32(p, p_end, cnt);

    if (cnt > 0) {
        module->native_symbol_list = wasm_runtime_malloc(cnt * sizeof(void *));
        if (module->native_symbol_list == NULL) {
            set_error_buf(error_buf, error_buf_size,
                          "malloc native symbol list failed");
            goto fail;
        }

        for (i = cnt - 1; i >= 0; i--) {
            read_string(p, p_end, symbol);
            if (!strncmp(symbol, "f32#", 4) || !strncmp(symbol, "i32#", 4)) {
                uint32 u32;
                /* Resolve the raw int bits of f32 const */
                if (!str2uint32(symbol + 4, &u32)) {
                    set_error_buf_v(error_buf, error_buf_size,
                                    "resolve symbol %s failed", symbol);
                    goto fail;
                }
                *(uint32 *)(&module->native_symbol_list[i]) = u32;
            }
            else if (!strncmp(symbol, "f64#", 4)
                     || !strncmp(symbol, "i64#", 4)) {
                uint64 u64;
                /* Resolve the raw int bits of f64 const */
                if (!str2uint64(symbol + 4, &u64)) {
                    set_error_buf_v(error_buf, error_buf_size,
                                    "resolve symbol %s failed", symbol);
                    goto fail;
                }
                *(uint64 *)(&module->native_symbol_list[i]) = u64;
            }
            else if (!strncmp(symbol, "__ignore", 8)) {
                /* Padding bytes to make f64 on 8-byte aligned address,
                   or it is the second 32-bit slot in 32-bit system */
                continue;
            }
            else {
                module->native_symbol_list[i] =
                    get_native_symbol_by_name(symbol);
                if (module->native_symbol_list[i] == NULL) {
                    set_error_buf_v(error_buf, error_buf_size,
                                    "missing native symbol: %s", symbol);
                    goto fail;
                }
            }
        }
    }

    return true;
fail:
    return false;
}

static bool
load_name_section(const uint8 *buf, const uint8 *buf_end, AOTModule *module,
                  bool is_load_from_file_buf, char *error_buf,
                  uint32 error_buf_size)
{
#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
    const uint8 *p = buf, *p_end = buf_end;
    uint32 *aux_func_indexes;
    const char **aux_func_names;
    uint32 name_type, subsection_size;
    uint32 previous_name_type = 0;
    uint32 num_func_name;
    uint32 func_index;
    uint32 previous_func_index = ~0U;
    uint32 name_index;
    int i = 0;
    uint32 name_len;
    uint64 size;

    if (p >= p_end) {
        set_error_buf(error_buf, error_buf_size, "unexpected end");
        return false;
    }

    read_uint32(p, p_end, name_len);

    if (name_len != 4 || p + name_len > p_end) {
        set_error_buf(error_buf, error_buf_size, "unexpected end");
        return false;
    }

    if (memcmp(p, "name", 4) != 0) {
        set_error_buf(error_buf, error_buf_size, "invalid custom name section");
        return false;
    }
    p += name_len;

    while (p < p_end) {
        read_uint32(p, p_end, name_type);
        if (i != 0) {
            if (name_type == previous_name_type) {
                set_error_buf(error_buf, error_buf_size,
                              "duplicate sub-section");
                return false;
            }
            if (name_type < previous_name_type) {
                set_error_buf(error_buf, error_buf_size,
                              "out-of-order sub-section");
                return false;
            }
        }
        previous_name_type = name_type;
        read_uint32(p, p_end, subsection_size);
        CHECK_BUF(p, p_end, subsection_size);
        switch (name_type) {
            case SUB_SECTION_TYPE_FUNC:
                if (subsection_size) {
                    read_uint32(p, p_end, num_func_name);
                    if (num_func_name
                        > module->import_func_count + module->func_count) {
                        set_error_buf(error_buf, error_buf_size,
                                      "function name count out of bounds");
                        return false;
                    }
                    module->aux_func_name_count = num_func_name;

                    /* Allocate memory */
                    size = sizeof(uint32) * (uint64)module->aux_func_name_count;
                    if (!(aux_func_indexes = module->aux_func_indexes =
                              loader_malloc(size, error_buf, error_buf_size))) {
                        return false;
                    }
                    size =
                        sizeof(char **) * (uint64)module->aux_func_name_count;
                    if (!(aux_func_names = module->aux_func_names =
                              loader_malloc(size, error_buf, error_buf_size))) {
                        return false;
                    }

                    for (name_index = 0; name_index < num_func_name;
                         name_index++) {
                        read_uint32(p, p_end, func_index);
                        if (name_index != 0
                            && func_index == previous_func_index) {
                            set_error_buf(error_buf, error_buf_size,
                                          "duplicate function name");
                            return false;
                        }
                        if (name_index != 0
                            && func_index < previous_func_index) {
                            set_error_buf(error_buf, error_buf_size,
                                          "out-of-order function index ");
                            return false;
                        }
                        if (func_index
                            >= module->import_func_count + module->func_count) {
                            set_error_buf(error_buf, error_buf_size,
                                          "function index out of bounds");
                            return false;
                        }
                        previous_func_index = func_index;
                        *(aux_func_indexes + name_index) = func_index;
                        read_string(p, p_end, *(aux_func_names + name_index));
#if 0
                        LOG_DEBUG("func_index %u -> aux_func_name = %s\n",
                               func_index, *(aux_func_names + name_index));
#endif
                    }
                }
                break;
            case SUB_SECTION_TYPE_MODULE: /* TODO: Parse for module subsection
                                           */
            case SUB_SECTION_TYPE_LOCAL:  /* TODO: Parse for local subsection */
            default:
                p = p + subsection_size;
                break;
        }
        i++;
    }

    return true;
fail:
    return false;
#else
    return true;
#endif /* WASM_ENABLE_CUSTOM_NAME_SECTION != 0 */
}

static bool
load_custom_section(const uint8 *buf, const uint8 *buf_end, AOTModule *module,
                    bool is_load_from_file_buf, char *error_buf,
                    uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    uint32 sub_section_type;

    read_uint32(p, p_end, sub_section_type);
    buf = p;

    switch (sub_section_type) {
        case AOT_CUSTOM_SECTION_NATIVE_SYMBOL:
            if (!load_native_symbol_section(buf, buf_end, module,
                                            is_load_from_file_buf, error_buf,
                                            error_buf_size))
                goto fail;
            break;
        case AOT_CUSTOM_SECTION_NAME:
            if (!load_name_section(buf, buf_end, module, is_load_from_file_buf,
                                   error_buf, error_buf_size))
                goto fail;
            break;
#if WASM_ENABLE_LOAD_CUSTOM_SECTION != 0
        case AOT_CUSTOM_SECTION_RAW:
        {
            const char *section_name;
            WASMCustomSection *section;

            if (p >= p_end) {
                set_error_buf(error_buf, error_buf_size, "unexpected end");
                goto fail;
            }

            read_string(p, p_end, section_name);

            section = loader_malloc(sizeof(WASMCustomSection), error_buf,
                                    error_buf_size);
            if (!section) {
                goto fail;
            }

            section->name_addr = (char *)section_name;
            section->name_len = (uint32)strlen(section_name);
            section->content_addr = (uint8 *)p;
            section->content_len = (uint32)(p_end - p);

            section->next = module->custom_section_list;
            module->custom_section_list = section;
            LOG_VERBOSE("Load custom section [%s] success.", section_name);
            break;
        }
#endif /* end of WASM_ENABLE_LOAD_CUSTOM_SECTION != 0 */
        default:
            break;
    }

    return true;
fail:
    return false;
}

static void
destroy_import_memories(AOTImportMemory *import_memories, bool is_jit_mode)
{
    if (!is_jit_mode)
        wasm_runtime_free(import_memories);
}

static void
destroy_mem_init_data_list(AOTMemInitData **data_list, uint32 count,
                           bool is_jit_mode)
{
    if (!is_jit_mode) {
        uint32 i;
        for (i = 0; i < count; i++)
            if (data_list[i])
                wasm_runtime_free(data_list[i]);
        wasm_runtime_free(data_list);
    }
}

static bool
load_mem_init_data_list(const uint8 **p_buf, const uint8 *buf_end,
                        AOTModule *module, char *error_buf,
                        uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;
    AOTMemInitData **data_list;
    uint64 size;
    uint32 i;

    /* Allocate memory */
    size = sizeof(AOTMemInitData *) * (uint64)module->mem_init_data_count;
    if (!(module->mem_init_data_list = data_list =
              loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }

    /* Create each memory data segment */
    for (i = 0; i < module->mem_init_data_count; i++) {
        uint32 init_expr_type, byte_count;
        uint64 init_expr_value;
        uint32 is_passive;
        uint32 memory_index;

        read_uint32(buf, buf_end, is_passive);
        read_uint32(buf, buf_end, memory_index);
        read_uint32(buf, buf_end, init_expr_type);
        read_uint64(buf, buf_end, init_expr_value);
        read_uint32(buf, buf_end, byte_count);
        size = offsetof(AOTMemInitData, bytes) + (uint64)byte_count;
        if (!(data_list[i] = loader_malloc(size, error_buf, error_buf_size))) {
            return false;
        }

#if WASM_ENABLE_BULK_MEMORY != 0
        /* is_passive and memory_index is only used in bulk memory mode */
        data_list[i]->is_passive = (bool)is_passive;
        data_list[i]->memory_index = memory_index;
#endif
        data_list[i]->offset.init_expr_type = (uint8)init_expr_type;
        data_list[i]->offset.u.i64 = (int64)init_expr_value;
        data_list[i]->byte_count = byte_count;
        read_byte_array(buf, buf_end, data_list[i]->bytes,
                        data_list[i]->byte_count);
    }

    *p_buf = buf;
    return true;
fail:
    return false;
}

static bool
load_memory_info(const uint8 **p_buf, const uint8 *buf_end, AOTModule *module,
                 char *error_buf, uint32 error_buf_size)
{
    uint32 i;
    uint64 total_size;
    const uint8 *buf = *p_buf;

    read_uint32(buf, buf_end, module->import_memory_count);
    /* We don't support import_memory_count > 0 currently */
    bh_assert(module->import_memory_count == 0);

    read_uint32(buf, buf_end, module->memory_count);
    total_size = sizeof(AOTMemory) * (uint64)module->memory_count;
    if (!(module->memories =
              loader_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    for (i = 0; i < module->memory_count; i++) {
        read_uint32(buf, buf_end, module->memories[i].memory_flags);
        read_uint32(buf, buf_end, module->memories[i].num_bytes_per_page);
        read_uint32(buf, buf_end, module->memories[i].mem_init_page_count);
        read_uint32(buf, buf_end, module->memories[i].mem_max_page_count);
    }

    read_uint32(buf, buf_end, module->mem_init_data_count);

    /* load memory init data list */
    if (module->mem_init_data_count > 0
        && !load_mem_init_data_list(&buf, buf_end, module, error_buf,
                                    error_buf_size))
        return false;

    *p_buf = buf;
    return true;
fail:
    return false;
}

static void
destroy_import_tables(AOTImportTable *import_tables, bool is_jit_mode)
{
    if (!is_jit_mode)
        wasm_runtime_free(import_tables);
}

static void
destroy_tables(AOTTable *tables, bool is_jit_mode)
{
    if (!is_jit_mode)
        wasm_runtime_free(tables);
}

static void
destroy_table_init_data_list(AOTTableInitData **data_list, uint32 count,
                             bool is_jit_mode)
{
    if (!is_jit_mode) {
        uint32 i;
        for (i = 0; i < count; i++)
            if (data_list[i])
                wasm_runtime_free(data_list[i]);
        wasm_runtime_free(data_list);
    }
}

static bool
load_import_table_list(const uint8 **p_buf, const uint8 *buf_end,
                       AOTModule *module, char *error_buf,
                       uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;
    AOTImportTable *import_table;
    uint64 size;
    uint32 i, possible_grow;

    /* Allocate memory */
    size = sizeof(AOTImportTable) * (uint64)module->import_table_count;
    if (!(module->import_tables = import_table =
              loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }

    /* keep sync with aot_emit_table_info() aot_emit_aot_file */
    for (i = 0; i < module->import_table_count; i++, import_table++) {
        read_uint32(buf, buf_end, import_table->elem_type);
        read_uint32(buf, buf_end, import_table->table_init_size);
        read_uint32(buf, buf_end, import_table->table_max_size);
        read_uint32(buf, buf_end, possible_grow);
        import_table->possible_grow = (possible_grow & 0x1);
    }

    *p_buf = buf;
    return true;
fail:
    return false;
}

static bool
load_table_list(const uint8 **p_buf, const uint8 *buf_end, AOTModule *module,
                char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;
    AOTTable *table;
    uint64 size;
    uint32 i, possible_grow;

    /* Allocate memory */
    size = sizeof(AOTTable) * (uint64)module->table_count;
    if (!(module->tables = table =
              loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }

    /* Create each table data segment */
    for (i = 0; i < module->table_count; i++, table++) {
        read_uint32(buf, buf_end, table->elem_type);
        read_uint32(buf, buf_end, table->table_flags);
        read_uint32(buf, buf_end, table->table_init_size);
        read_uint32(buf, buf_end, table->table_max_size);
        read_uint32(buf, buf_end, possible_grow);
        table->possible_grow = (possible_grow & 0x1);
    }

    *p_buf = buf;
    return true;
fail:
    return false;
}

static bool
load_table_init_data_list(const uint8 **p_buf, const uint8 *buf_end,
                          AOTModule *module, char *error_buf,
                          uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;
    AOTTableInitData **data_list;
    uint64 size;
    uint32 i;

    /* Allocate memory */
    size = sizeof(AOTTableInitData *) * (uint64)module->table_init_data_count;
    if (!(module->table_init_data_list = data_list =
              loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }

    /* Create each table data segment */
    for (i = 0; i < module->table_init_data_count; i++) {
        uint32 mode, elem_type;
        uint32 table_index, init_expr_type, func_index_count;
        uint64 init_expr_value, size1;

        read_uint32(buf, buf_end, mode);
        read_uint32(buf, buf_end, elem_type);
        read_uint32(buf, buf_end, table_index);
        read_uint32(buf, buf_end, init_expr_type);
        read_uint64(buf, buf_end, init_expr_value);
        read_uint32(buf, buf_end, func_index_count);

        size1 = sizeof(uint32) * (uint64)func_index_count;
        size = offsetof(AOTTableInitData, func_indexes) + size1;
        if (!(data_list[i] = loader_malloc(size, error_buf, error_buf_size))) {
            return false;
        }

        data_list[i]->mode = mode;
        data_list[i]->elem_type = elem_type;
        data_list[i]->is_dropped = false;
        data_list[i]->table_index = table_index;
        data_list[i]->offset.init_expr_type = (uint8)init_expr_type;
        data_list[i]->offset.u.i64 = (int64)init_expr_value;
        data_list[i]->func_index_count = func_index_count;
        read_byte_array(buf, buf_end, data_list[i]->func_indexes,
                        (uint32)size1);
    }

    *p_buf = buf;
    return true;
fail:
    return false;
}

static bool
load_table_info(const uint8 **p_buf, const uint8 *buf_end, AOTModule *module,
                char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;

    read_uint32(buf, buf_end, module->import_table_count);
    if (module->import_table_count > 0
        && !load_import_table_list(&buf, buf_end, module, error_buf,
                                   error_buf_size))
        return false;

    read_uint32(buf, buf_end, module->table_count);
    if (module->table_count > 0
        && !load_table_list(&buf, buf_end, module, error_buf, error_buf_size))
        return false;

    read_uint32(buf, buf_end, module->table_init_data_count);

    /* load table init data list */
    if (module->table_init_data_count > 0
        && !load_table_init_data_list(&buf, buf_end, module, error_buf,
                                      error_buf_size))
        return false;

    *p_buf = buf;
    return true;
fail:
    return false;
}

static void
destroy_func_types(AOTFuncType **func_types, uint32 count, bool is_jit_mode)
{
    if (!is_jit_mode) {
        uint32 i;
        for (i = 0; i < count; i++)
            if (func_types[i])
                wasm_runtime_free(func_types[i]);
        wasm_runtime_free(func_types);
    }
}

static bool
load_func_types(const uint8 **p_buf, const uint8 *buf_end, AOTModule *module,
                char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;
    AOTFuncType **func_types;
    uint64 size;
    uint32 i;

    /* Allocate memory */
    size = sizeof(AOTFuncType *) * (uint64)module->func_type_count;
    if (!(module->func_types = func_types =
              loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }

    /* Create each function type */
    for (i = 0; i < module->func_type_count; i++) {
        uint32 param_count, result_count;
        uint32 param_cell_num, ret_cell_num;
        uint64 size1;

        read_uint32(buf, buf_end, param_count);
        read_uint32(buf, buf_end, result_count);

        if (param_count > UINT16_MAX || result_count > UINT16_MAX) {
            set_error_buf(error_buf, error_buf_size,
                          "param count or result count too large");
            return false;
        }

        size1 = (uint64)param_count + (uint64)result_count;
        size = offsetof(AOTFuncType, types) + size1;
        if (!(func_types[i] = loader_malloc(size, error_buf, error_buf_size))) {
            return false;
        }

        func_types[i]->param_count = (uint16)param_count;
        func_types[i]->result_count = (uint16)result_count;
        read_byte_array(buf, buf_end, func_types[i]->types, (uint32)size1);

        param_cell_num = wasm_get_cell_num(func_types[i]->types, param_count);
        ret_cell_num =
            wasm_get_cell_num(func_types[i]->types + param_count, result_count);
        if (param_cell_num > UINT16_MAX || ret_cell_num > UINT16_MAX) {
            set_error_buf(error_buf, error_buf_size,
                          "param count or result count too large");
            return false;
        }

        func_types[i]->param_cell_num = (uint16)param_cell_num;
        func_types[i]->ret_cell_num = (uint16)ret_cell_num;
    }

    *p_buf = buf;
    return true;
fail:
    return false;
}

static bool
load_func_type_info(const uint8 **p_buf, const uint8 *buf_end,
                    AOTModule *module, char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;

    read_uint32(buf, buf_end, module->func_type_count);

    /* load function type */
    if (module->func_type_count > 0
        && !load_func_types(&buf, buf_end, module, error_buf, error_buf_size))
        return false;

    *p_buf = buf;
    return true;
fail:
    return false;
}

static void
destroy_import_globals(AOTImportGlobal *import_globals, bool is_jit_mode)
{
    if (!is_jit_mode)
        wasm_runtime_free(import_globals);
}

static bool
load_import_globals(const uint8 **p_buf, const uint8 *buf_end,
                    AOTModule *module, bool is_load_from_file_buf,
                    char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;
    AOTImportGlobal *import_globals;
    uint64 size;
    uint32 i, data_offset = 0;
#if WASM_ENABLE_LIBC_BUILTIN != 0
    WASMGlobalImport tmp_global;
#endif

    /* Allocate memory */
    size = sizeof(AOTImportGlobal) * (uint64)module->import_global_count;
    if (!(module->import_globals = import_globals =
              loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }

    /* Create each import global */
    for (i = 0; i < module->import_global_count; i++) {
        buf = (uint8 *)align_ptr(buf, 2);
        read_uint8(buf, buf_end, import_globals[i].type);
        read_uint8(buf, buf_end, import_globals[i].is_mutable);
        read_string(buf, buf_end, import_globals[i].module_name);
        read_string(buf, buf_end, import_globals[i].global_name);

#if WASM_ENABLE_LIBC_BUILTIN != 0
        if (wasm_native_lookup_libc_builtin_global(
                import_globals[i].module_name, import_globals[i].global_name,
                &tmp_global)) {
            if (tmp_global.type != import_globals[i].type
                || tmp_global.is_mutable != import_globals[i].is_mutable) {
                set_error_buf(error_buf, error_buf_size,
                              "incompatible import type");
                return false;
            }
            import_globals[i].global_data_linked =
                tmp_global.global_data_linked;
        }
#endif

        import_globals[i].size = wasm_value_type_size(import_globals[i].type);
        import_globals[i].data_offset = data_offset;
        data_offset += import_globals[i].size;
        module->global_data_size += import_globals[i].size;
    }

    *p_buf = buf;
    return true;
fail:
    return false;
}

static bool
load_import_global_info(const uint8 **p_buf, const uint8 *buf_end,
                        AOTModule *module, bool is_load_from_file_buf,
                        char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;

    read_uint32(buf, buf_end, module->import_global_count);

    /* load import globals */
    if (module->import_global_count > 0
        && !load_import_globals(&buf, buf_end, module, is_load_from_file_buf,
                                error_buf, error_buf_size))
        return false;

    *p_buf = buf;
    return true;
fail:
    return false;
}

static void
destroy_globals(AOTGlobal *globals, bool is_jit_mode)
{
    if (!is_jit_mode)
        wasm_runtime_free(globals);
}

static bool
load_globals(const uint8 **p_buf, const uint8 *buf_end, AOTModule *module,
             char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;
    AOTGlobal *globals;
    uint64 size;
    uint32 i, data_offset = 0;
    AOTImportGlobal *last_import_global;

    /* Allocate memory */
    size = sizeof(AOTGlobal) * (uint64)module->global_count;
    if (!(module->globals = globals =
              loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }

    if (module->import_global_count > 0) {
        last_import_global =
            &module->import_globals[module->import_global_count - 1];
        data_offset =
            last_import_global->data_offset + last_import_global->size;
    }

    /* Create each global */
    for (i = 0; i < module->global_count; i++) {
        uint16 init_expr_type;

        read_uint8(buf, buf_end, globals[i].type);
        read_uint8(buf, buf_end, globals[i].is_mutable);
        read_uint16(buf, buf_end, init_expr_type);

        if (init_expr_type != INIT_EXPR_TYPE_V128_CONST) {
            read_uint64(buf, buf_end, globals[i].init_expr.u.i64);
        }
        else {
            uint64 *i64x2 = (uint64 *)globals[i].init_expr.u.v128.i64x2;
            CHECK_BUF(buf, buf_end, sizeof(uint64) * 2);
            wasm_runtime_read_v128(buf, &i64x2[0], &i64x2[1]);
            buf += sizeof(uint64) * 2;
        }

        globals[i].init_expr.init_expr_type = (uint8)init_expr_type;

        globals[i].size = wasm_value_type_size(globals[i].type);
        globals[i].data_offset = data_offset;
        data_offset += globals[i].size;
        module->global_data_size += globals[i].size;
    }

    *p_buf = buf;
    return true;
fail:
    return false;
}

static bool
load_global_info(const uint8 **p_buf, const uint8 *buf_end, AOTModule *module,
                 char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;

    read_uint32(buf, buf_end, module->global_count);

    /* load globals */
    if (module->global_count > 0
        && !load_globals(&buf, buf_end, module, error_buf, error_buf_size))
        return false;

    *p_buf = buf;
    return true;
fail:
    return false;
}

static void
destroy_import_funcs(AOTImportFunc *import_funcs, bool is_jit_mode)
{
    if (!is_jit_mode)
        wasm_runtime_free(import_funcs);
}

static bool
load_import_funcs(const uint8 **p_buf, const uint8 *buf_end, AOTModule *module,
                  bool is_load_from_file_buf, char *error_buf,
                  uint32 error_buf_size)
{
    const char *module_name, *field_name;
    const uint8 *buf = *p_buf;
    AOTImportFunc *import_funcs;
    uint64 size;
    uint32 i;

    /* Allocate memory */
    size = sizeof(AOTImportFunc) * (uint64)module->import_func_count;
    if (!(module->import_funcs = import_funcs =
              loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }

    /* Create each import func */
    for (i = 0; i < module->import_func_count; i++) {
        read_uint16(buf, buf_end, import_funcs[i].func_type_index);
        if (import_funcs[i].func_type_index >= module->func_type_count) {
            set_error_buf(error_buf, error_buf_size, "unknown type");
            return false;
        }
        import_funcs[i].func_type =
            module->func_types[import_funcs[i].func_type_index];
        read_string(buf, buf_end, import_funcs[i].module_name);
        read_string(buf, buf_end, import_funcs[i].func_name);

        module_name = import_funcs[i].module_name;
        field_name = import_funcs[i].func_name;
        import_funcs[i].func_ptr_linked = wasm_native_resolve_symbol(
            module_name, field_name, import_funcs[i].func_type,
            &import_funcs[i].signature, &import_funcs[i].attachment,
            &import_funcs[i].call_conv_raw);

#if WASM_ENABLE_LIBC_WASI != 0
        if (!strcmp(import_funcs[i].module_name, "wasi_unstable")
            || !strcmp(import_funcs[i].module_name, "wasi_snapshot_preview1"))
            module->import_wasi_api = true;
#endif
    }

    *p_buf = buf;
    return true;
fail:
    return false;
}

static bool
load_import_func_info(const uint8 **p_buf, const uint8 *buf_end,
                      AOTModule *module, bool is_load_from_file_buf,
                      char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;

    read_uint32(buf, buf_end, module->import_func_count);

    /* load import funcs */
    if (module->import_func_count > 0
        && !load_import_funcs(&buf, buf_end, module, is_load_from_file_buf,
                              error_buf, error_buf_size))
        return false;

    *p_buf = buf;
    return true;
fail:
    return false;
}

static void
destroy_object_data_sections(AOTObjectDataSection *data_sections,
                             uint32 data_section_count)
{
    uint32 i;
    AOTObjectDataSection *data_section = data_sections;
    for (i = 0; i < data_section_count; i++, data_section++)
        if (data_section->data)
            os_munmap(data_section->data, data_section->size);
    wasm_runtime_free(data_sections);
}

static bool
load_object_data_sections(const uint8 **p_buf, const uint8 *buf_end,
                          AOTModule *module, bool is_load_from_file_buf,
                          char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;
    AOTObjectDataSection *data_sections;
    uint64 size;
    uint32 i;

    /* Allocate memory */
    size = sizeof(AOTObjectDataSection) * (uint64)module->data_section_count;
    if (!(module->data_sections = data_sections =
              loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }

    /* Create each data section */
    for (i = 0; i < module->data_section_count; i++) {
        int map_prot = MMAP_PROT_READ | MMAP_PROT_WRITE;
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64) \
    || defined(BUILD_TARGET_RISCV64_LP64D)                       \
    || defined(BUILD_TARGET_RISCV64_LP64)
        /* aot code and data in x86_64 must be in range 0 to 2G due to
           relocation for R_X86_64_32/32S/PC32 */
        int map_flags = MMAP_MAP_32BIT;
#else
        int map_flags = MMAP_MAP_NONE;
#endif

        read_string(buf, buf_end, data_sections[i].name);
        read_uint32(buf, buf_end, data_sections[i].size);

        /* Allocate memory for data */
        if (data_sections[i].size > 0
            && !(data_sections[i].data = os_mmap(NULL, data_sections[i].size,
                                                 map_prot, map_flags))) {
            set_error_buf(error_buf, error_buf_size, "allocate memory failed");
            return false;
        }
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64)
#if !defined(BH_PLATFORM_LINUX_SGX) && !defined(BH_PLATFORM_WINDOWS) \
    && !defined(BH_PLATFORM_DARWIN)
        /* address must be in the first 2 Gigabytes of
           the process address space */
        bh_assert((uintptr_t)data_sections[i].data < INT32_MAX);
#endif
#endif

        read_byte_array(buf, buf_end, data_sections[i].data,
                        data_sections[i].size);
    }

    *p_buf = buf;
    return true;
fail:
    return false;
}

static bool
load_object_data_sections_info(const uint8 **p_buf, const uint8 *buf_end,
                               AOTModule *module, bool is_load_from_file_buf,
                               char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;

    read_uint32(buf, buf_end, module->data_section_count);

    /* load object data sections */
    if (module->data_section_count > 0
        && !load_object_data_sections(&buf, buf_end, module,
                                      is_load_from_file_buf, error_buf,
                                      error_buf_size))
        return false;

    *p_buf = buf;
    return true;
fail:
    return false;
}

static bool
load_init_data_section(const uint8 *buf, const uint8 *buf_end,
                       AOTModule *module, bool is_load_from_file_buf,
                       char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;

    if (!load_memory_info(&p, p_end, module, error_buf, error_buf_size)
        || !load_table_info(&p, p_end, module, error_buf, error_buf_size)
        || !load_func_type_info(&p, p_end, module, error_buf, error_buf_size)
        || !load_import_global_info(&p, p_end, module, is_load_from_file_buf,
                                    error_buf, error_buf_size)
        || !load_global_info(&p, p_end, module, error_buf, error_buf_size)
        || !load_import_func_info(&p, p_end, module, is_load_from_file_buf,
                                  error_buf, error_buf_size))
        return false;

    /* load function count and start function index */
    read_uint32(p, p_end, module->func_count);
    read_uint32(p, p_end, module->start_func_index);

    /* check start function index */
    if (module->start_func_index != (uint32)-1
        && (module->start_func_index
            >= module->import_func_count + module->func_count)) {
        set_error_buf(error_buf, error_buf_size,
                      "invalid start function index");
        return false;
    }

    read_uint32(p, p_end, module->aux_data_end_global_index);
    read_uint32(p, p_end, module->aux_data_end);
    read_uint32(p, p_end, module->aux_heap_base_global_index);
    read_uint32(p, p_end, module->aux_heap_base);
    read_uint32(p, p_end, module->aux_stack_top_global_index);
    read_uint32(p, p_end, module->aux_stack_bottom);
    read_uint32(p, p_end, module->aux_stack_size);

    if (!load_object_data_sections_info(&p, p_end, module,
                                        is_load_from_file_buf, error_buf,
                                        error_buf_size))
        return false;

    if (p != p_end) {
        set_error_buf(error_buf, error_buf_size,
                      "invalid init data section size");
        return false;
    }

    return true;
fail:
    return false;
}

static bool
load_text_section(const uint8 *buf, const uint8 *buf_end, AOTModule *module,
                  char *error_buf, uint32 error_buf_size)
{
    uint8 *plt_base;

    if (module->func_count > 0 && buf_end == buf) {
        set_error_buf(error_buf, error_buf_size, "invalid code size");
        return false;
    }

    /* The layout is: literal size + literal + code (with plt table) */
    read_uint32(buf, buf_end, module->literal_size);

    /* literal data is at beginning of the text section */
    module->literal = (uint8 *)buf;
    module->code = (void *)(buf + module->literal_size);
    module->code_size = (uint32)(buf_end - (uint8 *)module->code);

#if WASM_ENABLE_DEBUG_AOT != 0
    module->elf_size = module->code_size;

    if (is_ELF(module->code)) {
        /* Now code points to an ELF object, we pull it down to .text section */
        uint64 offset;
        uint64 size;
        char *code_buf = module->code;
        module->elf_hdr = code_buf;
        if (!get_text_section(code_buf, &offset, &size)) {
            set_error_buf(error_buf, error_buf_size,
                          "get text section of ELF failed");
            return false;
        }
        module->code = code_buf + offset;
        module->code_size -= (uint32)offset;
    }
#endif

    if ((module->code_size > 0) && !module->is_indirect_mode) {
        plt_base = (uint8 *)buf_end - get_plt_table_size();
        init_plt_table(plt_base);
    }
    return true;
fail:
    return false;
}

static bool
load_function_section(const uint8 *buf, const uint8 *buf_end, AOTModule *module,
                      char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    uint32 i;
    uint64 size, text_offset;
#if defined(OS_ENABLE_HW_BOUND_CHECK) && defined(BH_PLATFORM_WINDOWS)
    RUNTIME_FUNCTION *rtl_func_table;
    AOTUnwindInfo *unwind_info;
    uint32 unwind_info_offset = module->code_size - sizeof(AOTUnwindInfo);
    uint32 unwind_code_offset = unwind_info_offset - PLT_ITEM_SIZE;
#endif

#if defined(OS_ENABLE_HW_BOUND_CHECK) && defined(BH_PLATFORM_WINDOWS)
    unwind_info = (AOTUnwindInfo *)((uint8 *)module->code + module->code_size
                                    - sizeof(AOTUnwindInfo));
    unwind_info->Version = 1;
    unwind_info->Flags = UNW_FLAG_NHANDLER;
    *(uint32 *)&unwind_info->UnwindCode[0] = unwind_code_offset;

    size = sizeof(RUNTIME_FUNCTION) * (uint64)module->func_count;
    if (size > 0
        && !(rtl_func_table = module->rtl_func_table =
                 loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }
#endif

    size = sizeof(void *) * (uint64)module->func_count;
    if (size > 0
        && !(module->func_ptrs =
                 loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }

    for (i = 0; i < module->func_count; i++) {
        if (sizeof(void *) == 8) {
            read_uint64(p, p_end, text_offset);
        }
        else {
            uint32 text_offset32;
            read_uint32(p, p_end, text_offset32);
            text_offset = text_offset32;
        }
        if (text_offset >= module->code_size) {
            set_error_buf(error_buf, error_buf_size,
                          "invalid function code offset");
            return false;
        }
        module->func_ptrs[i] = (uint8 *)module->code + text_offset;
#if defined(BUILD_TARGET_THUMB) || defined(BUILD_TARGET_THUMB_VFP)
        /* bits[0] of thumb function address must be 1 */
        module->func_ptrs[i] = (void *)((uintptr_t)module->func_ptrs[i] | 1);
#endif
#if defined(OS_ENABLE_HW_BOUND_CHECK) && defined(BH_PLATFORM_WINDOWS)
        rtl_func_table[i].BeginAddress = (DWORD)text_offset;
        if (i > 0) {
            rtl_func_table[i - 1].EndAddress = rtl_func_table[i].BeginAddress;
        }
        rtl_func_table[i].UnwindInfoAddress = (DWORD)unwind_info_offset;
#endif
    }

#if defined(OS_ENABLE_HW_BOUND_CHECK) && defined(BH_PLATFORM_WINDOWS)
    if (module->func_count > 0) {
        uint32 plt_table_size =
            module->is_indirect_mode ? 0 : get_plt_table_size();
        rtl_func_table[module->func_count - 1].EndAddress =
            (DWORD)(module->code_size - plt_table_size);

        if (!RtlAddFunctionTable(rtl_func_table, module->func_count,
                                 (DWORD64)(uintptr_t)module->code)) {
            set_error_buf(error_buf, error_buf_size,
                          "add dynamic function table failed");
            return false;
        }
        module->rtl_func_table_registered = true;
    }
#endif

    /* Set start function when function pointers are resolved */
    if (module->start_func_index != (uint32)-1) {
        if (module->start_func_index >= module->import_func_count)
            module->start_function =
                module->func_ptrs[module->start_func_index
                                  - module->import_func_count];
        else
            /* TODO: fix start function can be import function issue */
            module->start_function = NULL;
    }
    else {
        module->start_function = NULL;
    }

    size = sizeof(uint32) * (uint64)module->func_count;
    if (size > 0
        && !(module->func_type_indexes =
                 loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }

    for (i = 0; i < module->func_count; i++) {
        read_uint32(p, p_end, module->func_type_indexes[i]);
        if (module->func_type_indexes[i] >= module->func_type_count) {
            set_error_buf(error_buf, error_buf_size, "unknown type");
            return false;
        }
    }

    if (p != buf_end) {
        set_error_buf(error_buf, error_buf_size,
                      "invalid function section size");
        return false;
    }

    return true;
fail:
    return false;
}

static void
destroy_exports(AOTExport *exports, bool is_jit_mode)
{
    if (!is_jit_mode)
        wasm_runtime_free(exports);
}

static bool
load_exports(const uint8 **p_buf, const uint8 *buf_end, AOTModule *module,
             bool is_load_from_file_buf, char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;
    AOTExport *exports;
    uint64 size;
    uint32 i;

    /* Allocate memory */
    size = sizeof(AOTExport) * (uint64)module->export_count;
    if (!(module->exports = exports =
              loader_malloc(size, error_buf, error_buf_size))) {
        return false;
    }

    /* Create each export */
    for (i = 0; i < module->export_count; i++) {
        read_uint32(buf, buf_end, exports[i].index);
        read_uint8(buf, buf_end, exports[i].kind);
        read_string(buf, buf_end, exports[i].name);
#if 0 /* TODO: check kind and index */
        if (export_funcs[i].index >=
              module->func_count + module->import_func_count) {
            set_error_buf(error_buf, error_buf_size,
                          "function index is out of range");
            return false;
        }
#endif
    }

    *p_buf = buf;
    return true;
fail:
    return false;
}

static bool
load_export_section(const uint8 *buf, const uint8 *buf_end, AOTModule *module,
                    bool is_load_from_file_buf, char *error_buf,
                    uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;

    /* load export functions */
    read_uint32(p, p_end, module->export_count);
    if (module->export_count > 0
        && !load_exports(&p, p_end, module, is_load_from_file_buf, error_buf,
                         error_buf_size))
        return false;

    if (p != p_end) {
        set_error_buf(error_buf, error_buf_size, "invalid export section size");
        return false;
    }

    return true;
fail:
    return false;
}

static void *
get_data_section_addr(AOTModule *module, const char *section_name,
                      uint32 *p_data_size)
{
    uint32 i;
    AOTObjectDataSection *data_section = module->data_sections;

    for (i = 0; i < module->data_section_count; i++, data_section++) {
        if (!strcmp(data_section->name, section_name)) {
            if (p_data_size)
                *p_data_size = data_section->size;
            return data_section->data;
        }
    }

    return NULL;
}

static void *
resolve_target_sym(const char *symbol, int32 *p_index)
{
    uint32 i, num = 0;
    SymbolMap *target_sym_map;

    if (!(target_sym_map = get_target_symbol_map(&num)))
        return NULL;

    for (i = 0; i < num; i++) {
        if (!strcmp(target_sym_map[i].symbol_name, symbol)
#if defined(_WIN32) || defined(_WIN32_)
            /* In Win32, the symbol name of function added by
               LLVMAddFunction() is prefixed by '_', ignore it */
            || (strlen(symbol) > 1 && symbol[0] == '_'
                && !strcmp(target_sym_map[i].symbol_name, symbol + 1))
#endif
        ) {
            *p_index = (int32)i;
            return target_sym_map[i].symbol_addr;
        }
    }
    return NULL;
}

static bool
is_literal_relocation(const char *reloc_sec_name)
{
    return !strcmp(reloc_sec_name, ".rela.literal");
}

static bool
str2uint32(const char *buf, uint32 *p_res)
{
    uint32 res = 0, val;
    const char *buf_end = buf + 8;
    char ch;

    while (buf < buf_end) {
        ch = *buf++;
        if (ch >= '0' && ch <= '9')
            val = ch - '0';
        else if (ch >= 'a' && ch <= 'f')
            val = ch - 'a' + 0xA;
        else if (ch >= 'A' && ch <= 'F')
            val = ch - 'A' + 0xA;
        else
            return false;
        res = (res << 4) | val;
    }
    *p_res = res;
    return true;
}

static bool
str2uint64(const char *buf, uint64 *p_res)
{
    uint64 res = 0, val;
    const char *buf_end = buf + 16;
    char ch;

    while (buf < buf_end) {
        ch = *buf++;
        if (ch >= '0' && ch <= '9')
            val = ch - '0';
        else if (ch >= 'a' && ch <= 'f')
            val = ch - 'a' + 0xA;
        else if (ch >= 'A' && ch <= 'F')
            val = ch - 'A' + 0xA;
        else
            return false;
        res = (res << 4) | val;
    }
    *p_res = res;
    return true;
}

static bool
do_text_relocation(AOTModule *module, AOTRelocationGroup *group,
                   char *error_buf, uint32 error_buf_size)
{
    bool is_literal = is_literal_relocation(group->section_name);
    uint8 *aot_text = is_literal ? module->literal : module->code;
    uint32 aot_text_size =
        is_literal ? module->literal_size : module->code_size;
    uint32 i, func_index, symbol_len;
#if defined(BH_PLATFORM_WINDOWS)
    uint32 ymm_plt_index = 0, xmm_plt_index = 0;
    uint32 real_plt_index = 0, float_plt_index = 0, j;
#endif
    char symbol_buf[128] = { 0 }, *symbol, *p;
    void *symbol_addr;
    AOTRelocation *relocation = group->relocations;

    if (group->relocation_count > 0 && !aot_text) {
        set_error_buf(error_buf, error_buf_size,
                      "invalid text relocation count");
        return false;
    }

    for (i = 0; i < group->relocation_count; i++, relocation++) {
        int32 symbol_index = -1;
        symbol_len = (uint32)strlen(relocation->symbol_name);
        if (symbol_len + 1 <= sizeof(symbol_buf))
            symbol = symbol_buf;
        else {
            if (!(symbol = loader_malloc(symbol_len + 1, error_buf,
                                         error_buf_size))) {
                return false;
            }
        }
        bh_memcpy_s(symbol, symbol_len, relocation->symbol_name, symbol_len);
        symbol[symbol_len] = '\0';

        if (!strncmp(symbol, AOT_FUNC_PREFIX, strlen(AOT_FUNC_PREFIX))) {
            p = symbol + strlen(AOT_FUNC_PREFIX);
            if (*p == '\0'
                || (func_index = (uint32)atoi(p)) > module->func_count) {
                set_error_buf_v(error_buf, error_buf_size,
                                "invalid import symbol %s", symbol);
                goto check_symbol_fail;
            }
            symbol_addr = module->func_ptrs[func_index];
        }
        else if (!strcmp(symbol, ".text")) {
            symbol_addr = module->code;
        }
        else if (!strcmp(symbol, ".data") || !strcmp(symbol, ".sdata")
                 || !strcmp(symbol, ".rdata")
                 || !strcmp(symbol, ".rodata")
                 /* ".rodata.cst4/8/16/.." */
                 || !strncmp(symbol, ".rodata.cst", strlen(".rodata.cst"))
                 /* ".rodata.strn.m" */
                 || !strncmp(symbol, ".rodata.str", strlen(".rodata.str"))) {
            symbol_addr = get_data_section_addr(module, symbol, NULL);
            if (!symbol_addr) {
                set_error_buf_v(error_buf, error_buf_size,
                                "invalid data section (%s)", symbol);
                goto check_symbol_fail;
            }
        }
        else if (!strcmp(symbol, ".literal")) {
            symbol_addr = module->literal;
        }
#if defined(BH_PLATFORM_WINDOWS)
        /* Relocation for symbols which start with "__ymm@", "__xmm@" or
           "__real@" and end with the ymm value, xmm value or real value.
           In Windows PE file, the data is stored in some individual ".rdata"
           sections. We simply create extra plt data, parse the values from
           the symbols and stored them into the extra plt data. */
        else if (!strcmp(group->section_name, ".text")
                 && !strncmp(symbol, YMM_PLT_PREFIX, strlen(YMM_PLT_PREFIX))
                 && strlen(symbol) == strlen(YMM_PLT_PREFIX) + 64) {
            char ymm_buf[17] = { 0 };

            symbol_addr = module->extra_plt_data + ymm_plt_index * 32;
            for (j = 0; j < 4; j++) {
                bh_memcpy_s(ymm_buf, sizeof(ymm_buf),
                            symbol + strlen(YMM_PLT_PREFIX) + 48 - 16 * j, 16);
                if (!str2uint64(ymm_buf,
                                (uint64 *)((uint8 *)symbol_addr + 8 * j))) {
                    set_error_buf_v(error_buf, error_buf_size,
                                    "resolve symbol %s failed", symbol);
                    goto check_symbol_fail;
                }
            }
            ymm_plt_index++;
        }
        else if (!strcmp(group->section_name, ".text")
                 && !strncmp(symbol, XMM_PLT_PREFIX, strlen(XMM_PLT_PREFIX))
                 && strlen(symbol) == strlen(XMM_PLT_PREFIX) + 32) {
            char xmm_buf[17] = { 0 };

            symbol_addr = module->extra_plt_data + module->ymm_plt_count * 32
                          + xmm_plt_index * 16;
            for (j = 0; j < 2; j++) {
                bh_memcpy_s(xmm_buf, sizeof(xmm_buf),
                            symbol + strlen(XMM_PLT_PREFIX) + 16 - 16 * j, 16);
                if (!str2uint64(xmm_buf,
                                (uint64 *)((uint8 *)symbol_addr + 8 * j))) {
                    set_error_buf_v(error_buf, error_buf_size,
                                    "resolve symbol %s failed", symbol);
                    goto check_symbol_fail;
                }
            }
            xmm_plt_index++;
        }
        else if (!strcmp(group->section_name, ".text")
                 && !strncmp(symbol, REAL_PLT_PREFIX, strlen(REAL_PLT_PREFIX))
                 && strlen(symbol) == strlen(REAL_PLT_PREFIX) + 16) {
            char real_buf[17] = { 0 };

            symbol_addr = module->extra_plt_data + module->ymm_plt_count * 32
                          + module->xmm_plt_count * 16 + real_plt_index * 8;
            bh_memcpy_s(real_buf, sizeof(real_buf),
                        symbol + strlen(REAL_PLT_PREFIX), 16);
            if (!str2uint64(real_buf, (uint64 *)symbol_addr)) {
                set_error_buf_v(error_buf, error_buf_size,
                                "resolve symbol %s failed", symbol);
                goto check_symbol_fail;
            }
            real_plt_index++;
        }
        else if (!strcmp(group->section_name, ".text")
                 && !strncmp(symbol, REAL_PLT_PREFIX, strlen(REAL_PLT_PREFIX))
                 && strlen(symbol) == strlen(REAL_PLT_PREFIX) + 8) {
            char float_buf[9] = { 0 };

            symbol_addr = module->extra_plt_data + module->ymm_plt_count * 32
                          + module->xmm_plt_count * 16
                          + module->real_plt_count * 8 + float_plt_index * 4;
            bh_memcpy_s(float_buf, sizeof(float_buf),
                        symbol + strlen(REAL_PLT_PREFIX), 8);
            if (!str2uint32(float_buf, (uint32 *)symbol_addr)) {
                set_error_buf_v(error_buf, error_buf_size,
                                "resolve symbol %s failed", symbol);
                goto check_symbol_fail;
            }
            float_plt_index++;
        }
#endif /* end of defined(BH_PLATFORM_WINDOWS) */
        else if (!(symbol_addr = resolve_target_sym(symbol, &symbol_index))) {
            set_error_buf_v(error_buf, error_buf_size,
                            "resolve symbol %s failed", symbol);
            goto check_symbol_fail;
        }

        if (symbol != symbol_buf)
            wasm_runtime_free(symbol);

        if (!apply_relocation(
                module, aot_text, aot_text_size, relocation->relocation_offset,
                relocation->relocation_addend, relocation->relocation_type,
                symbol_addr, symbol_index, error_buf, error_buf_size))
            return false;
    }

    return true;

check_symbol_fail:
    if (symbol != symbol_buf)
        wasm_runtime_free(symbol);
    return false;
}

static bool
do_data_relocation(AOTModule *module, AOTRelocationGroup *group,
                   char *error_buf, uint32 error_buf_size)

{
    uint8 *data_addr;
    uint32 data_size = 0, i;
    AOTRelocation *relocation = group->relocations;
    void *symbol_addr;
    char *symbol, *data_section_name;

    if (!strncmp(group->section_name, ".rela.", 6)) {
        data_section_name = group->section_name + strlen(".rela");
    }
    else if (!strncmp(group->section_name, ".rel.", 5)) {
        data_section_name = group->section_name + strlen(".rel");
    }
    else if (!strcmp(group->section_name, ".rdata")) {
        data_section_name = group->section_name;
    }
    else {
        set_error_buf(error_buf, error_buf_size,
                      "invalid data relocation section name");
        return false;
    }

    data_addr = get_data_section_addr(module, data_section_name, &data_size);

    if (group->relocation_count > 0 && !data_addr) {
        set_error_buf(error_buf, error_buf_size,
                      "invalid data relocation count");
        return false;
    }

    for (i = 0; i < group->relocation_count; i++, relocation++) {
        symbol = relocation->symbol_name;
        if (!strcmp(symbol, ".text")) {
            symbol_addr = module->code;
        }
        else {
            set_error_buf_v(error_buf, error_buf_size,
                            "invalid relocation symbol %s", symbol);
            return false;
        }

        if (!apply_relocation(
                module, data_addr, data_size, relocation->relocation_offset,
                relocation->relocation_addend, relocation->relocation_type,
                symbol_addr, -1, error_buf, error_buf_size))
            return false;
    }

    return true;
}

static bool
validate_symbol_table(uint8 *buf, uint8 *buf_end, uint32 *offsets, uint32 count,
                      char *error_buf, uint32 error_buf_size)
{
    uint32 i, str_len_addr = 0;
    uint16 str_len;

    for (i = 0; i < count; i++) {
        if (offsets[i] != str_len_addr)
            return false;

        read_uint16(buf, buf_end, str_len);
        str_len_addr += (uint32)sizeof(uint16) + str_len;
        str_len_addr = align_uint(str_len_addr, 2);
        buf += str_len;
        buf = (uint8 *)align_ptr(buf, 2);
    }

    if (buf == buf_end)
        return true;
fail:
    return false;
}

static bool
load_relocation_section(const uint8 *buf, const uint8 *buf_end,
                        AOTModule *module, bool is_load_from_file_buf,
                        char *error_buf, uint32 error_buf_size)
{
    AOTRelocationGroup *groups = NULL, *group;
    uint32 symbol_count = 0;
    uint32 group_count = 0, i, j;
    uint64 size;
    uint32 *symbol_offsets, total_string_len;
    uint8 *symbol_buf, *symbol_buf_end;
    int map_prot, map_flags;
    bool ret = false;
    char **symbols = NULL;

    read_uint32(buf, buf_end, symbol_count);

    symbol_offsets = (uint32 *)buf;
    for (i = 0; i < symbol_count; i++) {
        CHECK_BUF(buf, buf_end, sizeof(uint32));
        buf += sizeof(uint32);
    }

    read_uint32(buf, buf_end, total_string_len);
    symbol_buf = (uint8 *)buf;
    symbol_buf_end = symbol_buf + total_string_len;

    if (!validate_symbol_table(symbol_buf, symbol_buf_end, symbol_offsets,
                               symbol_count, error_buf, error_buf_size)) {
        set_error_buf(error_buf, error_buf_size,
                      "validate symbol table failed");
        goto fail;
    }

    if (symbol_count > 0) {
        symbols = loader_malloc((uint64)sizeof(*symbols) * symbol_count,
                                error_buf, error_buf_size);
        if (symbols == NULL) {
            goto fail;
        }
    }

#if defined(BH_PLATFORM_WINDOWS)
    buf = symbol_buf_end;
    read_uint32(buf, buf_end, group_count);

    for (i = 0; i < group_count; i++) {
        uint32 name_index, relocation_count;
        uint16 group_name_len;
        uint8 *group_name;

        /* section name address is 4 bytes aligned. */
        buf = (uint8 *)align_ptr(buf, sizeof(uint32));
        read_uint32(buf, buf_end, name_index);

        if (name_index >= symbol_count) {
            set_error_buf(error_buf, error_buf_size,
                          "symbol index out of range");
            goto fail;
        }

        group_name = symbol_buf + symbol_offsets[name_index];
        group_name_len = *(uint16 *)group_name;
        group_name += sizeof(uint16);

        read_uint32(buf, buf_end, relocation_count);

        for (j = 0; j < relocation_count; j++) {
            AOTRelocation relocation = { 0 };
            uint32 symbol_index, offset32;
            int32 addend32;
            uint16 symbol_name_len;
            uint8 *symbol_name;

            if (sizeof(void *) == 8) {
                read_uint64(buf, buf_end, relocation.relocation_offset);
                read_uint64(buf, buf_end, relocation.relocation_addend);
            }
            else {
                read_uint32(buf, buf_end, offset32);
                relocation.relocation_offset = (uint64)offset32;
                read_uint32(buf, buf_end, addend32);
                relocation.relocation_addend = (int64)addend32;
            }
            read_uint32(buf, buf_end, relocation.relocation_type);
            read_uint32(buf, buf_end, symbol_index);

            if (symbol_index >= symbol_count) {
                set_error_buf(error_buf, error_buf_size,
                              "symbol index out of range");
                goto fail;
            }

            symbol_name = symbol_buf + symbol_offsets[symbol_index];
            symbol_name_len = *(uint16 *)symbol_name;
            symbol_name += sizeof(uint16);

            char group_name_buf[128] = { 0 };
            char symbol_name_buf[128] = { 0 };
            memcpy(group_name_buf, group_name, group_name_len);
            memcpy(symbol_name_buf, symbol_name, symbol_name_len);

            if ((group_name_len == strlen(".text")
                 || (module->is_indirect_mode
                     && group_name_len == strlen(".text") + 1))
                && !strncmp(group_name, ".text", strlen(".text"))) {
                if ((symbol_name_len == strlen(YMM_PLT_PREFIX) + 64
                     || (module->is_indirect_mode
                         && symbol_name_len == strlen(YMM_PLT_PREFIX) + 64 + 1))
                    && !strncmp(symbol_name, YMM_PLT_PREFIX,
                                strlen(YMM_PLT_PREFIX))) {
                    module->ymm_plt_count++;
                }
                else if ((symbol_name_len == strlen(XMM_PLT_PREFIX) + 32
                          || (module->is_indirect_mode
                              && symbol_name_len
                                     == strlen(XMM_PLT_PREFIX) + 32 + 1))
                         && !strncmp(symbol_name, XMM_PLT_PREFIX,
                                     strlen(XMM_PLT_PREFIX))) {
                    module->xmm_plt_count++;
                }
                else if ((symbol_name_len == strlen(REAL_PLT_PREFIX) + 16
                          || (module->is_indirect_mode
                              && symbol_name_len
                                     == strlen(REAL_PLT_PREFIX) + 16 + 1))
                         && !strncmp(symbol_name, REAL_PLT_PREFIX,
                                     strlen(REAL_PLT_PREFIX))) {
                    module->real_plt_count++;
                }
                else if ((symbol_name_len >= strlen(REAL_PLT_PREFIX) + 8
                          || (module->is_indirect_mode
                              && symbol_name_len
                                     == strlen(REAL_PLT_PREFIX) + 8 + 1))
                         && !strncmp(symbol_name, REAL_PLT_PREFIX,
                                     strlen(REAL_PLT_PREFIX))) {
                    module->float_plt_count++;
                }
            }
        }
    }

    /* Allocate memory for extra plt data */
    size = sizeof(uint64) * 4 * module->ymm_plt_count
           + sizeof(uint64) * 2 * module->xmm_plt_count
           + sizeof(uint64) * module->real_plt_count
           + sizeof(uint32) * module->float_plt_count;
    if (size > 0) {
        map_prot = MMAP_PROT_READ | MMAP_PROT_WRITE | MMAP_PROT_EXEC;
        /* aot code and data in x86_64 must be in range 0 to 2G due to
           relocation for R_X86_64_32/32S/PC32 */
        map_flags = MMAP_MAP_32BIT;

        if (size > UINT32_MAX
            || !(module->extra_plt_data =
                     os_mmap(NULL, (uint32)size, map_prot, map_flags))) {
            set_error_buf(error_buf, error_buf_size, "mmap memory failed");
            goto fail;
        }
        module->extra_plt_data_size = (uint32)size;
    }
#endif /* end of defined(BH_PLATFORM_WINDOWS) */

    buf = symbol_buf_end;
    read_uint32(buf, buf_end, group_count);

    /* Allocate memory for relocation groups */
    size = sizeof(AOTRelocationGroup) * (uint64)group_count;
    if (size > 0
        && !(groups = loader_malloc(size, error_buf, error_buf_size))) {
        goto fail;
    }

    /* Load each relocation group */
    for (i = 0, group = groups; i < group_count; i++, group++) {
        AOTRelocation *relocation;
        uint32 name_index;

        /* section name address is 4 bytes aligned. */
        buf = (uint8 *)align_ptr(buf, sizeof(uint32));
        read_uint32(buf, buf_end, name_index);

        if (name_index >= symbol_count) {
            set_error_buf(error_buf, error_buf_size,
                          "symbol index out of range");
            goto fail;
        }

        if (symbols[name_index] == NULL) {
            uint8 *name_addr = symbol_buf + symbol_offsets[name_index];

            read_string(name_addr, buf_end, symbols[name_index]);
        }
        group->section_name = symbols[name_index];

        read_uint32(buf, buf_end, group->relocation_count);

        /* Allocate memory for relocations */
        size = sizeof(AOTRelocation) * (uint64)group->relocation_count;
        if (!(group->relocations = relocation =
                  loader_malloc(size, error_buf, error_buf_size))) {
            ret = false;
            goto fail;
        }

        /* Load each relocation */
        for (j = 0; j < group->relocation_count; j++, relocation++) {
            uint32 symbol_index;

            if (sizeof(void *) == 8) {
                read_uint64(buf, buf_end, relocation->relocation_offset);
                read_uint64(buf, buf_end, relocation->relocation_addend);
            }
            else {
                uint32 offset32, addend32;
                read_uint32(buf, buf_end, offset32);
                relocation->relocation_offset = (uint64)offset32;
                read_uint32(buf, buf_end, addend32);
                relocation->relocation_addend = (uint64)addend32;
            }
            read_uint32(buf, buf_end, relocation->relocation_type);
            read_uint32(buf, buf_end, symbol_index);

            if (symbol_index >= symbol_count) {
                set_error_buf(error_buf, error_buf_size,
                              "symbol index out of range");
                goto fail;
            }

            if (symbols[symbol_index] == NULL) {
                uint8 *symbol_addr = symbol_buf + symbol_offsets[symbol_index];

                read_string(symbol_addr, buf_end, symbols[symbol_index]);
            }
            relocation->symbol_name = symbols[symbol_index];
        }

        if (!strcmp(group->section_name, ".rel.text")
            || !strcmp(group->section_name, ".rela.text")
            || !strcmp(group->section_name, ".rela.literal")
#ifdef BH_PLATFORM_WINDOWS
            || !strcmp(group->section_name, ".text")
#endif
        ) {
#if !defined(BH_PLATFORM_LINUX) && !defined(BH_PLATFORM_LINUX_SGX) \
    && !defined(BH_PLATFORM_DARWIN) && !defined(BH_PLATFORM_WINDOWS)
            if (module->is_indirect_mode) {
                set_error_buf(error_buf, error_buf_size,
                              "cannot apply relocation to text section "
                              "for aot file generated with "
                              "\"--enable-indirect-mode\" flag");
                goto fail;
            }
#endif
            if (!do_text_relocation(module, group, error_buf, error_buf_size))
                goto fail;
        }
        else {
            if (!do_data_relocation(module, group, error_buf, error_buf_size))
                goto fail;
        }
    }

    /* Set read only for AOT code and some data sections */
    map_prot = MMAP_PROT_READ | MMAP_PROT_EXEC;

    if (module->code) {
        /* The layout is: literal size + literal + code (with plt table) */
        uint8 *mmap_addr = module->literal - sizeof(uint32);
        uint32 total_size =
            sizeof(uint32) + module->literal_size + module->code_size;
        os_mprotect(mmap_addr, total_size, map_prot);
    }

    map_prot = MMAP_PROT_READ;

#if defined(BH_PLATFORM_WINDOWS)
    if (module->extra_plt_data) {
        os_mprotect(module->extra_plt_data, module->extra_plt_data_size,
                    map_prot);
    }
#endif

    for (i = 0; i < module->data_section_count; i++) {
        AOTObjectDataSection *data_section = module->data_sections + i;
        if (!strcmp(data_section->name, ".rdata")
            || !strcmp(data_section->name, ".rodata")
            /* ".rodata.cst4/8/16/.." */
            || !strncmp(data_section->name, ".rodata.cst",
                        strlen(".rodata.cst"))
            /* ".rodata.strn.m" */
            || !strncmp(data_section->name, ".rodata.str",
                        strlen(".rodata.str"))) {
            os_mprotect(data_section->data, data_section->size, map_prot);
        }
    }

    ret = true;

fail:
    if (symbols) {
        wasm_runtime_free(symbols);
    }
    if (groups) {
        for (i = 0, group = groups; i < group_count; i++, group++)
            if (group->relocations)
                wasm_runtime_free(group->relocations);
        wasm_runtime_free(groups);
    }

    (void)map_flags;
    return ret;
}

static bool
load_from_sections(AOTModule *module, AOTSection *sections,
                   bool is_load_from_file_buf, char *error_buf,
                   uint32 error_buf_size)
{
    AOTSection *section = sections;
    const uint8 *buf, *buf_end;
    uint32 last_section_type = (uint32)-1, section_type;
    uint32 i, func_index, func_type_index;
    AOTFuncType *func_type;
    AOTExport *exports;

    while (section) {
        buf = section->section_body;
        buf_end = buf + section->section_body_size;
        /* Check sections */
        section_type = (uint32)section->section_type;
        if ((last_section_type == (uint32)-1
             && section_type != AOT_SECTION_TYPE_TARGET_INFO)
            || (last_section_type != (uint32)-1
                && (section_type != last_section_type + 1
                    && section_type != AOT_SECTION_TYPE_CUSTOM))) {
            set_error_buf(error_buf, error_buf_size, "invalid section order");
            return false;
        }
        last_section_type = section_type;
        switch (section_type) {
            case AOT_SECTION_TYPE_TARGET_INFO:
                if (!load_target_info_section(buf, buf_end, module, error_buf,
                                              error_buf_size))
                    return false;
                break;
            case AOT_SECTION_TYPE_INIT_DATA:
                if (!load_init_data_section(buf, buf_end, module,
                                            is_load_from_file_buf, error_buf,
                                            error_buf_size))
                    return false;
                break;
            case AOT_SECTION_TYPE_TEXT:
                if (!load_text_section(buf, buf_end, module, error_buf,
                                       error_buf_size))
                    return false;
                break;
            case AOT_SECTION_TYPE_FUNCTION:
                if (!load_function_section(buf, buf_end, module, error_buf,
                                           error_buf_size))
                    return false;
                break;
            case AOT_SECTION_TYPE_EXPORT:
                if (!load_export_section(buf, buf_end, module,
                                         is_load_from_file_buf, error_buf,
                                         error_buf_size))
                    return false;
                break;
            case AOT_SECTION_TYPE_RELOCATION:
                if (!load_relocation_section(buf, buf_end, module,
                                             is_load_from_file_buf, error_buf,
                                             error_buf_size))
                    return false;
                break;
            case AOT_SECTION_TYPE_CUSTOM:
                if (!load_custom_section(buf, buf_end, module,
                                         is_load_from_file_buf, error_buf,
                                         error_buf_size))
                    return false;
                break;
            default:
                set_error_buf(error_buf, error_buf_size,
                              "invalid aot section type");
                return false;
        }

        section = section->next;
    }

    if (last_section_type != AOT_SECTION_TYPE_RELOCATION
        && last_section_type != AOT_SECTION_TYPE_CUSTOM) {
        set_error_buf(error_buf, error_buf_size, "section missing");
        return false;
    }

    /* Resolve malloc and free function */
    module->malloc_func_index = (uint32)-1;
    module->free_func_index = (uint32)-1;
    module->retain_func_index = (uint32)-1;

    exports = module->exports;
    for (i = 0; i < module->export_count; i++) {
        if (exports[i].kind == EXPORT_KIND_FUNC
            && exports[i].index >= module->import_func_count) {
            if (!strcmp(exports[i].name, "malloc")) {
                func_index = exports[i].index - module->import_func_count;
                func_type_index = module->func_type_indexes[func_index];
                func_type = module->func_types[func_type_index];
                if (func_type->param_count == 1 && func_type->result_count == 1
                    && func_type->types[0] == VALUE_TYPE_I32
                    && func_type->types[1] == VALUE_TYPE_I32) {
                    bh_assert(module->malloc_func_index == (uint32)-1);
                    module->malloc_func_index = func_index;
                    LOG_VERBOSE("Found malloc function, name: %s, index: %u",
                                exports[i].name, exports[i].index);
                }
            }
            else if (!strcmp(exports[i].name, "__new")) {
                func_index = exports[i].index - module->import_func_count;
                func_type_index = module->func_type_indexes[func_index];
                func_type = module->func_types[func_type_index];
                if (func_type->param_count == 2 && func_type->result_count == 1
                    && func_type->types[0] == VALUE_TYPE_I32
                    && func_type->types[1] == VALUE_TYPE_I32
                    && func_type->types[2] == VALUE_TYPE_I32) {
                    uint32 j;
                    WASMExport *export_tmp;

                    bh_assert(module->malloc_func_index == (uint32)-1);
                    module->malloc_func_index = func_index;
                    LOG_VERBOSE("Found malloc function, name: %s, index: %u",
                                exports[i].name, exports[i].index);

                    /* resolve retain function.
                        If not find, reset malloc function index */
                    export_tmp = module->exports;
                    for (j = 0; j < module->export_count; j++, export_tmp++) {
                        if ((export_tmp->kind == EXPORT_KIND_FUNC)
                            && (!strcmp(export_tmp->name, "__retain")
                                || !strcmp(export_tmp->name, "__pin"))) {
                            func_index =
                                export_tmp->index - module->import_func_count;
                            func_type_index =
                                module->func_type_indexes[func_index];
                            func_type = module->func_types[func_type_index];
                            if (func_type->param_count == 1
                                && func_type->result_count == 1
                                && func_type->types[0] == VALUE_TYPE_I32
                                && func_type->types[1] == VALUE_TYPE_I32) {
                                bh_assert(module->retain_func_index
                                          == (uint32)-1);
                                module->retain_func_index = export_tmp->index;
                                LOG_VERBOSE("Found retain function, name: %s, "
                                            "index: %u",
                                            export_tmp->name,
                                            export_tmp->index);
                                break;
                            }
                        }
                    }
                    if (j == module->export_count) {
                        module->malloc_func_index = (uint32)-1;
                        LOG_VERBOSE("Can't find retain function,"
                                    "reset malloc function index to -1");
                    }
                }
            }
            else if ((!strcmp(exports[i].name, "free"))
                     || (!strcmp(exports[i].name, "__release"))
                     || (!strcmp(exports[i].name, "__unpin"))) {
                func_index = exports[i].index - module->import_func_count;
                func_type_index = module->func_type_indexes[func_index];
                func_type = module->func_types[func_type_index];
                if (func_type->param_count == 1 && func_type->result_count == 0
                    && func_type->types[0] == VALUE_TYPE_I32) {
                    bh_assert(module->free_func_index == (uint32)-1);
                    module->free_func_index = func_index;
                    LOG_VERBOSE("Found free function, name: %s, index: %u",
                                exports[i].name, exports[i].index);
                }
            }
        }
    }

    /* Flush data cache before executing AOT code,
     * otherwise unpredictable behavior can occur. */
    os_dcache_flush();

#if WASM_ENABLE_MEMORY_TRACING != 0
    wasm_runtime_dump_module_mem_consumption((WASMModuleCommon *)module);
#endif

#if WASM_ENABLE_DEBUG_AOT != 0
    if (!jit_code_entry_create(module->elf_hdr, module->elf_size)) {
        set_error_buf(error_buf, error_buf_size,
                      "create jit code entry failed");
        return false;
    }
#endif
    return true;
}

static AOTModule *
create_module(char *error_buf, uint32 error_buf_size)
{
    AOTModule *module =
        loader_malloc(sizeof(AOTModule), error_buf, error_buf_size);

    if (!module) {
        return NULL;
    }

    module->module_type = Wasm_Module_AoT;

    return module;
}

AOTModule *
aot_load_from_sections(AOTSection *section_list, char *error_buf,
                       uint32 error_buf_size)
{
    AOTModule *module = create_module(error_buf, error_buf_size);

    if (!module)
        return NULL;

    if (!load_from_sections(module, section_list, false, error_buf,
                            error_buf_size)) {
        aot_unload(module);
        return NULL;
    }

    LOG_VERBOSE("Load module from sections success.\n");
    return module;
}

static void
destroy_sections(AOTSection *section_list, bool destroy_aot_text)
{
    AOTSection *section = section_list, *next;
    while (section) {
        next = section->next;
        if (destroy_aot_text && section->section_type == AOT_SECTION_TYPE_TEXT
            && section->section_body)
            os_munmap((uint8 *)section->section_body,
                      section->section_body_size);
        wasm_runtime_free(section);
        section = next;
    }
}

static bool
resolve_execute_mode(const uint8 *buf, uint32 size, bool *p_mode,
                     char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf + size;
    uint32 section_type;
    uint32 section_size = 0;
    uint16 e_type = 0;

    p += 8;
    while (p < p_end) {
        read_uint32(p, p_end, section_type);
        if (section_type <= AOT_SECTION_TYPE_SIGANATURE
            || section_type == AOT_SECTION_TYPE_TARGET_INFO) {
            read_uint32(p, p_end, section_size);
            CHECK_BUF(p, p_end, section_size);
            if (section_type == AOT_SECTION_TYPE_TARGET_INFO) {
                p += 4;
                read_uint16(p, p_end, e_type);
                if (e_type == E_TYPE_XIP) {
                    *p_mode = true;
                }
                else {
                    *p_mode = false;
                }
                break;
            }
        }
        else if (section_type > AOT_SECTION_TYPE_SIGANATURE) {
            set_error_buf(error_buf, error_buf_size,
                          "resolve execute mode failed");
            break;
        }
        p += section_size;
    }
    return true;
fail:
    return false;
}

static bool
create_sections(AOTModule *module, const uint8 *buf, uint32 size,
                AOTSection **p_section_list, char *error_buf,
                uint32 error_buf_size)
{
    AOTSection *section_list = NULL, *section_list_end = NULL, *section;
    const uint8 *p = buf, *p_end = buf + size;
    bool destroy_aot_text = false;
    bool is_indirect_mode = false;
    uint32 section_type;
    uint32 section_size;
    uint64 total_size;
    uint8 *aot_text;

    if (!resolve_execute_mode(buf, size, &is_indirect_mode, error_buf,
                              error_buf_size)) {
        goto fail;
    }

    module->is_indirect_mode = is_indirect_mode;

    p += 8;
    while (p < p_end) {
        read_uint32(p, p_end, section_type);
        if (section_type < AOT_SECTION_TYPE_SIGANATURE
            || section_type == AOT_SECTION_TYPE_CUSTOM) {
            read_uint32(p, p_end, section_size);
            CHECK_BUF(p, p_end, section_size);

            if (!(section = loader_malloc(sizeof(AOTSection), error_buf,
                                          error_buf_size))) {
                goto fail;
            }

            memset(section, 0, sizeof(AOTSection));
            section->section_type = (int32)section_type;
            section->section_body = (uint8 *)p;
            section->section_body_size = section_size;

            if (section_type == AOT_SECTION_TYPE_TEXT) {
                if ((section_size > 0) && !module->is_indirect_mode) {
                    int map_prot =
                        MMAP_PROT_READ | MMAP_PROT_WRITE | MMAP_PROT_EXEC;
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64) \
    || defined(BUILD_TARGET_RISCV64_LP64D)                       \
    || defined(BUILD_TARGET_RISCV64_LP64)
                    /* aot code and data in x86_64 must be in range 0 to 2G due
                       to relocation for R_X86_64_32/32S/PC32 */
                    int map_flags = MMAP_MAP_32BIT;
#else
                    int map_flags = MMAP_MAP_NONE;
#endif
                    total_size =
                        (uint64)section_size + aot_get_plt_table_size();
                    total_size = (total_size + 3) & ~((uint64)3);
                    if (total_size >= UINT32_MAX
                        || !(aot_text = os_mmap(NULL, (uint32)total_size,
                                                map_prot, map_flags))) {
                        wasm_runtime_free(section);
                        set_error_buf(error_buf, error_buf_size,
                                      "mmap memory failed");
                        goto fail;
                    }
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64)
#if !defined(BH_PLATFORM_LINUX_SGX) && !defined(BH_PLATFORM_WINDOWS) \
    && !defined(BH_PLATFORM_DARWIN)
                    /* address must be in the first 2 Gigabytes of
                       the process address space */
                    bh_assert((uintptr_t)aot_text < INT32_MAX);
#endif
#endif
                    bh_memcpy_s(aot_text, (uint32)total_size,
                                section->section_body, (uint32)section_size);
                    section->section_body = aot_text;
                    destroy_aot_text = true;

                    if ((uint32)total_size > section->section_body_size) {
                        memset(aot_text + (uint32)section_size, 0,
                               (uint32)total_size - section_size);
                        section->section_body_size = (uint32)total_size;
                    }
                }
            }

            if (!section_list)
                section_list = section_list_end = section;
            else {
                section_list_end->next = section;
                section_list_end = section;
            }

            p += section_size;
        }
        else {
            set_error_buf(error_buf, error_buf_size, "invalid section id");
            goto fail;
        }
    }

    if (!section_list) {
        set_error_buf(error_buf, error_buf_size, "create section list failed");
        return false;
    }

    *p_section_list = section_list;
    return true;
fail:
    if (section_list)
        destroy_sections(section_list, destroy_aot_text);
    return false;
}

static bool
load(const uint8 *buf, uint32 size, AOTModule *module, char *error_buf,
     uint32 error_buf_size)
{
    const uint8 *buf_end = buf + size;
    const uint8 *p = buf, *p_end = buf_end;
    uint32 magic_number, version;
    AOTSection *section_list = NULL;
    bool ret;

    read_uint32(p, p_end, magic_number);
    if (magic_number != AOT_MAGIC_NUMBER) {
        set_error_buf(error_buf, error_buf_size, "magic header not detected");
        return false;
    }

    read_uint32(p, p_end, version);
    if (version != AOT_CURRENT_VERSION) {
        set_error_buf(error_buf, error_buf_size, "unknown binary version");
        return false;
    }

    if (!create_sections(module, buf, size, &section_list, error_buf,
                         error_buf_size))
        return false;

    ret = load_from_sections(module, section_list, true, error_buf,
                             error_buf_size);
    if (!ret) {
        /* If load_from_sections() fails, then aot text is destroyed
           in destroy_sections() */
        destroy_sections(section_list, module->is_indirect_mode ? false : true);
        /* aot_unload() won't destroy aot text again */
        module->code = NULL;
    }
    else {
        /* If load_from_sections() succeeds, then aot text is set to
           module->code and will be destroyed in aot_unload() */
        destroy_sections(section_list, false);
    }
    return ret;
fail:
    return false;
}

AOTModule *
aot_load_from_aot_file(const uint8 *buf, uint32 size, char *error_buf,
                       uint32 error_buf_size)
{
    AOTModule *module = create_module(error_buf, error_buf_size);

    if (!module)
        return NULL;

    if (!load(buf, size, module, error_buf, error_buf_size)) {
        aot_unload(module);
        return NULL;
    }

    LOG_VERBOSE("Load module success.\n");
    return module;
}

#if WASM_ENABLE_JIT != 0
#if WASM_ENABLE_LAZY_JIT != 0
/* Orc JIT thread arguments */
typedef struct OrcJitThreadArg {
    AOTCompData *comp_data;
    AOTCompContext *comp_ctx;
    AOTModule *module;
    int32 group_idx;
    int32 group_stride;
} OrcJitThreadArg;

static bool orcjit_stop_compiling = false;
static korp_tid orcjit_threads[WASM_LAZY_JIT_COMPILE_THREAD_NUM];
static OrcJitThreadArg orcjit_thread_args[WASM_LAZY_JIT_COMPILE_THREAD_NUM];

static void *
orcjit_thread_callback(void *arg)
{
    LLVMErrorRef error;
    LLVMOrcJITTargetAddress func_addr = 0;
    OrcJitThreadArg *thread_arg = (OrcJitThreadArg *)arg;
    AOTCompData *comp_data = thread_arg->comp_data;
    AOTCompContext *comp_ctx = thread_arg->comp_ctx;
    AOTModule *module = thread_arg->module;
    char func_name[32];
    int32 i;

    /* Compile wasm functions of this group */
    for (i = thread_arg->group_idx; i < (int32)comp_data->func_count;
         i += thread_arg->group_stride) {
        if (!module->func_ptrs[i]) {
            snprintf(func_name, sizeof(func_name), "%s%d", AOT_FUNC_PREFIX, i);
            if ((error = LLVMOrcLLJITLookup(comp_ctx->orc_lazyjit, &func_addr,
                                            func_name))) {
                char *err_msg = LLVMGetErrorMessage(error);
                os_printf("failed to compile orc jit function: %s", err_msg);
                LLVMDisposeErrorMessage(err_msg);
                break;
            }
            /**
             * No need to lock the func_ptr[func_idx] here as it is basic
             * data type, the load/store for it can be finished by one cpu
             * instruction, and there can be only one cpu instruction
             * loading/storing at the same time.
             */
            module->func_ptrs[i] = (void *)func_addr;
        }
        if (orcjit_stop_compiling) {
            break;
        }
    }

    /* Try to compile functions that haven't been compiled by other threads */
    for (i = (int32)comp_data->func_count - 1; i > 0; i--) {
        if (orcjit_stop_compiling) {
            break;
        }
        if (!module->func_ptrs[i]) {
            snprintf(func_name, sizeof(func_name), "%s%d", AOT_FUNC_PREFIX, i);
            if ((error = LLVMOrcLLJITLookup(comp_ctx->orc_lazyjit, &func_addr,
                                            func_name))) {
                char *err_msg = LLVMGetErrorMessage(error);
                os_printf("failed to compile orc jit function: %s", err_msg);
                LLVMDisposeErrorMessage(err_msg);
                break;
            }
            module->func_ptrs[i] = (void *)func_addr;
        }
    }

    return NULL;
}

static void
orcjit_stop_compile_threads()
{
    uint32 i;

    orcjit_stop_compiling = true;
    for (i = 0; i < WASM_LAZY_JIT_COMPILE_THREAD_NUM; i++) {
        os_thread_join(orcjit_threads[i], NULL);
    }
}
#endif

static AOTModule *
aot_load_from_comp_data(AOTCompData *comp_data, AOTCompContext *comp_ctx,
                        char *error_buf, uint32 error_buf_size)
{
    uint32 i;
    uint64 size;
    char func_name[32];
    AOTModule *module;

    /* Allocate memory for module */
    if (!(module =
              loader_malloc(sizeof(AOTModule), error_buf, error_buf_size))) {
        return NULL;
    }

    module->module_type = Wasm_Module_AoT;

    module->import_memory_count = comp_data->import_memory_count;
    module->import_memories = comp_data->import_memories;

    module->memory_count = comp_data->memory_count;
    if (module->memory_count) {
        size = sizeof(AOTMemory) * (uint64)module->memory_count;
        if (!(module->memories =
                  loader_malloc(size, error_buf, error_buf_size))) {
            goto fail1;
        }

        bh_memcpy_s(module->memories, (uint32)size, comp_data->memories,
                    (uint32)size);
    }

    module->mem_init_data_list = comp_data->mem_init_data_list;
    module->mem_init_data_count = comp_data->mem_init_data_count;

    module->import_table_count = comp_data->import_table_count;
    module->import_tables = comp_data->import_tables;

    module->table_count = comp_data->table_count;
    module->tables = comp_data->tables;

    module->table_init_data_list = comp_data->table_init_data_list;
    module->table_init_data_count = comp_data->table_init_data_count;

    module->func_type_count = comp_data->func_type_count;
    module->func_types = comp_data->func_types;

    module->import_global_count = comp_data->import_global_count;
    module->import_globals = comp_data->import_globals;

    module->global_count = comp_data->global_count;
    module->globals = comp_data->globals;

    module->global_count = comp_data->global_count;
    module->globals = comp_data->globals;

    module->global_data_size = comp_data->global_data_size;

    module->import_func_count = comp_data->import_func_count;
    module->import_funcs = comp_data->import_funcs;

    module->func_count = comp_data->func_count;

    /* Allocate memory for function pointers */
    size = (uint64)module->func_count * sizeof(void *);
    if (size > 0
        && !(module->func_ptrs =
                 loader_malloc(size, error_buf, error_buf_size))) {
        goto fail2;
    }

#if WASM_ENABLE_LAZY_JIT != 0
    /* Create threads to compile the wasm functions */
    for (i = 0; i < WASM_LAZY_JIT_COMPILE_THREAD_NUM; i++) {
        orcjit_thread_args[i].comp_data = comp_data;
        orcjit_thread_args[i].comp_ctx = comp_ctx;
        orcjit_thread_args[i].module = module;
        orcjit_thread_args[i].group_idx = (int32)i;
        orcjit_thread_args[i].group_stride = WASM_LAZY_JIT_COMPILE_THREAD_NUM;
        if (os_thread_create(&orcjit_threads[i], orcjit_thread_callback,
                             (void *)&orcjit_thread_args[i],
                             APP_THREAD_STACK_SIZE_DEFAULT)
            != 0) {
            uint32 j;

            set_error_buf(error_buf, error_buf_size,
                          "create orcjit compile thread failed");
            /* Terminate the threads created */
            orcjit_stop_compiling = true;
            for (j = 0; j < i; j++) {
                os_thread_join(orcjit_threads[j], NULL);
            }
            goto fail3;
        }
    }
#else
    /* Resolve function addresses */
    bh_assert(comp_ctx->exec_engine);
    for (i = 0; i < comp_data->func_count; i++) {
        snprintf(func_name, sizeof(func_name), "%s%d", AOT_FUNC_PREFIX, i);
        if (!(module->func_ptrs[i] = (void *)LLVMGetFunctionAddress(
                  comp_ctx->exec_engine, func_name))) {
            set_error_buf(error_buf, error_buf_size,
                          "get function address failed");
            goto fail3;
        }
    }
#endif /* WASM_ENABLE_LAZY_JIT != 0 */

    /* Allocation memory for function type indexes */
    size = (uint64)module->func_count * sizeof(uint32);
    if (size > 0
        && !(module->func_type_indexes =
                 loader_malloc(size, error_buf, error_buf_size))) {
        goto fail4;
    }
    for (i = 0; i < comp_data->func_count; i++)
        module->func_type_indexes[i] = comp_data->funcs[i]->func_type_index;

    module->export_count = comp_data->wasm_module->export_count;
    module->exports = comp_data->wasm_module->exports;

    module->start_func_index = comp_data->start_func_index;
    if (comp_data->start_func_index != (uint32)-1) {
        bh_assert(comp_data->start_func_index
                  < module->import_func_count + module->func_count);
        /* TODO: fix issue that start func cannot be import func */
        if (comp_data->start_func_index >= module->import_func_count) {
#if WASM_ENABLE_LAZY_JIT != 0
            if (!module->func_ptrs[comp_data->start_func_index
                                   - module->import_func_count]) {
                LLVMErrorRef error;
                LLVMOrcJITTargetAddress func_addr = 0;

                snprintf(func_name, sizeof(func_name), "%s%d", AOT_FUNC_PREFIX,
                         comp_data->start_func_index
                             - module->import_func_count);
                if ((error = LLVMOrcLLJITLookup(comp_ctx->orc_lazyjit,
                                                &func_addr, func_name))) {
                    char *err_msg = LLVMGetErrorMessage(error);
                    set_error_buf_v(error_buf, error_buf_size,
                                    "failed to compile orc jit function: %s",
                                    err_msg);
                    LLVMDisposeErrorMessage(err_msg);
                    goto fail5;
                }
                module->func_ptrs[comp_data->start_func_index
                                  - module->import_func_count] =
                    (void *)func_addr;
            }
#endif
            module->start_function =
                module->func_ptrs[comp_data->start_func_index
                                  - module->import_func_count];
        }
    }

    module->malloc_func_index = comp_data->malloc_func_index;
    module->free_func_index = comp_data->free_func_index;
    module->retain_func_index = comp_data->retain_func_index;

    module->aux_data_end_global_index = comp_data->aux_data_end_global_index;
    module->aux_data_end = comp_data->aux_data_end;
    module->aux_heap_base_global_index = comp_data->aux_heap_base_global_index;
    module->aux_heap_base = comp_data->aux_heap_base;
    module->aux_stack_top_global_index = comp_data->aux_stack_top_global_index;
    module->aux_stack_bottom = comp_data->aux_stack_bottom;
    module->aux_stack_size = comp_data->aux_stack_size;

    module->code = NULL;
    module->code_size = 0;

    module->is_jit_mode = true;

    module->wasm_module = comp_data->wasm_module;
    module->comp_ctx = comp_ctx;
    module->comp_data = comp_data;

#if WASM_ENABLE_LIBC_WASI != 0
    module->import_wasi_api = comp_data->wasm_module->import_wasi_api;
#endif

    return module;

#if WASM_ENABLE_LAZY_JIT != 0
fail5:
    if (module->func_type_indexes)
        wasm_runtime_free(module->func_type_indexes);
#endif

fail4:
#if WASM_ENABLE_LAZY_JIT != 0
    /* Terminate all threads before free module->func_ptrs */
    orcjit_stop_compile_threads();
#endif
fail3:
    if (module->func_ptrs)
        wasm_runtime_free(module->func_ptrs);
fail2:
    if (module->memory_count > 0)
        wasm_runtime_free(module->memories);
fail1:
    wasm_runtime_free(module);
    return NULL;
}

AOTModule *
aot_convert_wasm_module(WASMModule *wasm_module, char *error_buf,
                        uint32 error_buf_size)
{
    AOTCompData *comp_data;
    AOTCompContext *comp_ctx;
    AOTModule *aot_module;
    AOTCompOption option = { 0 };
    char *aot_last_error;

    comp_data = aot_create_comp_data(wasm_module);
    if (!comp_data) {
        aot_last_error = aot_get_last_error();
        bh_assert(aot_last_error != NULL);
        set_error_buf(error_buf, error_buf_size, aot_last_error);
        return NULL;
    }

    option.is_jit_mode = true;
    option.opt_level = 3;
    option.size_level = 3;
#if WASM_ENABLE_BULK_MEMORY != 0
    option.enable_bulk_memory = true;
#endif
#if WASM_ENABLE_THREAD_MGR != 0
    option.enable_thread_mgr = true;
#endif
#if WASM_ENABLE_TAIL_CALL != 0
    option.enable_tail_call = true;
#endif
#if WASM_ENABLE_SIMD != 0
    option.enable_simd = true;
#endif
#if WASM_ENABLE_REF_TYPES != 0
    option.enable_ref_types = true;
#endif
    option.enable_aux_stack_check = true;
#if (WASM_ENABLE_PERF_PROFILING != 0) || (WASM_ENABLE_DUMP_CALL_STACK != 0)
    option.enable_aux_stack_frame = true;
#endif

    comp_ctx = aot_create_comp_context(comp_data, &option);
    if (!comp_ctx) {
        aot_last_error = aot_get_last_error();
        bh_assert(aot_last_error != NULL);
        set_error_buf(error_buf, error_buf_size, aot_last_error);
        goto fail1;
    }

    if (!aot_compile_wasm(comp_ctx)) {
        aot_last_error = aot_get_last_error();
        bh_assert(aot_last_error != NULL);
        set_error_buf(error_buf, error_buf_size, aot_last_error);
        goto fail2;
    }

    aot_module =
        aot_load_from_comp_data(comp_data, comp_ctx, error_buf, error_buf_size);
    if (!aot_module) {
        goto fail2;
    }

    return aot_module;

fail2:
    aot_destroy_comp_context(comp_ctx);
fail1:
    aot_destroy_comp_data(comp_data);
    return NULL;
}
#endif

void
aot_unload(AOTModule *module)
{
#if WASM_ENABLE_JIT != 0
#if WASM_ENABLE_LAZY_JIT != 0
    orcjit_stop_compile_threads();
#endif

    if (module->comp_data)
        aot_destroy_comp_data(module->comp_data);

    if (module->comp_ctx)
        aot_destroy_comp_context(module->comp_ctx);

    if (module->wasm_module)
        wasm_loader_unload(module->wasm_module);
#endif

    if (module->import_memories)
        destroy_import_memories(module->import_memories, module->is_jit_mode);

    if (module->memories)
        wasm_runtime_free(module->memories);

    if (module->mem_init_data_list)
        destroy_mem_init_data_list(module->mem_init_data_list,
                                   module->mem_init_data_count,
                                   module->is_jit_mode);

    if (module->native_symbol_list)
        wasm_runtime_free(module->native_symbol_list);

    if (module->import_tables)
        destroy_import_tables(module->import_tables, module->is_jit_mode);

    if (module->tables)
        destroy_tables(module->tables, module->is_jit_mode);

    if (module->table_init_data_list)
        destroy_table_init_data_list(module->table_init_data_list,
                                     module->table_init_data_count,
                                     module->is_jit_mode);

    if (module->func_types)
        destroy_func_types(module->func_types, module->func_type_count,
                           module->is_jit_mode);

    if (module->import_globals)
        destroy_import_globals(module->import_globals, module->is_jit_mode);

    if (module->globals)
        destroy_globals(module->globals, module->is_jit_mode);

    if (module->import_funcs)
        destroy_import_funcs(module->import_funcs, module->is_jit_mode);

    if (module->exports)
        destroy_exports(module->exports, module->is_jit_mode);

    if (module->func_type_indexes)
        wasm_runtime_free(module->func_type_indexes);

    if (module->func_ptrs)
        wasm_runtime_free(module->func_ptrs);

    if (module->const_str_set)
        bh_hash_map_destroy(module->const_str_set);

    if (module->code && !module->is_indirect_mode) {
        /* The layout is: literal size + literal + code (with plt table) */
        uint8 *mmap_addr = module->literal - sizeof(uint32);
        uint32 total_size =
            sizeof(uint32) + module->literal_size + module->code_size;
        os_munmap(mmap_addr, total_size);
    }

#if defined(BH_PLATFORM_WINDOWS)
    if (module->extra_plt_data) {
        os_munmap(module->extra_plt_data, module->extra_plt_data_size);
    }
#endif

#if defined(OS_ENABLE_HW_BOUND_CHECK) && defined(BH_PLATFORM_WINDOWS)
    if (module->rtl_func_table) {
        if (module->rtl_func_table_registered)
            RtlDeleteFunctionTable(module->rtl_func_table);
        wasm_runtime_free(module->rtl_func_table);
    }
#endif

    if (module->data_sections)
        destroy_object_data_sections(module->data_sections,
                                     module->data_section_count);
#if WASM_ENABLE_DEBUG_AOT != 0
    jit_code_entry_destroy(module->elf_hdr);
#endif

#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
    if (module->aux_func_indexes) {
        wasm_runtime_free(module->aux_func_indexes);
    }
    if (module->aux_func_names) {
        wasm_runtime_free((void *)module->aux_func_names);
    }
#endif

#if WASM_ENABLE_LOAD_CUSTOM_SECTION != 0
    wasm_runtime_destroy_custom_sections(module->custom_section_list);
#endif

    wasm_runtime_free(module);
}

uint32
aot_get_plt_table_size()
{
    return get_plt_table_size();
}

#if WASM_ENABLE_LOAD_CUSTOM_SECTION != 0
const uint8 *
aot_get_custom_section(const AOTModule *module, const char *name, uint32 *len)
{
    WASMCustomSection *section = module->custom_section_list;

    while (section) {
        if (strcmp(section->name_addr, name) == 0) {
            if (len) {
                *len = section->content_len;
            }
            return section->content_addr;
        }

        section = section->next;
    }

    return NULL;
}
#endif /* end of WASM_ENABLE_LOAD_CUSTOM_SECTION */
