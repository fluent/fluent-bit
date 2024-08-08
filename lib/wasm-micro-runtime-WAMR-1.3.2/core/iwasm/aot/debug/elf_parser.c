/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include "elf.h"

#include "aot_runtime.h"
#include "bh_log.h"
#include "elf_parser.h"

bool
is_ELF(void *buf)
{
    Elf32_Ehdr *eh = (Elf32_Ehdr *)buf;
    if (!strncmp((char *)eh->e_ident, "\177ELF", 4)) {
        LOG_VERBOSE("the buffer is ELF entry!");
        return true;
    }
    LOG_VERBOSE("the buffer is not ELF entry!");
    return false;
}

static bool
is64Bit(Elf32_Ehdr *eh)
{
    if (eh->e_ident[EI_CLASS] == ELFCLASS64)
        return true;
    else
        return false;
}

static bool
is32Bit(Elf32_Ehdr *eh)
{
    if (eh->e_ident[EI_CLASS] == ELFCLASS32)
        return true;
    else
        return false;
}

bool
is_ELF64(void *buf)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    if (!strncmp((char *)eh->e_ident, "\177ELF", 4)) {
        LOG_VERBOSE("the buffer is ELF entry!");
        return true;
    }
    LOG_VERBOSE("the buffer is not ELF entry!");
    return false;
}

static void
read_section_header_table(Elf32_Ehdr *eh, Elf32_Shdr *sh_table[])
{
    uint32_t i;
    char *buf = (char *)eh;
    buf += eh->e_shoff;
    LOG_VERBOSE("str index = %d count=%d", eh->e_shstrndx, eh->e_shnum);
    for (i = 0; i < eh->e_shnum; i++) {
        sh_table[i] = (Elf32_Shdr *)buf;
        buf += eh->e_shentsize;
    }
}

static void
read_section_header_table64(Elf64_Ehdr *eh, Elf64_Shdr *sh_table[])
{
    uint32_t i;
    char *buf = (char *)eh;
    buf += eh->e_shoff;

    for (i = 0; i < eh->e_shnum; i++) {
        sh_table[i] = (Elf64_Shdr *)buf;
        buf += eh->e_shentsize;
    }
}

static char *
get_section(Elf32_Ehdr *eh, Elf32_Shdr *section_header)
{
    char *buf = (char *)eh;
    return buf + section_header->sh_offset;
}

static char *
get_section64(Elf64_Ehdr *eh, Elf64_Shdr *section_header)
{
    char *buf = (char *)eh;
    return buf + section_header->sh_offset;
}

static bool
is_text_section(const char *section_name)
{
    return !strcmp(section_name, ".text") || !strcmp(section_name, ".ltext");
}

bool
get_text_section(void *buf, uint64_t *offset, uint64_t *size)
{
    bool ret = false;
    uint32 i;
    char *sh_str;

    /* Assumption: Only one of .text or .ltext is non-empty. */
    if (is64Bit(buf)) {
        Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
        Elf64_Shdr **sh_table =
            wasm_runtime_malloc(eh->e_shnum * sizeof(Elf64_Shdr *));
        if (sh_table) {
            read_section_header_table64(eh, sh_table);
            sh_str = get_section64(eh, sh_table[eh->e_shstrndx]);
            for (i = 0; i < eh->e_shnum; i++) {
                if (is_text_section(sh_str + sh_table[i]->sh_name)) {
                    *offset = sh_table[i]->sh_offset;
                    *size = sh_table[i]->sh_size;
                    sh_table[i]->sh_addr =
                        (Elf64_Addr)(uintptr_t)((char *)buf
                                                + sh_table[i]->sh_offset);
                    ret = true;
                    if (*size > 0) {
                        break;
                    }
                }
            }
            wasm_runtime_free(sh_table);
        }
    }
    else if (is32Bit(buf)) {
        Elf32_Ehdr *eh = (Elf32_Ehdr *)buf;
        Elf32_Shdr **sh_table =
            wasm_runtime_malloc(eh->e_shnum * sizeof(Elf32_Shdr *));
        if (sh_table) {
            read_section_header_table(eh, sh_table);
            sh_str = get_section(eh, sh_table[eh->e_shstrndx]);
            for (i = 0; i < eh->e_shnum; i++) {
                if (is_text_section(sh_str + sh_table[i]->sh_name)) {
                    *offset = sh_table[i]->sh_offset;
                    *size = sh_table[i]->sh_size;
                    sh_table[i]->sh_addr =
                        (Elf32_Addr)(uintptr_t)((char *)buf
                                                + sh_table[i]->sh_offset);
                    ret = true;
                    if (*size > 0) {
                        break;
                    }
                }
            }
            wasm_runtime_free(sh_table);
        }
    }

    return ret;
}
