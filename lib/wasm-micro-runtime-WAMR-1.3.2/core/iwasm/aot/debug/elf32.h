/****************************************************************************
 * include/elf32.h
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

#ifndef __INCLUDE_ELF32_H
#define __INCLUDE_ELF32_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdint.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define ELF32_ST_BIND(i) ((i) >> 4)
#define ELF32_ST_TYPE(i) ((i)&0xf)
#define ELF32_ST_INFO(b, t) (((b) << 4) | ((t)&0xf))

/* Definitions for Elf32_Rel*::r_info */

#define ELF32_R_SYM(i) ((i) >> 8)
#define ELF32_R_TYPE(i) ((i)&0xff)
#define ELF32_R_INFO(s, t) (((s) << 8) | ((t)&0xff))

#if 0
#define ELF_R_SYM(i) ELF32_R_SYM(i)
#endif

/****************************************************************************
 * Public Type Definitions
 ****************************************************************************/

/* Figure 4.2: 32-Bit Data Types */

typedef uint32_t Elf32_Addr; /* Unsigned program address */
typedef uint16_t Elf32_Half; /* Unsigned medium integer */
typedef uint32_t Elf32_Off;  /* Unsigned file offset */
typedef int32_t Elf32_Sword; /* Signed large integer */
typedef uint32_t Elf32_Word; /* Unsigned large integer */

/* Figure 4-3: ELF Header */

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
} Elf32_Ehdr;

/* Figure 4-8: Section Header */

typedef struct {
    Elf32_Word sh_name;
    Elf32_Word sh_type;
    Elf32_Word sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off sh_offset;
    Elf32_Word sh_size;
    Elf32_Word sh_link;
    Elf32_Word sh_info;
    Elf32_Word sh_addralign;
    Elf32_Word sh_entsize;
} Elf32_Shdr;

/* Figure 4-15: Symbol Table Entry */

typedef struct {
    Elf32_Word st_name;
    Elf32_Addr st_value;
    Elf32_Word st_size;
    unsigned char st_info;
    unsigned char st_other;
    Elf32_Half st_shndx;
} Elf32_Sym;

/* Figure 4-19: Relocation Entries */

typedef struct {
    Elf32_Addr r_offset;
    Elf32_Word r_info;
} Elf32_Rel;

typedef struct {
    Elf32_Addr r_offset;
    Elf32_Word r_info;
    Elf32_Sword r_addend;
} Elf32_Rela;

/* Figure 5-1: Program Header */

typedef struct {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
} Elf32_Phdr;

/* Figure 5-7: Note Information */

typedef struct {
    Elf32_Word n_namesz; /* Length of the note's name.  */
    Elf32_Word n_descsz; /* Length of the note's descriptor.  */
    Elf32_Word n_type;   /* Type of the note.  */
} Elf32_Nhdr;

/* Figure 5-9: Dynamic Structure */

typedef struct {
    Elf32_Sword d_tag;
    union {
        Elf32_Word d_val;
        Elf32_Addr d_ptr;
    } d_un;
} Elf32_Dyn;

#if 0
typedef Elf32_Addr  Elf_Addr;
typedef Elf32_Ehdr  Elf_Ehdr;
typedef Elf32_Rel   Elf_Rel;
typedef Elf32_Rela  Elf_Rela;
typedef Elf32_Nhdr  Elf_Nhdr;
typedef Elf32_Phdr  Elf_Phdr;
typedef Elf32_Sym   Elf_Sym;
typedef Elf32_Shdr  Elf_Shdr;
typedef Elf32_Word  Elf_Word;
#endif

#endif /* __INCLUDE_ELF32_H */
