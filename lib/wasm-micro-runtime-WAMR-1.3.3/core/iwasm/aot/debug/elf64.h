/****************************************************************************
 * include/elf64.h
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

#ifndef __INCLUDE_ELF64_H
#define __INCLUDE_ELF64_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdint.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* See ELF-64 Object File Format: Version 1.5 Draft 2 */

/* Definitions for Elf64_Rel*::r_info */

#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i)&0xffffffffL)
#define ELF64_R_INFO(s, t) (((s) << 32) + ((t)&0xffffffffL))

#if 0
#define ELF_R_SYM(i) ELF64_R_SYM(i)
#endif

/****************************************************************************
 * Public Type Definitions
 ****************************************************************************/

/* Table 1: ELF-64 Data Types */

typedef uint64_t Elf64_Addr;  /* Unsigned program address */
typedef uint64_t Elf64_Off;   /* Unsigned file offset */
typedef uint16_t Elf64_Half;  /* Unsigned medium integer */
typedef uint32_t Elf64_Word;  /* Unsigned long integer */
typedef int32_t Elf64_Sword;  /* Signed integer */
typedef uint64_t Elf64_Xword; /* Unsigned long integer */
typedef int64_t Elf64_Sxword; /* Signed large integer */

/* Figure 2: ELF-64 Header */

typedef struct {
    unsigned char e_ident[EI_NIDENT]; /* ELF identification */
    Elf64_Half e_type;                /* Object file type */
    Elf64_Half e_machine;             /* Machine type */
    Elf64_Word e_version;             /* Object file version */
    Elf64_Addr e_entry;               /* Entry point address */
    Elf64_Off e_phoff;                /* Program header offset */
    Elf64_Off e_shoff;                /* Section header offset */
    Elf64_Word e_flags;               /* Processor-specific flags */
    Elf64_Half e_ehsize;              /* ELF header size */
    Elf64_Half e_phentsize;           /* Size of program header entry */
    Elf64_Half e_phnum;               /* Number of program header entry */
    Elf64_Half e_shentsize;           /* Size of section header entry */
    Elf64_Half e_shnum;               /* Number of section header entries */
    Elf64_Half e_shstrndx;            /* Section name string table index */
} Elf64_Ehdr;

/* Figure 3: ELF-64 Section Header */

typedef struct {
    Elf64_Word sh_name;       /* Section name */
    Elf64_Word sh_type;       /* Section type */
    Elf64_Xword sh_flags;     /* Section attributes */
    Elf64_Addr sh_addr;       /* Virtual address in memory */
    Elf64_Off sh_offset;      /* Offset in file */
    Elf64_Xword sh_size;      /* Size of section */
    Elf64_Word sh_link;       /* Link to other section */
    Elf64_Word sh_info;       /* Miscellaneous information */
    Elf64_Xword sh_addralign; /* Address alignment boundary */
    Elf64_Xword sh_entsize;   /* Size of entries, if section has table */
} Elf64_Shdr;

/* Figure 4: ELF-64 Symbol Table Entry */

typedef struct {
    Elf64_Word st_name;     /* Symbol name */
    unsigned char st_info;  /* Type and Binding attributes */
    unsigned char st_other; /* Reserved */
    Elf64_Half st_shndx;    /* Section table index */
    Elf64_Addr st_value;    /* Symbol value */
    Elf64_Xword st_size;    /* Size of object (e.g., common) */
} Elf64_Sym;

/* Figure 5: ELF-64 Relocation Entries */

typedef struct {
    Elf64_Addr r_offset; /* Address of reference */
    Elf64_Xword r_info;  /* Symbol index and type of relocation */
} Elf64_Rel;

typedef struct {
    Elf64_Addr r_offset;   /* Address of reference */
    Elf64_Xword r_info;    /* Symbol index and type of relocation */
    Elf64_Sxword r_addend; /* Constant part of expression */
} Elf64_Rela;

/* Figure 6: ELF-64 Program Header Table Entry */

typedef struct {
    Elf64_Word p_type;   /* Type of segment */
    Elf64_Word p_flags;  /* Segment attributes */
    Elf64_Off p_offset;  /* Offset in file */
    Elf64_Addr p_vaddr;  /* Virtual address in memory */
    Elf64_Addr p_paddr;  /* Reserved */
    Elf64_Word p_filesz; /* Size of segment in file */
    Elf64_Word p_memsz;  /* Size of segment in memory */
    Elf64_Word p_align;  /* Alignment of segment */
} Elf64_Phdr;

/* Figure 7. Format of a Note Section */

typedef struct {
    Elf64_Word n_namesz; /* Length of the note's name.  */
    Elf64_Word n_descsz; /* Length of the note's descriptor.  */
    Elf64_Word n_type;   /* Type of the note.  */
} Elf64_Nhdr;

/* Figure 8: Dynamic Table Structure */

typedef struct {
    Elf64_Sxword d_tag;
    union {
        Elf64_Xword d_val;
        Elf64_Addr d_ptr;
    } d_un;
} Elf64_Dyn;

#if 0
typedef Elf64_Addr  Elf_Addr;
typedef Elf64_Ehdr  Elf_Ehdr;
typedef Elf64_Rel   Elf_Rel;
typedef Elf64_Rela  Elf_Rela;
typedef Elf64_Nhdr  Elf_Nhdr;
typedef Elf64_Phdr  Elf_Phdr;
typedef Elf64_Sym   Elf_Sym;
typedef Elf64_Shdr  Elf_Shdr;
typedef Elf64_Word  Elf_Word;
#endif

#endif /* __INCLUDE_ELF64_H */
