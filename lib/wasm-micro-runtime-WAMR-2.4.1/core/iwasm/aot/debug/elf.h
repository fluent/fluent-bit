/****************************************************************************
 * include/elf.h
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

#ifndef __INCLUDE_ELF_H
#define __INCLUDE_ELF_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdint.h>

#define EI_NIDENT 16 /* Size of e_ident[] */

/* NOTE: elf64.h and elf32.h refer EI_NIDENT defined above */

#include "elf64.h"
#include "elf32.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Values for Elf_Ehdr::e_type */

#define ET_NONE 0        /* No file type */
#define ET_REL 1         /* Relocatable file */
#define ET_EXEC 2        /* Executable file */
#define ET_DYN 3         /* Shared object file */
#define ET_CORE 4        /* Core file */
#define ET_LOPROC 0xff00 /* Processor-specific */
#define ET_HIPROC 0xffff /* Processor-specific */

/* Values for Elf_Ehdr::e_machine (most of this were not included in the
 * original SCO document but have been gleaned from elsewhere).
 */

#define EM_NONE 0         /* No machine */
#define EM_M32 1          /* AT&T WE 32100 */
#define EM_SPARC 2        /* SPARC */
#define EM_386 3          /* Intel 80386 */
#define EM_68K 4          /* Motorola 68000 */
#define EM_88K 5          /* Motorola 88000 */
#define EM_486 6          /* Intel 486+ */
#define EM_860 7          /* Intel 80860 */
#define EM_MIPS 8         /* MIPS R3000 Big-Endian */
#define EM_MIPS_RS4_BE 10 /* MIPS R4000 Big-Endian */
#define EM_PARISC 15      /* HPPA */
#define EM_SPARC32PLUS 18 /* Sun's "v8plus" */
#define EM_PPC 20         /* PowerPC */
#define EM_PPC64 21       /* PowerPC64 */
#define EM_ARM 40         /* ARM */
#define EM_SH 42          /* SuperH */
#define EM_SPARCV9 43     /* SPARC v9 64-bit */
#define EM_H8_300 46
#define EM_IA_64 50  /* HP/Intel IA-64 */
#define EM_X86_64 62 /* AMD x86-64 */
#define EM_S390 22   /* IBM S/390 */
#define EM_CRIS 76   /* Axis Communications 32-bit embedded processor */
#define EM_V850 87   /* NEC v850 */
#define EM_M32R 88   /* Renesas M32R */
#define EM_XTENSA 94 /* Tensilica Xtensa */
#define EM_RISCV 243 /* RISC-V */
#define EM_ALPHA 0x9026
#define EM_CYGNUS_V850 0x9080
#define EM_CYGNUS_M32R 0x9041
#define EM_S390_OLD 0xa390
#define EM_FRV 0x5441

/* Values for Elf_Ehdr::e_version */

#define EV_NONE 0    /* Invalid version */
#define EV_CURRENT 1 /* The current version */

/* Table 2. Ehe ELF identifier */

#define EI_MAG0 0 /* File identification */
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4   /* File class */
#define EI_DATA 5    /* Data encoding */
#define EI_VERSION 6 /* File version */
#define EI_OSABI 7   /* OS ABI */
#define EI_PAD 8     /* Start of padding bytes */

/* EI_NIDENT is defined in "Included Files" section */

#define EI_MAGIC_SIZE 4
#define EI_MAGIC            \
    {                       \
        0x7f, 'E', 'L', 'F' \
    }

#define ELFMAG0 0x7f /* EI_MAG */
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFMAG "\177ELF"

/* Table 3. Values for EI_CLASS */

#define ELFCLASSNONE 0 /* Invalid class */
#define ELFCLASS32 1   /* 32-bit objects */
#define ELFCLASS64 2   /* 64-bit objects */

/* Table 4. Values for EI_DATA */

#define ELFDATANONE 0 /* Invalid data encoding */
#define ELFDATA2LSB                                                          \
    1                 /* Least significant byte occupying the lowest address \
                       */
#define ELFDATA2MSB 2 /* Most significant byte occupying the lowest address */

/* Table 6. Values for EI_OSABI */

#define ELFOSABI_NONE 0   /* UNIX System V ABI */
#define ELFOSABI_SYSV 0   /* Alias.  */
#define ELFOSABI_HPUX 1   /* HP-UX */
#define ELFOSABI_NETBSD 2 /* NetBSD.  */
#define ELFOSABI_GNU 3    /* Object uses GNU ELF extensions.  */
#define ELFOSABI_LINUX ELFOSABI_GNU
/* Compatibility alias.  */
#define ELFOSABI_SOLARIS 6      /* Sun Solaris.  */
#define ELFOSABI_AIX 7          /* IBM AIX.  */
#define ELFOSABI_IRIX 8         /* SGI Irix.  */
#define ELFOSABI_FREEBSD 9      /* FreeBSD.  */
#define ELFOSABI_TRU64 10       /* Compaq TRU64 UNIX.  */
#define ELFOSABI_MODESTO 11     /* Novell Modesto.  */
#define ELFOSABI_OPENBSD 12     /* OpenBSD.  */
#define ELFOSABI_ARM_AEABI 64   /* ARM EABI */
#define ELFOSABI_ARM 97         /* ARM */
#define ELFOSABI_STANDALONE 255 /* Standalone (embedded) application */

#ifndef ELF_OSABI
#define ELF_OSABI ELFOSABI_NONE
#endif

/* Table 7: Special Section Indexes */

#define SHN_UNDEF 0
#define SHN_LOPROC 0xff00
#define SHN_HIPROC 0xff1f
#define SHN_ABS 0xfff1
#define SHN_COMMON 0xfff2

/* Figure 4-9: Section Types, sh_type */

#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_HASH 5
#define SHT_DYNAMIC 6
#define SHT_NOTE 7
#define SHT_NOBITS 8
#define SHT_REL 9
#define SHT_SHLIB 10
#define SHT_DYNSYM 11
#define SHT_LOPROC 0x70000000
#define SHT_HIPROC 0x7fffffff
#define SHT_LOUSER 0x80000000
#define SHT_HIUSER 0xffffffff

/* Figure 4-11: Section Attribute Flags, sh_flags */

#define SHF_WRITE 1
#define SHF_ALLOC 2
#define SHF_EXECINSTR 4
#define SHF_MASKPROC 0xf0000000

/* Figure 4-16: Symbol Binding, ELF_ST_BIND */

#define STB_LOCAL 0
#define STB_GLOBAL 1
#define STB_WEAK 2
#define STB_LOPROC 13
#define STB_HIPROC 15

/* Figure 4-17: Symbol Types, ELF_ST_TYPE */

#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_SECTION 3
#define STT_FILE 4
#define STT_LOPROC 13
#define STT_HIPROC 15

/* Figure 5-2: Segment Types, p_type */

#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_SHLIB 5
#define PT_PHDR 6
#define PT_LOPROC 0x70000000
#define PT_HIPROC 0x7fffffff

/* Figure 5-3: Segment Flag Bits, p_flags */

#define PF_X 1                 /* Execute */
#define PF_W 2                 /* Write */
#define PF_R 4                 /* Read */
#define PF_MASKPROC 0xf0000000 /* Unspecified */

/* Figure 5-10: Dynamic Array Tags, d_tag */

#define DT_NULL 0            /* d_un=ignored */
#define DT_NEEDED 1          /* d_un=d_val */
#define DT_PLTRELSZ 2        /* d_un=d_val */
#define DT_PLTGOT 3          /* d_un=d_ptr */
#define DT_HASH 4            /* d_un=d_ptr */
#define DT_STRTAB 5          /* d_un=d_ptr */
#define DT_SYMTAB 6          /* d_un=d_ptr */
#define DT_RELA 7            /* d_un=d_ptr */
#define DT_RELASZ 8          /* d_un=d_val */
#define DT_RELAENT 9         /* d_un=d_val */
#define DT_STRSZ 10          /* d_un=d_val */
#define DT_SYMENT 11         /* d_un=d_val */
#define DT_INIT 12           /* d_un=d_ptr */
#define DT_FINI 13           /* d_un=d_ptr */
#define DT_SONAME 14         /* d_un=d_val */
#define DT_RPATH 15          /* d_un=d_val */
#define DT_SYMBOLIC 16       /* d_un=ignored */
#define DT_REL 17            /* d_un=d_ptr */
#define DT_RELSZ 18          /* d_un=d_val */
#define DT_RELENT 19         /* d_un=d_val */
#define DT_PLTREL 20         /* d_un=d_val */
#define DT_DEBUG 21          /* d_un=d_ptr */
#define DT_TEXTREL 22        /* d_un=ignored */
#define DT_JMPREL 23         /* d_un=d_ptr */
#define DT_BINDNOW 24        /* d_un=ignored */
#define DT_LOPROC 0x70000000 /* d_un=unspecified */
#define DT_HIPROC 0x7fffffff /* d_un= unspecified */

/* Legal values for note segment descriptor types for core files. */

#define NT_PRSTATUS 1   /* Contains copy of prstatus struct */
#define NT_PRFPREG 2    /* Contains copy of fpregset struct. */
#define NT_FPREGSET 2   /* Contains copy of fpregset struct */
#define NT_PRPSINFO 3   /* Contains copy of prpsinfo struct */
#define NT_PRXREG 4     /* Contains copy of prxregset struct */
#define NT_TASKSTRUCT 4 /* Contains copy of task structure */
#define NT_PLATFORM 5   /* String from sysinfo(SI_PLATFORM) */
#define NT_AUXV 6       /* Contains copy of auxv array */
#define NT_GWINDOWS 7   /* Contains copy of gwindows struct */
#define NT_ASRS 8       /* Contains copy of asrset struct */
#define NT_PSTATUS 10   /* Contains copy of pstatus struct */
#define NT_PSINFO 13    /* Contains copy of psinfo struct */
#define NT_PRCRED 14    /* Contains copy of prcred struct */
#define NT_UTSNAME 15   /* Contains copy of utsname struct */
#define NT_LWPSTATUS 16 /* Contains copy of lwpstatus struct */
#define NT_LWPSINFO 17  /* Contains copy of lwpinfo struct */
#define NT_PRFPXREG 20  /* Contains copy of fprxregset struct */
#define NT_SIGINFO 0x53494749
/* Contains copy of siginfo_t,
 * size might increase
 */
#define NT_FILE 0x46494c45
/* Contains information about mapped
 * files
 */
#define NT_PRXFPREG 0x46e62b7f
/* Contains copy of user_fxsr_struct */
#define NT_PPC_VMX 0x100     /* PowerPC Altivec/VMX registers */
#define NT_PPC_SPE 0x101     /* PowerPC SPE/EVR registers */
#define NT_PPC_VSX 0x102     /* PowerPC VSX registers */
#define NT_PPC_TAR 0x103     /* Target Address Register */
#define NT_PPC_PPR 0x104     /* Program Priority Register */
#define NT_PPC_DSCR 0x105    /* Data Stream Control Register */
#define NT_PPC_EBB 0x106     /* Event Based Branch Registers */
#define NT_PPC_PMU 0x107     /* Performance Monitor Registers */
#define NT_PPC_TM_CGPR 0x108 /* TM checkpointed GPR Registers */
#define NT_PPC_TM_CFPR 0x109 /* TM checkpointed FPR Registers */
#define NT_PPC_TM_CVMX 0x10a /* TM checkpointed VMX Registers */
#define NT_PPC_TM_CVSX 0x10b /* TM checkpointed VSX Registers */
#define NT_PPC_TM_SPR 0x10c  /* TM Special Purpose Registers */
#define NT_PPC_TM_CTAR                      \
    0x10d /* TM checkpointed Target Address \
           * Register                       \
           */
#define NT_PPC_TM_CPPR                        \
    0x10e /* TM checkpointed Program Priority \
           * Register                         \
           */
#define NT_PPC_TM_CDSCR                          \
    0x10f /* TM checkpointed Data Stream Control \
           * Register                            \
           */
#define NT_PPC_PKEY                                         \
    0x110                         /* Memory Protection Keys \
                                   * registers.             \
                                   */
#define NT_386_TLS 0x200          /* i386 TLS slots (struct user_desc) */
#define NT_386_IOPERM 0x201       /* x86 io permission bitmap (1=deny) */
#define NT_X86_XSTATE 0x202       /* x86 extended state using xsave */
#define NT_S390_HIGH_GPRS 0x300   /* s390 upper register halves */
#define NT_S390_TIMER 0x301       /* s390 timer register */
#define NT_S390_TODCMP 0x302      /* s390 TOD clock comparator register */
#define NT_S390_TODPREG 0x303     /* s390 TOD programmable register */
#define NT_S390_CTRS 0x304        /* s390 control registers */
#define NT_S390_PREFIX 0x305      /* s390 prefix register */
#define NT_S390_LAST_BREAK 0x306  /* s390 breaking event address */
#define NT_S390_SYSTEM_CALL 0x307 /* s390 system call restart data */
#define NT_S390_TDB 0x308         /* s390 transaction diagnostic block */
#define NT_S390_VXRS_LOW                                      \
    0x309                       /* s390 vector registers 0-15 \
                                 * upper half.                \
                                 */
#define NT_S390_VXRS_HIGH 0x30a /* s390 vector registers 16-31.  */
#define NT_S390_GS_CB 0x30b     /* s390 guarded storage registers.  */
#define NT_S390_GS_BC                                        \
    0x30c                        /* s390 guarded storage     \
                                  * broadcast control block. \
                                  */
#define NT_S390_RI_CB 0x30d      /* s390 runtime instrumentation.  */
#define NT_ARM_VFP 0x400         /* ARM VFP/NEON registers */
#define NT_ARM_TLS 0x401         /* ARM TLS register */
#define NT_ARM_HW_BREAK 0x402    /* ARM hardware breakpoint registers */
#define NT_ARM_HW_WATCH 0x403    /* ARM hardware watchpoint registers */
#define NT_ARM_SYSTEM_CALL 0x404 /* ARM system call number */
#define NT_ARM_SVE                         \
    0x405 /* ARM Scalable Vector Extension \
           * registers                     \
           */
#define NT_ARM_PAC_MASK                 \
    0x406 /* ARM pointer authentication \
           * code masks.                \
           */
#define NT_ARM_PACA_KEYS                \
    0x407 /* ARM pointer authentication \
           * address keys.              \
           */
#define NT_ARM_PACG_KEYS                                    \
    0x408                     /* ARM pointer authentication \
                               * generic key.               \
                               */
#define NT_VMCOREDD 0x700     /* Vmcore Device Dump Note.  */
#define NT_MIPS_DSP 0x800     /* MIPS DSP ASE registers.  */
#define NT_MIPS_FP_MODE 0x801 /* MIPS floating-point mode.  */
#define NT_MIPS_MSA 0x802     /* MIPS SIMD registers.  */

/* Legal values for the note segment descriptor types for object files.  */

#define NT_VERSION 1 /* Contains a version string.  */

#endif /* __INCLUDE_ELF_H */
