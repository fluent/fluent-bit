/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _EMS_GC_INTERNAL_H
#define _EMS_GC_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bh_platform.h"
#include "ems_gc.h"

/* HMU (heap memory unit) basic block type */
typedef enum hmu_type_enum {
    HMU_TYPE_MIN = 0,
    HMU_TYPE_MAX = 3,
    HMU_JO = 3,
    HMU_VO = 2,
    HMU_FC = 1,
    HMU_FM = 0
} hmu_type_t;

typedef struct hmu_struct {
    gc_uint32 header;
} hmu_t;

#if BH_ENABLE_GC_VERIFY != 0

#if UINTPTR_MAX > UINT32_MAX
/* 2 prefix paddings for 64-bit pointer */
#define GC_OBJECT_PREFIX_PADDING_CNT 2
#else
/* 3 prefix paddings for 32-bit pointer */
#define GC_OBJECT_PREFIX_PADDING_CNT 3
#endif
#define GC_OBJECT_SUFFIX_PADDING_CNT 4
#define GC_OBJECT_PADDING_VALUE (0x12345678)

typedef struct gc_object_prefix {
    const char *file_name;
    gc_int32 line_no;
    gc_int32 size;
    gc_uint32 padding[GC_OBJECT_PREFIX_PADDING_CNT];
} gc_object_prefix_t;

typedef struct gc_object_suffix {
    gc_uint32 padding[GC_OBJECT_SUFFIX_PADDING_CNT];
} gc_object_suffix_t;

#define OBJ_PREFIX_SIZE (sizeof(gc_object_prefix_t))
#define OBJ_SUFFIX_SIZE (sizeof(gc_object_suffix_t))

void
hmu_init_prefix_and_suffix(hmu_t *hmu, gc_size_t tot_size,
                           const char *file_name, int line_no);

void
hmu_verify(void *vheap, hmu_t *hmu);

#define SKIP_OBJ_PREFIX(p) ((void *)((gc_uint8 *)(p) + OBJ_PREFIX_SIZE))
#define SKIP_OBJ_SUFFIX(p) ((void *)((gc_uint8 *)(p) + OBJ_SUFFIX_SIZE))

#define OBJ_EXTRA_SIZE (HMU_SIZE + OBJ_PREFIX_SIZE + OBJ_SUFFIX_SIZE)

#else /* else of BH_ENABLE_GC_VERIFY */

#define OBJ_PREFIX_SIZE 0
#define OBJ_SUFFIX_SIZE 0

#define SKIP_OBJ_PREFIX(p) ((void *)((gc_uint8 *)(p) + OBJ_PREFIX_SIZE))
#define SKIP_OBJ_SUFFIX(p) ((void *)((gc_uint8 *)(p) + OBJ_SUFFIX_SIZE))

#define OBJ_EXTRA_SIZE (HMU_SIZE + OBJ_PREFIX_SIZE + OBJ_SUFFIX_SIZE)

#endif /* end of BH_ENABLE_GC_VERIFY */

#define hmu_obj_size(s) ((s)-OBJ_EXTRA_SIZE)

#define GC_ALIGN_8(s) (((uint32)(s) + 7) & (uint32)~7)

#define GC_SMALLEST_SIZE \
    GC_ALIGN_8(HMU_SIZE + OBJ_PREFIX_SIZE + OBJ_SUFFIX_SIZE + 8)
#define GC_GET_REAL_SIZE(x)                                 \
    GC_ALIGN_8(HMU_SIZE + OBJ_PREFIX_SIZE + OBJ_SUFFIX_SIZE \
               + (((x) > 8) ? (x) : 8))

/**
 * hmu bit operation
 */

#define SETBIT(v, offset) (v) |= ((uint32)1 << (offset))
#define GETBIT(v, offset) ((v) & ((uint32)1 << (offset)) ? 1 : 0)
#define CLRBIT(v, offset) (v) &= (~((uint32)1 << (offset)))

/* clang-format off */
#define SETBITS(v, offset, size, value)                \
    do {                                               \
        (v) &= ~((((uint32)1 << size) - 1) << offset); \
        (v) |= ((uint32)value << offset);              \
    } while (0)
#define CLRBITS(v, offset, size) \
    (v) &= ~((((uint32)1 << size) - 1) << offset)
#define GETBITS(v, offset, size) \
    (((v) & (((((uint32)1 << size) - 1) << offset))) >> offset)
/* clang-format on */

/**
 * gc object layout definition
 */

#define HMU_SIZE (sizeof(hmu_t))

#define hmu_to_obj(hmu) (gc_object_t)(SKIP_OBJ_PREFIX((hmu_t *)(hmu) + 1))
#define obj_to_hmu(obj) ((hmu_t *)((gc_uint8 *)(obj)-OBJ_PREFIX_SIZE) - 1)

#define HMU_UT_SIZE 2
#define HMU_UT_OFFSET 30

/* clang-format off */
#define hmu_get_ut(hmu) \
    GETBITS((hmu)->header, HMU_UT_OFFSET, HMU_UT_SIZE)
#define hmu_set_ut(hmu, type) \
    SETBITS((hmu)->header, HMU_UT_OFFSET, HMU_UT_SIZE, type)
#define hmu_is_ut_valid(tp) \
    (tp >= HMU_TYPE_MIN && tp <= HMU_TYPE_MAX)
/* clang-format on */

/* P in use bit means the previous chunk is in use */
#define HMU_P_OFFSET 29

#define hmu_mark_pinuse(hmu) SETBIT((hmu)->header, HMU_P_OFFSET)
#define hmu_unmark_pinuse(hmu) CLRBIT((hmu)->header, HMU_P_OFFSET)
#define hmu_get_pinuse(hmu) GETBIT((hmu)->header, HMU_P_OFFSET)

#define HMU_JO_VT_SIZE 27
#define HMU_JO_VT_OFFSET 0
#define HMU_JO_MB_OFFSET 28

#define hmu_mark_jo(hmu) SETBIT((hmu)->header, HMU_JO_MB_OFFSET)
#define hmu_unmark_jo(hmu) CLRBIT((hmu)->header, HMU_JO_MB_OFFSET)
#define hmu_is_jo_marked(hmu) GETBIT((hmu)->header, HMU_JO_MB_OFFSET)

/**
 * The hmu size is divisible by 8, its lowest 3 bits are 0, so we only
 * store its higher bits of bit [29..3], and bit [2..0] are not stored.
 * After that, the maximal heap size can be enlarged from (1<<27) = 128MB
 * to (1<<27) * 8 = 1GB.
 */
#define HMU_SIZE_SIZE 27
#define HMU_SIZE_OFFSET 0

#define HMU_VO_FB_OFFSET 28

#define hmu_is_vo_freed(hmu) GETBIT((hmu)->header, HMU_VO_FB_OFFSET)
#define hmu_unfree_vo(hmu) CLRBIT((hmu)->header, HMU_VO_FB_OFFSET)

#define hmu_get_size(hmu) \
    (GETBITS((hmu)->header, HMU_SIZE_OFFSET, HMU_SIZE_SIZE) << 3)
#define hmu_set_size(hmu, size) \
    SETBITS((hmu)->header, HMU_SIZE_OFFSET, HMU_SIZE_SIZE, ((size) >> 3))

/**
 * HMU free chunk management
 */

#ifndef HMU_NORMAL_NODE_CNT
#define HMU_NORMAL_NODE_CNT 32
#endif
#define HMU_FC_NORMAL_MAX_SIZE ((HMU_NORMAL_NODE_CNT - 1) << 3)
#define HMU_IS_FC_NORMAL(size) ((size) < HMU_FC_NORMAL_MAX_SIZE)
#if HMU_FC_NORMAL_MAX_SIZE >= GC_MAX_HEAP_SIZE
#error "Too small GC_MAX_HEAP_SIZE"
#endif

typedef struct hmu_normal_node {
    hmu_t hmu_header;
    gc_int32 next_offset;
} hmu_normal_node_t;

typedef struct hmu_normal_list {
    hmu_normal_node_t *next;
} hmu_normal_list_t;

static inline hmu_normal_node_t *
get_hmu_normal_node_next(hmu_normal_node_t *node)
{
    return node->next_offset
               ? (hmu_normal_node_t *)((uint8 *)node + node->next_offset)
               : NULL;
}

static inline void
set_hmu_normal_node_next(hmu_normal_node_t *node, hmu_normal_node_t *next)
{
    if (next) {
        bh_assert((uint8 *)next - (uint8 *)node < INT32_MAX);
        node->next_offset = (gc_int32)(intptr_t)((uint8 *)next - (uint8 *)node);
    }
    else {
        node->next_offset = 0;
    }
}

typedef struct hmu_tree_node {
    hmu_t hmu_header;
    gc_size_t size;
    struct hmu_tree_node *left;
    struct hmu_tree_node *right;
    struct hmu_tree_node *parent;
} hmu_tree_node_t;

typedef struct gc_heap_struct {
    /* for double checking*/
    gc_handle_t heap_id;

    gc_uint8 *base_addr;
    gc_size_t current_size;

    korp_mutex lock;

    hmu_normal_list_t kfc_normal_list[HMU_NORMAL_NODE_CNT];

    /* order in kfc_tree is: size[left] <= size[cur] < size[right]*/
    hmu_tree_node_t kfc_tree_root;

    /* whether heap is corrupted, e.g. the hmu nodes are modified
       by user */
    bool is_heap_corrupted;

    gc_size_t init_size;
    gc_size_t highmark_size;
    gc_size_t total_free_size;
} gc_heap_t;

/**
 * MISC internal used APIs
 */

bool
gci_add_fc(gc_heap_t *heap, hmu_t *hmu, gc_size_t size);

int
gci_is_heap_valid(gc_heap_t *heap);

/**
 * Verify heap integrity
 */
void
gci_verify_heap(gc_heap_t *heap);

/**
 * Dump heap nodes
 */
void
gci_dump(gc_heap_t *heap);

#ifdef __cplusplus
}
#endif

#endif /* end of _EMS_GC_INTERNAL_H */
