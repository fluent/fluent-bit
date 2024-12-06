/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "ems_gc_internal.h"

static gc_handle_t
gc_init_internal(gc_heap_t *heap, char *base_addr, gc_size_t heap_max_size)
{
    hmu_tree_node_t *root = NULL, *q = NULL;
    int ret;

    memset(heap, 0, sizeof *heap);

    ret = os_mutex_init(&heap->lock);
    if (ret != BHT_OK) {
        os_printf("[GC_ERROR]failed to init lock\n");
        return NULL;
    }

    /* init all data structures*/
    heap->current_size = heap_max_size;
    heap->base_addr = (gc_uint8 *)base_addr;
    heap->heap_id = (gc_handle_t)heap;

    heap->total_free_size = heap->current_size;
    heap->highmark_size = 0;

    root = heap->kfc_tree_root = (hmu_tree_node_t *)heap->kfc_tree_root_buf;
    memset(root, 0, sizeof *root);
    root->size = sizeof *root;
    hmu_set_ut(&root->hmu_header, HMU_FC);
    hmu_set_size(&root->hmu_header, sizeof *root);

    q = (hmu_tree_node_t *)heap->base_addr;
    memset(q, 0, sizeof *q);
    hmu_set_ut(&q->hmu_header, HMU_FC);
    hmu_set_size(&q->hmu_header, heap->current_size);

    ASSERT_TREE_NODE_ALIGNED_ACCESS(q);
    ASSERT_TREE_NODE_ALIGNED_ACCESS(root);

    hmu_mark_pinuse(&q->hmu_header);
    root->right = q;
    q->parent = root;
    q->size = heap->current_size;

    bh_assert(root->size <= HMU_FC_NORMAL_MAX_SIZE);

    return heap;
}

gc_handle_t
gc_init_with_pool(char *buf, gc_size_t buf_size)
{
    char *buf_end = buf + buf_size;
    char *buf_aligned = (char *)(((uintptr_t)buf + 7) & (uintptr_t)~7);
    char *base_addr = buf_aligned + sizeof(gc_heap_t);
    gc_heap_t *heap = (gc_heap_t *)buf_aligned;
    gc_size_t heap_max_size;

    if (buf_size < APP_HEAP_SIZE_MIN) {
        os_printf("[GC_ERROR]heap init buf size (%" PRIu32 ") < %" PRIu32 "\n",
                  buf_size, (uint32)APP_HEAP_SIZE_MIN);
        return NULL;
    }

    base_addr =
        (char *)(((uintptr_t)base_addr + 7) & (uintptr_t)~7) + GC_HEAD_PADDING;
    heap_max_size = (uint32)(buf_end - base_addr) & (uint32)~7;

#if WASM_ENABLE_MEMORY_TRACING != 0
    os_printf("Heap created, total size: %u\n", buf_size);
    os_printf("   heap struct size: %u\n", sizeof(gc_heap_t));
    os_printf("   actual heap size: %u\n", heap_max_size);
    os_printf("   padding bytes: %u\n",
              buf_size - sizeof(gc_heap_t) - heap_max_size);
#endif
    return gc_init_internal(heap, base_addr, heap_max_size);
}

gc_handle_t
gc_init_with_struct_and_pool(char *struct_buf, gc_size_t struct_buf_size,
                             char *pool_buf, gc_size_t pool_buf_size)
{
    gc_heap_t *heap = (gc_heap_t *)struct_buf;
    char *base_addr = pool_buf + GC_HEAD_PADDING;
    char *pool_buf_end = pool_buf + pool_buf_size;
    gc_size_t heap_max_size;

    if ((((uintptr_t)struct_buf) & 7) != 0) {
        os_printf("[GC_ERROR]heap init struct buf not 8-byte aligned\n");
        return NULL;
    }

    if (struct_buf_size < sizeof(gc_handle_t)) {
        os_printf("[GC_ERROR]heap init struct buf size (%" PRIu32 ") < %zu\n",
                  struct_buf_size, sizeof(gc_handle_t));
        return NULL;
    }

    if ((((uintptr_t)pool_buf) & 7) != 0) {
        os_printf("[GC_ERROR]heap init pool buf not 8-byte aligned\n");
        return NULL;
    }

    if (pool_buf_size < APP_HEAP_SIZE_MIN) {
        os_printf("[GC_ERROR]heap init buf size (%" PRIu32 ") < %u\n",
                  pool_buf_size, APP_HEAP_SIZE_MIN);
        return NULL;
    }

    heap_max_size = (uint32)(pool_buf_end - base_addr) & (uint32)~7;

#if WASM_ENABLE_MEMORY_TRACING != 0
    os_printf("Heap created, total size: %u\n",
              struct_buf_size + pool_buf_size);
    os_printf("   heap struct size: %u\n", sizeof(gc_heap_t));
    os_printf("   actual heap size: %u\n", heap_max_size);
    os_printf("   padding bytes: %u\n", pool_buf_size - heap_max_size);
#endif
    return gc_init_internal(heap, base_addr, heap_max_size);
}

int
gc_destroy_with_pool(gc_handle_t handle)
{
    gc_heap_t *heap = (gc_heap_t *)handle;
    int ret = GC_SUCCESS;

#if BH_ENABLE_GC_VERIFY != 0
    hmu_t *cur = (hmu_t *)heap->base_addr;
    hmu_t *end = (hmu_t *)((char *)heap->base_addr + heap->current_size);

    if (
#if BH_ENABLE_GC_CORRUPTION_CHECK != 0
        !heap->is_heap_corrupted &&
#endif
        (hmu_t *)((char *)cur + hmu_get_size(cur)) != end) {
        os_printf("Memory leak detected:\n");
        gci_dump(heap);
        ret = GC_ERROR;
    }
#endif

    os_mutex_destroy(&heap->lock);
    memset(heap, 0, sizeof(gc_heap_t));
    return ret;
}

uint32
gc_get_heap_struct_size()
{
    return sizeof(gc_heap_t);
}

static void
adjust_ptr(uint8 **p_ptr, intptr_t offset)
{
    if (*p_ptr)
        *p_ptr = (uint8 *)((intptr_t)(*p_ptr) + offset);
}

int
gc_migrate(gc_handle_t handle, char *pool_buf_new, gc_size_t pool_buf_size)
{
    gc_heap_t *heap = (gc_heap_t *)handle;
    char *base_addr_new = pool_buf_new + GC_HEAD_PADDING;
    char *pool_buf_end = pool_buf_new + pool_buf_size;
    intptr_t offset = (uint8 *)base_addr_new - (uint8 *)heap->base_addr;
    hmu_t *cur = NULL, *end = NULL;
    hmu_tree_node_t *tree_node;
    uint8 **p_left, **p_right, **p_parent;
    gc_size_t heap_max_size, size;

    if ((((uintptr_t)pool_buf_new) & 7) != 0) {
        os_printf("[GC_ERROR]heap migrate pool buf not 8-byte aligned\n");
        return GC_ERROR;
    }

    heap_max_size = (uint32)(pool_buf_end - base_addr_new) & (uint32)~7;

    if (pool_buf_end < base_addr_new || heap_max_size < heap->current_size) {
        os_printf("[GC_ERROR]heap migrate invlaid pool buf size\n");
        return GC_ERROR;
    }

    if (offset == 0)
        return 0;

#if BH_ENABLE_GC_CORRUPTION_CHECK != 0
    if (heap->is_heap_corrupted) {
        os_printf("[GC_ERROR]Heap is corrupted, heap migrate failed.\n");
        return GC_ERROR;
    }
#endif

    heap->base_addr = (uint8 *)base_addr_new;

    ASSERT_TREE_NODE_ALIGNED_ACCESS(heap->kfc_tree_root);

    p_left = (uint8 **)((uint8 *)heap->kfc_tree_root
                        + offsetof(hmu_tree_node_t, left));
    p_right = (uint8 **)((uint8 *)heap->kfc_tree_root
                         + offsetof(hmu_tree_node_t, right));
    p_parent = (uint8 **)((uint8 *)heap->kfc_tree_root
                          + offsetof(hmu_tree_node_t, parent));
    adjust_ptr(p_left, offset);
    adjust_ptr(p_right, offset);
    adjust_ptr(p_parent, offset);

    cur = (hmu_t *)heap->base_addr;
    end = (hmu_t *)((char *)heap->base_addr + heap->current_size);

    while (cur < end) {
        size = hmu_get_size(cur);

#if BH_ENABLE_GC_CORRUPTION_CHECK != 0
        if (size <= 0 || size > (uint32)((uint8 *)end - (uint8 *)cur)) {
            os_printf("[GC_ERROR]Heap is corrupted, heap migrate failed.\n");
            heap->is_heap_corrupted = true;
            return GC_ERROR;
        }
#endif

        if (hmu_get_ut(cur) == HMU_FC && !HMU_IS_FC_NORMAL(size)) {
            tree_node = (hmu_tree_node_t *)cur;

            ASSERT_TREE_NODE_ALIGNED_ACCESS(tree_node);

            p_left = (uint8 **)((uint8 *)tree_node
                                + offsetof(hmu_tree_node_t, left));
            p_right = (uint8 **)((uint8 *)tree_node
                                 + offsetof(hmu_tree_node_t, right));
            p_parent = (uint8 **)((uint8 *)tree_node
                                  + offsetof(hmu_tree_node_t, parent));
            adjust_ptr(p_left, offset);
            adjust_ptr(p_right, offset);
            if (tree_node->parent != heap->kfc_tree_root)
                /* The root node belongs to heap structure,
                   it is fixed part and isn't changed. */
                adjust_ptr(p_parent, offset);
        }
        cur = (hmu_t *)((char *)cur + size);
    }

#if BH_ENABLE_GC_CORRUPTION_CHECK != 0
    if (cur != end) {
        os_printf("[GC_ERROR]Heap is corrupted, heap migrate failed.\n");
        heap->is_heap_corrupted = true;
        return GC_ERROR;
    }
#else
    bh_assert(cur == end);
#endif

    return 0;
}

bool
gc_is_heap_corrupted(gc_handle_t handle)
{
#if BH_ENABLE_GC_CORRUPTION_CHECK != 0
    gc_heap_t *heap = (gc_heap_t *)handle;

    return heap->is_heap_corrupted ? true : false;
#else
    return false;
#endif
}

#if BH_ENABLE_GC_VERIFY != 0
void
gci_verify_heap(gc_heap_t *heap)
{
    hmu_t *cur = NULL, *end = NULL;

    bh_assert(heap && gci_is_heap_valid(heap));
    cur = (hmu_t *)heap->base_addr;
    end = (hmu_t *)(heap->base_addr + heap->current_size);
    while (cur < end) {
        hmu_verify(heap, cur);
        cur = (hmu_t *)((gc_uint8 *)cur + hmu_get_size(cur));
    }
    bh_assert(cur == end);
}
#endif

void *
gc_heap_stats(void *heap_arg, uint32 *stats, int size)
{
    int i;
    gc_heap_t *heap = (gc_heap_t *)heap_arg;

    for (i = 0; i < size; i++) {
        switch (i) {
            case GC_STAT_TOTAL:
                stats[i] = heap->current_size;
                break;
            case GC_STAT_FREE:
                stats[i] = heap->total_free_size;
                break;
            case GC_STAT_HIGHMARK:
                stats[i] = heap->highmark_size;
                break;
            default:
                break;
        }
    }
    return heap;
}
