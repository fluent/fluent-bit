/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2015, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RDLIST_H_
#define _RDLIST_H_


/**
 *
 * Simple light-weight append-only list to be used as a collection convenience.
 *
 */

typedef struct rd_list_s {
        int    rl_size;
        int    rl_cnt;
        void **rl_elems;
	void (*rl_free_cb) (void *);
	int    rl_flags;
#define RD_LIST_F_ALLOCATED  0x1  /* The rd_list_t is allocated,
				   * will be free on destroy() */
#define RD_LIST_F_SORTED     0x2  /* Set by sort(), cleared by any mutations.
				   * When this flag is set bsearch() is used
				   * by find(), otherwise a linear search. */
#define RD_LIST_F_FIXED_SIZE 0x4  /* Assert on grow */
#define RD_LIST_F_UNIQUE     0x8  /* Don't allow duplicates:
                                   * ONLY ENFORCED BY CALLER. */
} rd_list_t;


/**
 * @brief Initialize a list, preallocate space for 'initial_size' elements
 *       (optional).
 *       List elements will optionally be freed by \p free_cb.
 *
 * @returns \p rl
 */
rd_list_t *
rd_list_init (rd_list_t *rl, int initial_size, void (*free_cb) (void *));


/**
 * Allocate a new list pointer and initialize it according to rd_list_init().
 *
 * Use rd_list_destroy() to free.
 */
rd_list_t *rd_list_new (int initial_size, void (*free_cb) (void *));


/**
 * @brief Prepare list to for an additional \p size elements.
 *        This is an optimization to avoid incremental grows.
 */
void rd_list_grow (rd_list_t *rl, size_t size);

/**
 * @brief Preallocate elements to avoid having to pass an allocated pointer to
 *        rd_list_add(), instead pass NULL to rd_list_add() and use the returned
 *        pointer as the element.
 *
 * @param elemsize element size
 * @param size number of elements
 *
 * @remark Preallocated element lists can't grow past \p size.
 */
void rd_list_prealloc_elems (rd_list_t *rl, size_t elemsize, size_t size);


/**
 * @brief Free a pointer using the list's free_cb
 *
 * @remark If no free_cb is set, or \p ptr is NULL, dont do anything
 *
 * Typical use is rd_list_free_cb(rd_list_remove_cmp(....));
 */
void rd_list_free_cb (rd_list_t *rl, void *ptr);


/**
 * @brief Append element to list
 *
 * @returns \p elem. If \p elem is NULL the default element for that index
 *          will be returned (for use with set_elems).
 */
void *rd_list_add (rd_list_t *rl, void *elem);


/**
 * Remove element from list.
 * This is a slow O(n) + memmove operation.
 * Returns the removed element.
 */
void *rd_list_remove (rd_list_t *rl, void *match_elem);

/**
 * Remove element from list using comparator.
 * See rd_list_remove()
 */
void *rd_list_remove_cmp (rd_list_t *rl, void *match_elem,
                         int (*cmp) (void *_a, void *_b));


/**
 * @brief Remove element at index \p idx.
 *
 * This is a O(1) + memmove operation
 */
void rd_list_remove_elem (rd_list_t *rl, int idx);


/**
 * @brief Remove all elements matching comparator.
 *
 * @returns the number of elements removed.
 *
 * @sa rd_list_remove()
 */
int rd_list_remove_multi_cmp (rd_list_t *rl, void *match_elem,
                               int (*cmp) (void *_a, void *_b));


/**
 * Sort list using comparator
 */
void rd_list_sort (rd_list_t *rl, int (*cmp) (const void *, const void *));


/**
 * Empties the list (but does not free any memory)
 */
void rd_list_clear (rd_list_t *rl);


/**
 * Empties the list, frees the element array, and optionally frees
 * each element using the registered \c rl->rl_free_cb.
 *
 * If the list was previously allocated with rd_list_new() it will be freed.
 */
void rd_list_destroy (rd_list_t *rl);


/**
 * Returns the element at index 'idx', or NULL if out of range.
 *
 * Typical iteration is:
 *    int i = 0;
 *    my_type_t *obj;
 *    while ((obj = rd_list_elem(rl, i++)))
 *        do_something(obj);
 */
void *rd_list_elem (const rd_list_t *rl, int idx);

#define RD_LIST_FOREACH(elem,listp,idx) \
        for (idx = 0 ; (elem = rd_list_elem(listp, idx)) ; idx++)

#define RD_LIST_FOREACH_REVERSE(elem,listp,idx)                         \
        for (idx = (listp)->rl_cnt-1 ;                                  \
             idx >= 0 && (elem = rd_list_elem(listp, idx)) ; idx--)

/**
 * Returns the number of elements in list.
 */
static RD_INLINE RD_UNUSED int rd_list_cnt (const rd_list_t *rl) {
        return rl->rl_cnt;
}


/**
 * Returns true if list is empty
 */
#define rd_list_empty(rl) (rd_list_cnt(rl) == 0)



/**
 * Find element using comparator
 * 'match' will be the first argument to 'cmp', and each element (up to a match)
 * will be the second argument to 'cmp'.
 */
void *rd_list_find (const rd_list_t *rl, const void *match,
                    int (*cmp) (const void *, const void *));



/**
 * @brief Compare list \p a to \p b.
 *
 * @returns < 0 if a was "lesser" than b,
 *          > 0 if a was "greater" than b,
 *            0 if a and b are equal.
 */
int rd_list_cmp (const rd_list_t *a, rd_list_t *b,
                 int (*cmp) (const void *, const void *));

/**
 * @brief Simple element pointer comparator
 */
int rd_list_cmp_ptr (const void *a, const void *b);


/**
 * @brief Apply \p cb to each element in list, if \p cb returns 0
 *        the element will be removed (but not freed).
 */
void rd_list_apply (rd_list_t *rl,
                    int (*cb) (void *elem, void *opaque), void *opaque);



/**
 * @brief Copy list \p src, returning a new list,
 *        using optional \p copy_cb (per elem)
 */
rd_list_t *rd_list_copy (const rd_list_t *src,
                         void *(*copy_cb) (const void *elem, void *opaque),
                         void *opaque);


/**
 * @brief Copy list \p src to \p dst using optional \p copy_cb (per elem)
 * @remark The destination list is not initialized or copied by this function.
 * @remark copy_cb() may return NULL in which case no element is added,
 *                   but the copy callback might have done so itself.
 */
void rd_list_copy_to (rd_list_t *dst, const rd_list_t *src,
                      void *(*copy_cb) (const void *elem, void *opaque),
                      void *opaque);

/**
 * @brief String copier for rd_list_copy()
 */
static RD_UNUSED
void *rd_list_string_copy (const void *elem, void *opaque) {
        return rd_strdup((const char *)elem);
}


/**
 * Debugging: Print list to stdout.
 */
void rd_list_dump (const char *what, const rd_list_t *rl);

#endif /* _RDLIST_H_ */
