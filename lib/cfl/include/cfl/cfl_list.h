/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * This is a rebranded copy of the original Monkey HTTP Server linked list
 * interface (cfl_list).
 *
 * - http://monkey-project.com
 * - https://github.com/monkey/monkey
 */

#ifndef CFL_LIST_H
#define CFL_LIST_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
/* Windows */
#define cfl_container_of(address, type, field) ((type *)(                   \
                                                        (unsigned char *)(address) - \
                                                        (intptr_t)(&((type *)0)->field)))
#else
/* Rest of the world */
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define cfl_container_of(ptr, type, member) ({                  \
      const typeof( ((type *)0)->member ) *__mptr = (ptr);      \
      (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

struct cfl_list {
    struct cfl_list *prev, *next;
};

static inline int cfl_list_is_empty(struct cfl_list *head)
{
    if (head->next == head) {
        return 1;
    }

    return 0;
}

static inline void cfl_list_init(struct cfl_list *list)
{
    list->next = list;
    list->prev = list;
}

static inline void __cfl_list_del(struct cfl_list *prev,
                                  struct cfl_list *next)
{
    prev->next = next;
    next->prev = prev;
}

static inline void cfl_list_del(struct cfl_list *entry)
{
    __cfl_list_del(entry->prev, entry->next);

    entry->prev = NULL;
    entry->next = NULL;
}

static inline void __cfl_list_add(struct cfl_list *_new,
                                  struct cfl_list *prev,
                                  struct cfl_list *next)
{
    next->prev = _new;
    _new->next = next;
    _new->prev = prev;
    prev->next = _new;
}

static inline void cfl_list_add(struct cfl_list *_new,
                                struct cfl_list *head)
{
    __cfl_list_add(_new, head->prev, head);
}

static inline void cfl_list_add_after(struct cfl_list *_new,
                                      struct cfl_list *prev,
                                      struct cfl_list *head)
{
    struct cfl_list *next;

    if (_new == NULL || prev == NULL || head == NULL) {
        return;
    }

    next = prev->next;
    next->prev = prev;
    _new->next = next;
    _new->prev = prev;
    prev->next = _new;
}

static inline void cfl_list_add_before(struct cfl_list *_new,
                                       struct cfl_list *next,
                                       struct cfl_list *head)
{
    struct cfl_list *prev;

    if (_new == NULL || next == NULL || head == NULL) {
        return;
    }

    prev = next->prev;
    _new->next = next;
    _new->prev = prev;
    prev->next = _new;
    next->prev = _new;
}

static inline void cfl_list_append(struct cfl_list *_new,
                                   struct cfl_list *head)
{
    if (cfl_list_is_empty(head)) {
        __cfl_list_add(_new, head->prev, head);
    }
    else {
        cfl_list_add_after(_new,
                           head->prev,
                           head);
    }
}

static inline void cfl_list_prepend(struct cfl_list *_new,
                                    struct cfl_list *head)
{
    if (cfl_list_is_empty(head)) {
        __cfl_list_add(_new, head->prev, head);
    }
    else {
        cfl_list_add_before(_new,
                           head->next,
                           head);
    }
}

static inline int cfl_list_size(struct cfl_list *head)
{
    int ret = 0;
    struct cfl_list *it;

    for (it = head->next; it != head; it = it->next, ret++);

    return ret;
}

static inline void cfl_list_entry_init(struct cfl_list *entry)
{
    entry->next = NULL;
    entry->prev = NULL;
}

static inline int cfl_list_entry_is_orphan(struct cfl_list *entry)
{
    if (entry->next != NULL &&
        entry->prev != NULL) {
        return CFL_FALSE;
    }

    return CFL_TRUE;
}

static inline void cfl_list_cat(struct cfl_list *list, struct cfl_list *head)
{
    struct cfl_list *last;

    last = head->prev;
    last->next = list->next;
    list->next->prev = last;
    list->prev->next = head;
    head->prev = list->prev;
}

#define cfl_list_foreach(curr, head) for( curr = (head)->next; curr != (head); curr = curr->next )
#define cfl_list_foreach_safe(curr, n, head) \
    for (curr = (head)->next, n = curr->next; curr != (head); curr = n, n = curr->next)


#define cfl_list_foreach_r(curr, head) for( curr = (head)->prev; curr != (head); curr = curr->prev )
#define cfl_list_foreach_safe_r(curr, n, head) \
    for (curr = (head)->prev, n = curr->prev; curr != (head); curr = n, n = curr->prev)

#define cfl_list_entry( ptr, type, member ) cfl_container_of( ptr, type, member )

/*
 * First node of the list
 * ----------------------
 * Be careful with this Macro, its intended to be used when some node is already linked
 * to the list (ptr). If the list is empty it will return the list address as it points
 * to it self: list == list->prev == list->next.
 *
 * If exists some possiblity that your code handle an empty list, use cfl_list_is_empty()
 * previously to check if its empty or not.
 */
#define cfl_list_entry_first(ptr, type, member) cfl_container_of((ptr)->next, type, member)

/* First node of the list
 * ---------------------
 * Be careful with this Macro, its intended to be used when some node is already linked
 * to the list (ptr). If the list is empty it will return the list address as it points
 * to it self: list == list->prev == list->next.
 *
 * If exists some possiblity that your code handle an empty list, use cfl_list_is_empty()
 * previously to check if its empty or not.
 */
#define cfl_list_entry_last(ptr, type, member) cfl_container_of((ptr)->prev, type, member)

/* Next node */
#define cfl_list_entry_next(ptr, type, member, head)                     \
    (ptr)->next == (head) ? cfl_container_of((head)->next, type, member) :  \
        cfl_container_of((ptr)->next, type, member);

#endif /* !cfl_list_H_ */
