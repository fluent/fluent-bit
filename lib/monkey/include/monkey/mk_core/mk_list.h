/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
 *  Copyright (C) 2010, Jonathan Gonzalez V. <zeus@gnu.org>
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

#ifndef MK_LIST_H_
#define MK_LIST_H_

#include <stddef.h>
#include "mk_macros.h"

#ifdef _WIN32
/* Windows */
#define container_of(address, type, field) ((type *)(                   \
                                                     (PCHAR)(address) - \
                                                     (ULONG_PTR)(&((type *)0)->field)))
#else
/* Rest of the world */
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({                      \
      const typeof( ((type *)0)->member ) *__mptr = (ptr);      \
      (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

struct mk_list
{
    struct mk_list *prev, *next;
};

static inline void mk_list_init(struct mk_list *list)
{
    list->next = list;
    list->prev = list;
}

static inline void __mk_list_add(struct mk_list *_new, struct mk_list *prev,
                                 struct mk_list *next)
{
    next->prev = _new;
    _new->next = next;
    _new->prev = prev;
    prev->next = _new;
}

static inline void mk_list_add(struct mk_list *_new, struct mk_list *head)
{
    __mk_list_add(_new, head->prev, head);
}

static inline void mk_list_add_after(struct mk_list *_new,
                                     struct mk_list *prev,
                                     struct mk_list *head)
{
    struct mk_list *next;

    if (head->prev == head->next || head->prev == prev) {
        mk_list_add(_new, head);
        return;
    }

    next = prev->next;
    _new->next = next;
    _new->prev = prev;
    prev->next = _new;
    next->prev = _new;
}

static inline int mk_list_is_empty(struct mk_list *head)
{
    if (head->next == head) return 0;
    else return -1;
}

static inline void mk_list_add_before(struct mk_list *_new,
                                      struct mk_list *next,
                                      struct mk_list *head)
{
    struct mk_list *prev;

    if (_new == NULL || next == NULL || head == NULL) {
        return;
    }

    if (mk_list_is_empty(head) == 0 /*empty*/||
        next == head) {
        mk_list_add(_new, head);
        return;
    }

    prev = next->prev;
    _new->next = next;
    _new->prev = prev;
    prev->next = _new;
    next->prev = _new;
}

static inline void mk_list_append(struct mk_list *_new, struct mk_list *head)
{
    if (mk_list_is_empty(head) == 0) {
        __mk_list_add(_new, head->prev, head);
    }
    else {
        mk_list_add_after(_new,
                          head->prev,
                          head);
    }
}

static inline void mk_list_prepend(struct mk_list *_new, struct mk_list *head)
{
    if (mk_list_is_empty(head) == 0) {
        __mk_list_add(_new, head->prev, head);
    }
    else {
        mk_list_add_before(_new,
                           head->next,
                           head);
    }
}

static inline void __mk_list_del(struct mk_list *prev, struct mk_list *next)
{
    prev->next = next;
    next->prev = prev;
}

static inline void mk_list_del(struct mk_list *entry)
{
    __mk_list_del(entry->prev, entry->next);
    entry->prev = NULL;
    entry->next = NULL;
}

static inline int mk_list_is_set(struct mk_list *head)
{
    if (head->next && head->prev) {
        return 0;
    }

    return -1;
}

static inline int mk_list_size(struct mk_list *head)
{
    int ret = 0;
    struct mk_list *it;
    for (it = head->next; it != head; it = it->next, ret++);
    return ret;
}

static inline void mk_list_entry_init(struct mk_list *list)
{
    list->next = NULL;
    list->prev = NULL;
}

static inline int mk_list_entry_is_orphan(struct mk_list *head)
{
    if (head->next != NULL &&
        head->prev != NULL) {
        return MK_FALSE;
    }

    return MK_TRUE;
}

static inline int mk_list_entry_orphan(struct mk_list *head)
{
    if (head->next && head->prev) {
        return 0;
    }

    return -1;
}

static inline void mk_list_cat(struct mk_list *list, struct mk_list *head)
{
    struct mk_list *last;

    last = head->prev;
    last->next = list->next;
    list->next->prev = last;
    list->prev->next = head;
    head->prev = list->prev;
}

#define mk_list_foreach(curr, head) for( curr = (head)->next; curr != (head); curr = curr->next )
#define mk_list_foreach_safe(curr, n, head) \
    for (curr = (head)->next, n = curr->next; curr != (head); curr = n, n = curr->next)


#define mk_list_foreach_r(curr, head) for( curr = (head)->prev; curr != (head); curr = curr->prev )
#define mk_list_foreach_safe_r(curr, n, head) \
    for (curr = (head)->prev, n = curr->prev; curr != (head); curr = n, n = curr->prev)

#define mk_list_entry( ptr, type, member ) container_of( ptr, type, member )

/*
 * First node of the list
 * ----------------------
 * Be careful with this Macro, its intended to be used when some node is already linked
 * to the list (ptr). If the list is empty it will return the list address as it points
 * to it self: list == list->prev == list->next.
 *
 * If exists some possiblity that your code handle an empty list, use mk_list_is_empty()
 * previously to check if its empty or not.
 */
#define mk_list_entry_first(ptr, type, member) container_of((ptr)->next, type, member)

/* First node of the list
 * ---------------------
 * Be careful with this Macro, its intended to be used when some node is already linked
 * to the list (ptr). If the list is empty it will return the list address as it points
 * to it self: list == list->prev == list->next.
 *
 * If exists some possiblity that your code handle an empty list, use mk_list_is_empty()
 * previously to check if its empty or not.
 */
#define mk_list_entry_last(ptr, type, member) container_of((ptr)->prev, type, member)

/* Next node */
#define mk_list_entry_next(ptr, type, member, head)                     \
    (ptr)->next == (head) ? container_of((head)->next, type, member) :  \
        container_of((ptr)->next, type, member);

#endif /* !MK_LIST_H_ */
