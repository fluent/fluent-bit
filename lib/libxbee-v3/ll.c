/*
	libxbee - a C/C++ library to aid the use of Digi's XBee wireless modules
	          running in API mode.

	Copyright (C) 2009 onwards  Attie Grande (attie@attie.co.uk)

	libxbee is free software: you can redistribute it and/or modify it
	under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	libxbee is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with libxbee. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>

#include "internal.h"
#include "ll.h"

/* DO NOT RE-ORDER! */
struct xbee_ll_info {
	struct xbee_ll_info *next;
	struct xbee_ll_info *prev;
	int is_head;
	struct xbee_ll_head *head;
	void *item;
};

xbee_err __xbee_ll_get_item(void *list, void *item, struct xbee_ll_info **retItem, int needMutex);

/* this file is scary, sorry it isn't commented... i nearly broke myself writing it
   maybe oneday soon i'll be brave and put some commends down */

xbee_err xbee_ll_init(struct xbee_ll_head *list) {
	if (!list) return XBEE_EMISSINGPARAM;
	list->is_head = 1;
	list->head = NULL;
	list->tail = NULL;
	list->self = list;
	if (xsys_mutex_init(&list->mutex)) return XBEE_EMUTEX;
	return 0;
}

void xbee_ll_destroy(struct xbee_ll_head *list, void (*freeCallback)(void *)) {
	void *p;
	while ((xbee_ll_ext_tail(list, &p)) == XBEE_ENONE && p) {
		if (freeCallback) freeCallback(p);
	}
	xsys_mutex_destroy(&list->mutex);
}

/* ################################################################ */

void *xbee_ll_alloc(void) {
	struct xbee_ll_head *h;
	if ((h = calloc(1, sizeof(struct xbee_ll_head))) == NULL) return NULL;
	if (xbee_ll_init(h) != 0) {
		free(h);
		h = NULL;
	}
	return h;
}

void xbee_ll_free(void *list, void (*freeCallback)(void *)) {
	xbee_ll_destroy(list, freeCallback);
	free(list);
}

/* ################################################################ */

xbee_err xbee_ll_lock(void *list) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i;
	if (!list) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	xbee_mutex_lock(&h->mutex);
	return XBEE_ENONE;
}

xbee_err xbee_ll_unlock(void *list) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i;
	if (!list) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	xbee_mutex_unlock(&h->mutex);
	return XBEE_ENONE;
}

/* ################################################################ */

xbee_err _xbee_ll_add_head(void *list, void *item, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i, *p;
	xbee_err ret;
	ret = XBEE_ENONE;
	if (!list) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	p = h->head;
	if (!(h->head = calloc(1, sizeof(struct xbee_ll_info)))) {
		h->head = p;
		ret = XBEE_ENOMEM;
		goto out;
	}
	h->head->head = h;
	h->head->prev = NULL;
	if (p) {
		h->head->next = p;
		p->prev = h->head;
	} else {
		h->head->next = NULL;
		h->tail = h->head;
	}
	h->head->item = item;
out:
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	return ret;
}

xbee_err _xbee_ll_add_tail(void *list, void *item, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i, *p;
	xbee_err ret;
	ret = XBEE_ENONE;
	if (!list) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	p = h->tail;
	if (!(h->tail = calloc(1, sizeof(struct xbee_ll_info)))) {
		h->tail = p;
		ret = XBEE_ENOMEM;
		goto out;
	}
	h->tail->head = h;
	h->tail->next = NULL;
	if (p) {
		h->tail->prev = p;
		p->next = h->tail;
	} else {
		h->tail->prev = NULL;
		h->head = h->tail;
	}
	h->tail->item = item;
out:
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	return ret;
}

/* NULL ref will add to tail */
xbee_err _xbee_ll_add_after(void *list, void *ref, void *item, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i, *t;
	xbee_err ret;
	ret = XBEE_ENONE;
	if (!list) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (!ref) return xbee_ll_add_tail(h, item);
	if (needMutex) xbee_mutex_lock(&h->mutex);
	i = h->head;
	while (i) {
		if (i->item == ref) break;
		i = i->next;
	}
	if (!i) {
		ret = XBEE_ENOTEXISTS;
		goto out;
	}
	if (!(t = calloc(1, sizeof(struct xbee_ll_info)))) {
		ret = XBEE_ENOMEM;
		goto out;
	}
	t->head = i->head;
	if (!i->next) {
		h->tail = t;
		t->next = NULL;
	} else {
		i->next->prev = t;
		t->next = i->next;
	}
	i->next = t;
	t->prev = i;
	t->item = item;
out:
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	return ret;
}

/* NULL ref will add to head */
xbee_err _xbee_ll_add_before(void *list, void *ref, void *item, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i, *t;
	xbee_err ret;
	ret = XBEE_ENONE;
	if (!list) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (!ref) return xbee_ll_add_tail(h, item);
	if (needMutex) xbee_mutex_lock(&h->mutex);
	i = h->head;
	while (i) {
		if (i->item == ref) break;
		i = i->next;
	}
	if (!i) {
		ret = XBEE_ENOTEXISTS;
		goto out;
	}
	if (!(t = calloc(1, sizeof(struct xbee_ll_info)))) {
		ret = XBEE_ENOMEM;
		goto out;
	}
	t->head = i->head;
	if (!i->prev) {
		h->head = t;
		t->prev = NULL;
	} else {
		i->prev->next = t;
		t->prev = i->prev;
	}
	i->prev = t;
	t->next = i;
	t->item = item;
out:
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	return ret;
}

/* ################################################################ */

xbee_err _xbee_ll_get_head(void *list, void **retItem, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i;
	xbee_err ret;
	if (!list || !retItem) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	if (h->head) {
		*retItem = h->head->item;
		ret = XBEE_ENONE;
	} else {
		ret = XBEE_ERANGE;
	}
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	return ret;
}

xbee_err _xbee_ll_get_tail(void *list, void **retItem, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i;
	xbee_err ret;
	if (!list || !retItem) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	if (h->tail) {
		*retItem = h->tail->item;
		ret = XBEE_ENONE;
	} else {
		ret = XBEE_ERANGE;
	}
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	return ret;
}

/* returns struct xbee_ll_info* or NULL - don't touch the pointer if you don't know what you're doing ;) */
xbee_err __xbee_ll_get_item(void *list, void *item, struct xbee_ll_info **retItem, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i;
	if (!list) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	i = h->head;
	while (i) {
		if (i->item == item) break;
		i = i->next;
	}
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	if (retItem) *retItem = (void*)i;
	if (!i) return XBEE_ENOTEXISTS;
	return XBEE_ENONE;
}
xbee_err _xbee_ll_get_item(void *list, void *item, int needMutex) {
	return __xbee_ll_get_item(list, item, NULL, needMutex);
}

xbee_err _xbee_ll_get_next(void *list, void *ref, void **retItem, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i;
	void *ret = NULL;
	if (!list || !retItem) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (!ref) return _xbee_ll_get_head(h, retItem, needMutex);
	if (needMutex) xbee_mutex_lock(&h->mutex);
	i = h->head;
	if (__xbee_ll_get_item(h, ref, &i, 0) != XBEE_ENONE) goto out;
	if (!i) goto out;
	i = i->next;
	if (i) ret = i->item;
out:
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	*retItem = ret;
	if (!ret) return XBEE_ERANGE;
	return XBEE_ENONE;
}

xbee_err _xbee_ll_get_prev(void *list, void *ref, void **retItem, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i;
	void *ret = NULL;
	if (!list || !retItem) return XBEE_EMISSINGPARAM;
	if (!ref) return _xbee_ll_get_tail(list, retItem, needMutex);
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	i = h->head;
	if (__xbee_ll_get_item(h, ref, &i, 0) != XBEE_ENONE) goto out;
	if (!i) goto out;
	i = i->prev;
	if (i) ret = i->item;
out:
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	*retItem = ret;
	if (!ret) return XBEE_ERANGE;
	return XBEE_ENONE;
}

xbee_err _xbee_ll_get_index(void *list, unsigned int index, void **retItem, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i;
	int o;
	if (!list || !retItem) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	i = h->head;
	for (o = 0; o < index; o++) {
		i = i->next;
		if (!i) break;
	}
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	if (!i) {
		*retItem = NULL;
		return XBEE_ERANGE;
	}
	*retItem = i->item;
	return XBEE_ENONE;
}

/* ################################################################ */

xbee_err _xbee_ll_ext_head(void *list, void **retItem, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i, *p;
	void *ret;
	if (!list || !retItem) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	p = h->head;
	if (!p) {
		ret = NULL;
		goto out;
	}
	ret = p->item;
	h->head = p->next;
	if (h->head) h->head->prev = NULL;
	if (h->tail == p) h->tail = NULL;
	free(p);
out:
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	*retItem = ret;
	if (!ret) return XBEE_ERANGE;
	return XBEE_ENONE;
}

xbee_err _xbee_ll_ext_tail(void *list, void **retItem, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i, *p;
	void *ret;
	if (!list || !retItem) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	p = h->tail;
	if (!p) {
		ret = NULL;
		goto out;
	}
	ret = p->item;
	h->tail = p->prev;
	if (h->tail) h->tail->next = NULL;
	if (h->head == p) h->head = NULL;
	free(p);
out:
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	*retItem = ret;
	if (!ret) return XBEE_ERANGE;
	return XBEE_ENONE;
}

xbee_err _xbee_ll_ext_item(void *list, void *item, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i, *p;
	xbee_err ret;
	if (!list) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	p = h->head;
	ret = XBEE_ENONE;
	while (p) {
		if (p->is_head) {
			ret = XBEE_ELINKEDLIST;
			break;
		}
		if (p->item == item) {
			if (p->next) {
				p->next->prev = p->prev;
			} else {
				h->tail = p->prev;
			}
			if (p->prev) {
				p->prev->next = p->next;
			} else {
				h->head = p->next;
			}
			free(p);
			break;
		}
		p = p->next;
	}
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	if (!p) return XBEE_ENOTEXISTS;
	return ret;
}

xbee_err _xbee_ll_ext_index(void *list, unsigned int index, void **retItem, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i;
	int o;
	xbee_err ret;
	if (!list || !retItem) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	i = h->head;
	for (o = 0; o < index; o++) {
		i = i->next;
		if (!i) break;
	}
	if (!i) {
		*retItem = NULL;
		ret = XBEE_ERANGE;
		goto out;
	}
	*retItem = i->item;
	if (i->next) {
		i->next->prev = i->prev;
	} else {
		h->tail = i->prev;
	}
	if (i->prev) {
		i->prev->next = i->next;
	} else {
		h->head = i->next;
	}
	free(i);
	ret = XBEE_ENONE;
out:
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	return ret;
}

/* ################################################################ */

xbee_err _xbee_ll_modify_item(void *list, void *oldItem, void *newItem, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i, *p;
	xbee_err ret;
	if (!list) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	if ((ret = __xbee_ll_get_item(h, oldItem, &p, 0)) == XBEE_ENONE) {
		p->item = newItem;
	}
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	return ret;
}

/* ################################################################ */

xbee_err _xbee_ll_count_items(void *list, unsigned int *retCount, int needMutex) {
	struct xbee_ll_head *h;
	struct xbee_ll_info *i, *p;
	int count;
	if (!list || !retCount) return XBEE_EMISSINGPARAM;
	i = list;
	h = i->head;
	if (!(h && h->is_head && h->self == h)) return XBEE_EINVAL;
	if (needMutex) xbee_mutex_lock(&h->mutex);
	for (p = h->head, count = 0; p; p = p->next, count++);
	if (needMutex) xbee_mutex_unlock(&h->mutex);
	*retCount = count;
	return XBEE_ENONE;
}

/* ################################################################ */

xbee_err xbee_ll_combine(void *head, void *tail) {
	struct xbee_ll_head *hH, *hT;
	struct xbee_ll_info *iH, *iT;
	void *v;
	xbee_err ret;
	ret = XBEE_ENONE;
	if (!head || !tail) return XBEE_EMISSINGPARAM;
	if (head == tail) return XBEE_EINVAL;
	iH = head;
	hH = iH->head;
	if (!(hH && hH->is_head && hH->self == hH)) return XBEE_EINVAL;
	xbee_mutex_lock(&hH->mutex);
	iT = tail;
	hT = iT->head;
	if (!(hT && hT->is_head && hT->self == hT)) { ret = XBEE_EINVAL; goto out; }
	xbee_mutex_lock(&hT->mutex);
	while ((ret = _xbee_ll_ext_head(tail, &v, 0)) == XBEE_ENONE && v) {
		_xbee_ll_add_tail(head, v, 0);
	}
	xbee_mutex_unlock(&hH->mutex);
out:
	xbee_mutex_unlock(&hT->mutex);
	return XBEE_ENONE;
}
