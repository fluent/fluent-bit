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
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "conn.h"
#include "pkt.h"
#include "ll.h"

struct xbee_ll_head *pktList = NULL;

/* ########################################################################## */
static xbee_err _xbee_pktFree(struct xbee_pkt *pkt);
static xbee_err _xbee_pktDataKeyDestroy(struct pkt_dataKey *key);

xbee_err xbee_pktAlloc(struct xbee_pkt **nPkt, struct xbee_pkt *oPkt, int dataLen) {
	size_t memSize;
	struct xbee_pkt *pkt;
	xbee_err ret;
	
	if (!nPkt) return XBEE_EMISSINGPARAM;
	
	if (oPkt) {
		if ((ret = xbee_ll_ext_item(pktList, oPkt)) != XBEE_ENONE) {
			return ret;
		}
	}
	
	memSize = sizeof(*pkt);
	memSize += sizeof(char) * dataLen;
	
	if (!(pkt = realloc(oPkt, memSize))) return XBEE_ENOMEM;
	
	if (!oPkt) {
		memset(pkt, 0, memSize);
		pkt->dataItems = xbee_ll_alloc();
	}
	
	if ((ret = xbee_ll_add_tail(pktList, pkt)) != XBEE_ENONE) {
		_xbee_pktFree(pkt);
		ret = XBEE_ELINKEDLIST;
	} else {
		*nPkt = pkt;
	}
	
	return ret;
}

EXPORT xbee_err xbee_pktFree(struct xbee_pkt *pkt) {
	if (!pkt) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_pktValidate(pkt) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	return _xbee_pktFree(pkt);
}

static xbee_err _xbee_pktFree(struct xbee_pkt *pkt) {
	xbee_ll_ext_item(pktList, pkt);
	
	xbee_ll_free(pkt->dataItems, (void(*)(void *))_xbee_pktDataKeyDestroy);
	
	free(pkt);
	
	return XBEE_ENONE;
}

/* ########################################################################## */

EXPORT xbee_err xbee_pktValidate(struct xbee_pkt *pkt) {
	if (xbee_ll_get_item(pktList, pkt) != XBEE_ENONE) return XBEE_EINVAL;
	return XBEE_ENONE;
}

/* ########################################################################## */

xbee_err xbee_pktLink(struct xbee_con *con, struct xbee_pkt *pkt) {
	xbee_err ret;
	if (!con || !pkt) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_conValidate(con) != XBEE_ENONE) return XBEE_EINVAL;
	if (xbee_pktValidate(pkt) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	if (xbee_ll_get_item(con->pktList, pkt) == XBEE_ENONE) return XBEE_EEXISTS;
	if ((ret = xbee_ll_add_tail(con->pktList, pkt)) == XBEE_ENONE) {
		pkt->xbee = con->xbee;
		pkt->con = con;
	}
	return ret;
}

xbee_err _xbee_pktUnlink(struct xbee_con *con, struct xbee_pkt *pkt, int needsLLLock) {
	xbee_err ret;
	if (!con || !pkt) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_conValidate(con) != XBEE_ENONE) return XBEE_EINVAL;
	if (xbee_pktValidate(pkt) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	if ((ret = _xbee_ll_ext_item(con->pktList, pkt, needsLLLock)) == XBEE_ENONE) {
		pkt->xbee = NULL;
		pkt->con = NULL;
	}
	return ret;
}
xbee_err xbee_pktUnlink(struct xbee_con *con, struct xbee_pkt *pkt) {
	return _xbee_pktUnlink(con, pkt, 1);
}

/* ########################################################################## */

xbee_err xbee_pktDataKeyAdd(struct xbee_pkt *pkt, const char *key, int id, struct pkt_dataKey **retKey, void (*freeCallback)(void*)) {
	struct pkt_dataKey *k;
	xbee_err ret;
	
	if (!pkt || !key) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_pktValidate(pkt) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	
	if (xbee_pktDataKeyGet(pkt, key, id, &k) == XBEE_ENONE) {
		if (retKey) *retKey = k;
		return XBEE_EEXISTS;
	}
	
	if ((k = calloc(1, sizeof(*k))) == NULL) {
		return XBEE_ENOMEM;
	}
	
	ret = XBEE_ENONE;
	snprintf(k->name, PKT_DATAKEY_MAXLEN, "%s", key);
	k->id = id;
	k->freeCallback = freeCallback;
	if ((k->items = xbee_ll_alloc()) == NULL) {
		ret = XBEE_ENOMEM;
		goto die1;
	}
	
	if (xbee_ll_add_tail(pkt->dataItems, k) != XBEE_ENONE) {
		ret = XBEE_ELINKEDLIST;
		goto die2;
	}
	
	if (retKey) *retKey = k;
	
	goto done;
die2:
	xbee_ll_free(k->items, NULL);
die1:
	free(k);
done:
	return ret;
}

xbee_err xbee_pktDataKeyGet(struct xbee_pkt *pkt, const char *key, int id, struct pkt_dataKey **retKey) {
	xbee_err ret;
	struct pkt_dataKey *k;
	
	if (!pkt || !key) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_pktValidate(pkt) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	
	xbee_ll_lock(pkt->dataItems);
	ret = XBEE_ENOTEXISTS;
	for (k = NULL; (_xbee_ll_get_next(pkt->dataItems, k, (void**)&k, 0) == XBEE_ENONE) && k; ) {
		if (!strncasecmp(key, k->name, PKT_DATAKEY_MAXLEN)) {
			if (id == -1 || id == k->id) {
				if (retKey) *retKey = k;
				ret = XBEE_ENONE;
				break;
			}
		}
	}
	xbee_ll_unlock(pkt->dataItems);
	
	return ret;
}

static xbee_err _xbee_pktDataKeyDestroy(struct pkt_dataKey *key) {
	xbee_ll_free(key->items, key->freeCallback);
	free(key);
	return XBEE_ENONE;
}

/* ########################################################################## */

xbee_err xbee_pktDataAdd(struct xbee_pkt *pkt, const char *key, int id, void *data, void (*freeCallback)(void*)) {
	struct pkt_dataKey *k;
	xbee_err ret;
	
	if (!pkt || !key || !data) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_pktValidate(pkt) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	
	if ((ret = xbee_pktDataKeyAdd(pkt, key, id, &k, freeCallback)) != XBEE_ENONE && ret != XBEE_EEXISTS) {
		return XBEE_EFAILED;
	}
	
	if (xbee_ll_add_tail(k->items, data)) {
		return XBEE_ELINKEDLIST;
	}
	
	return XBEE_ENONE;
}

EXPORT xbee_err xbee_pktDataGet(struct xbee_pkt *pkt, const char *key, int id, int index, void **retData) {
	struct pkt_dataKey *k;
	unsigned int count;
	xbee_err ret;
	
	if (!pkt || !key || !retData) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_pktValidate(pkt) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	
	if ((ret = xbee_pktDataKeyGet(pkt, key, id, &k)) != XBEE_ENONE) return ret;
	
	if (xbee_ll_count_items(k->items, &count) != XBEE_ENONE) return XBEE_ELINKEDLIST;
	if (index >= count) return XBEE_ERANGE;
	
	*retData = NULL;
	if ((ret = xbee_ll_get_index(k->items, index, retData)) == XBEE_ERANGE) return ret;
	if (ret != XBEE_ENONE) return XBEE_EINVAL;
	
	return XBEE_ENONE;
}

/* ########################################################################## */

xbee_err xbee_pktAnalogAdd(struct xbee_pkt *pkt, int channel, long value) {
	if (!pkt) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_pktValidate(pkt) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	
	value += 1;
	return xbee_pktDataAdd(pkt, "analog", channel, (void*)value, NULL);
}

EXPORT xbee_err xbee_pktAnalogGet(struct xbee_pkt *pkt, int channel, int index, int *retVal) {
	int value;
	xbee_err ret;
	
	if (!pkt || !retVal) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_pktValidate(pkt) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	
	if ((ret = xbee_pktDataGet(pkt, "analog", channel, index, (void*)&value)) != XBEE_ENONE) return ret;
	value -= 1;
	*retVal = value;
	
	return XBEE_ENONE;
}

/* ########################################################################## */

xbee_err xbee_pktDigitalAdd(struct xbee_pkt *pkt, int channel, long value) {
	if (!pkt) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_pktValidate(pkt) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	
	value = !!value;
	value += 1;
	return xbee_pktDataAdd(pkt, "digital", channel, (void*)value, NULL);
}

EXPORT xbee_err xbee_pktDigitalGet(struct xbee_pkt *pkt, int channel, int index, int *retVal) {
	int value;
	xbee_err ret;
	
	if (!pkt || !retVal) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_pktValidate(pkt) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	
	if ((ret = xbee_pktDataGet(pkt, "digital", channel, index, (void*)&value)) != XBEE_ENONE) return ret;
	value -= 1;
	value = !!value;
	*retVal = value;
	
	return XBEE_ENONE;
}
