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
#include <string.h>

#include "internal.h"
#include "xbee_int.h"
#include "mode.h"
#include "conn.h"
#include "ll.h"

const struct xbee_mode * const modeList[] = { MODELIST };

/* ######################################################################### */

xbee_err xbee_modeRetrieve(const char *name, const struct xbee_mode **retMode) {
	const struct xbee_mode *mode;
	int i;
	if (!name || !retMode) return XBEE_EMISSINGPARAM;
	
	for (i = 0; modeList[i]; i++) {
		if (!modeList[i]->name) continue;
		if (strcasecmp(modeList[i]->name, name)) continue;
		mode = modeList[i];
		
		/* check compulsory functionality */
		if (!mode->init) return XBEE_EINVAL;
		if (!mode->rx_io) return XBEE_EINVAL;
		if (!mode->tx_io) return XBEE_EINVAL;
		
		*retMode = mode;
		return XBEE_ENONE;
	}
	
	return XBEE_EFAILED;
}

/* ######################################################################### */

/* pull the given mode information into the given xbee instance */
xbee_err xbee_modeImport(struct xbee_modeConType **retConTypes, const struct xbee_mode *mode) {
	int i, n;
	struct xbee_modeConType *conTypes;
	
	if (!retConTypes || !mode) return XBEE_EMISSINGPARAM;
	if (*retConTypes) return XBEE_EINVAL;
	
	for (n = 0; mode->conTypes && mode->conTypes[n] && mode->conTypes[n]->name; n++);
	
	if ((conTypes = malloc(sizeof(*conTypes) * (n + 1))) == NULL) return XBEE_ENOMEM;
	memset(&conTypes[n], 0, sizeof(*conTypes));
	
	for (i = 0; i < n; i++) {
		/* keep the pointers (they are const after all) */
		memcpy(&conTypes[i], mode->conTypes[i], sizeof(*conTypes));
		
		/* setup the addressCmp function */
		if (conTypes[i].addressCmp == NULL) conTypes[i].addressCmp = xbee_conAddressCmpDefault;
		/* initialization added for microsoft compiler support */
		if (conTypes[i].init) conTypes[i].init(&(conTypes[i]));
		
		conTypes[i].conList = xbee_ll_alloc();
	}
	
	*retConTypes = conTypes;
	
	return XBEE_ENONE;
}

/* ######################################################################### */

static void prepare_repopConTypes(struct xbee_modeConType *conTypes) {
	struct xbee_modeConType *conType;
	struct xbee_con *con;
	int i;
	
	for (i = 0; conTypes[i].name; i++) {
		conType = &conTypes[i];
		for (con = NULL; xbee_ll_get_next(conType->conList, con, (void**)&con) == XBEE_ENONE && con; ) {
			con->conType = conType;
		}
	}
}

xbee_err xbee_modeAddConType(struct xbee_modeConType **extConTypes, const struct xbee_modeConType *newConType) {
	int n;
	struct xbee_modeConType *conTypes;
	
	if (!extConTypes || !newConType) return XBEE_EMISSINGPARAM;
	if (!*extConTypes) return XBEE_EINVAL;
	if (!newConType->name) return XBEE_EINVAL;
	if (!newConType->rxHandler && !newConType->txHandler) return XBEE_EINVAL;
	
	for (n = 0; (*extConTypes)[n].name; n++);
	
	if ((conTypes = realloc(*extConTypes, sizeof(*conTypes) * (n + 2))) == NULL) return XBEE_ENOMEM;
	*extConTypes = conTypes;
	prepare_repopConTypes(conTypes);
	
	memset(&conTypes[n + 1], 0, sizeof(*conTypes));
	memcpy(&conTypes[n], newConType, sizeof(*newConType));
	conTypes[n].conList = xbee_ll_alloc();
	/* setup the addressCmp function */
	if (conTypes[n].addressCmp == NULL) conTypes[n].addressCmp = xbee_conAddressCmpDefault;
	
	return XBEE_ENONE;
}

/* ######################################################################### */

xbee_err xbee_modeCleanup(struct xbee_modeConType *conTypes) {
	int i;
	if (!conTypes) return XBEE_EMISSINGPARAM;
	
	for (i = 0; conTypes[i].name; i++) {
		xbee_ll_free(conTypes[i].conList, (void(*)(void*))xbee_conFree);
		/* i know, casting to void* to avoid the const keyword is naughty... */
		if (conTypes[i].nameNeedsFree) free((void*)conTypes[i].name);
		if (conTypes[i].rxHandler && conTypes[i].rxHandler->needsFree) free((void*)conTypes[i].rxHandler);
		if (conTypes[i].txHandler && conTypes[i].txHandler->needsFree) free((void*)conTypes[i].txHandler);
	}
	
	free(conTypes);
	return XBEE_ENONE;
}

/* ######################################################################### */

xbee_err xbee_modeLocateConType(struct xbee_modeConType *conTypes, int allowInternal, const char *name, const unsigned char *rxId, const unsigned char *txId, struct xbee_modeConType **retType) {
	int i;
	
	if (!retType) return XBEE_EMISSINGPARAM;
	if (!name && !rxId && !txId) return XBEE_EMISSINGPARAM;
	
	for (i = 0; conTypes[i].name; i++) {
		if (name) {
			if (strcasecmp(conTypes[i].name, name)) continue;
		}
		if (rxId) {
			if (!conTypes[i].rxHandler) continue;
			if (!conTypes[i].rxHandler->func) continue;
			if (conTypes[i].rxHandler->identifier != *rxId) continue;
		}
		if (txId) {
			if (!conTypes[i].txHandler) continue;
			if (!conTypes[i].txHandler->func) continue;
			if (conTypes[i].txHandler->identifier != *txId) continue;
		}
		if (!allowInternal && conTypes[i].internal) return XBEE_EINVAL;
		
		*retType = &conTypes[i];
		return XBEE_ENONE;
	}
	
	return XBEE_ENOTEXISTS;
}

/* ######################################################################### */

EXPORT xbee_err xbee_modeGetList(char ***retList) {
	int i, o;
	size_t memSize;
	char **mList;
	char *mName;
	if (!retList) return XBEE_EMISSINGPARAM;
	
	memSize = 0;
	for (i = 0, o = 0; modeList[i]; i++) {
		if (!modeList[i]->name) continue;
		memSize += sizeof(char *);
		memSize += sizeof(char) * (strlen(modeList[i]->name) + 1);
		o++;
	}
	memSize += sizeof(char *);
	
	if ((mList = malloc(memSize)) == NULL) {
		return XBEE_ENOMEM;
	}
	
	mName = (char *)&(mList[o+1]);
	for (i = 0, o = 0; modeList[i]; i++) {
		if (!modeList[i]->name) continue;
		mList[o] = mName;
		strcpy(mName, modeList[i]->name);
		mName += strlen(mName) + 1;
		o++;
	}
	mList[o] = NULL;
	
	*retList = mList;
	
	return XBEE_ENONE;
}

EXPORT xbee_err xbee_modeGet(struct xbee *xbee, const char **mode) {
	if (!xbee || !mode) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_validate(xbee) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	*mode = xbee->mode->name;
	return XBEE_ENONE;
}
