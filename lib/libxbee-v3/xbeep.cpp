/*
	libxbee - a C library to aid the use of Digi's XBee wireless modules
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

#include <stdlib.h>
#include <stdarg.h>
#include <iostream>

#ifdef LIBXBEE_BUILD
#include "xsys.h"
#else
#define EXPORT
#endif

#include "xbee.h"
#include "xbeep.h"

/* ========================================================================== */

EXPORT std::list<libxbee::XBee*> libxbee::xbeeList;

EXPORT std::list<std::string> libxbee::getModes(void) {
	xbee_err ret;
	char **modes;
	int i;
	std::list<std::string> modeList;
	
	if ((ret = xbee_modeGetList(&modes)) != XBEE_ENONE) throw(ret);
	for (i = 0; modes[i] != NULL; i++) {
		modeList.push_back(std::string(modes[i]));
	}
	free(modes);
	
	return modeList;
}

/* ========================================================================== */

EXPORT libxbee::XBee::XBee(std::string mode) {
	xbee_err ret;
	
	if ((ret = xbee_setup(&xbee, mode.c_str())) != XBEE_ENONE) throw(ret);
	
	xbeeList.push_back(this);
}
EXPORT libxbee::XBee::XBee(std::string mode, std::string device, int baudrate) {
	xbee_err ret;
	
	if ((ret = xbee_setup(&xbee, mode.c_str(), device.c_str(), baudrate)) != XBEE_ENONE) throw(ret);
	
	xbeeList.push_back(this);
}
EXPORT libxbee::XBee::XBee(std::string mode, va_list ap) {
	xbee_err ret;
	
	if ((ret = xbee_vsetup(&xbee, mode.c_str(), ap)) != XBEE_ENONE) throw(ret);
	
	xbeeList.push_back(this);
}

EXPORT libxbee::XBee::~XBee(void) {
	std::list<Con*>::iterator con;

	for (con = conList.begin(); con != conList.end(); con++) {
		(*con)->xbee = NULL;
		xbee_conEnd((*con)->con);
		(*con)->con = NULL;
	}

	xbee_shutdown(xbee);
	xbeeList.remove(this);
}

EXPORT struct xbee *libxbee::XBee::getHnd(void) {
	return xbee;
}
EXPORT void libxbee::XBee::conRegister(Con *con) {
	xbee_err ret;
	if ((ret = xbee_conValidate(con->getHnd())) != XBEE_ENONE) throw(ret);
	conList.push_back(con);
	conList.unique();
}
EXPORT void libxbee::XBee::conUnregister(Con *con) {
	conList.remove(con);
}
EXPORT libxbee::Con *libxbee::XBee::conLocate(struct xbee_con *con) {
	std::list<Con*>::iterator i;
	for (i = conList.begin(); i != conList.end(); i++) {
		if ((*i)->getHnd() == con) return (*i);
	}
	return NULL;
}

EXPORT std::list<std::string> libxbee::XBee::getConTypes(void) {
	xbee_err ret;
	char **types;
	int i;
	std::list<std::string> typeList;
	
	if ((ret = xbee_conGetTypes(xbee, &types)) != XBEE_ENONE) throw(ret);
	for (i = 0; types[i] != NULL; i++) {
		typeList.push_back(std::string(types[i]));
	}
	free(types);
	
	return typeList;
}

EXPORT std::string libxbee::XBee::mode(void) {
	xbee_err ret;
	const char *mode;
	
	if ((ret = xbee_modeGet(getHnd(), &mode)) != XBEE_ENONE) throw(ret);
	
	return std::string(mode);
}

EXPORT void libxbee::XBee::setLogTarget(FILE *f) {
	xbee_err ret;
	
	if ((ret = xbee_logTargetSet(xbee, f)) != XBEE_ENONE) throw(ret);
}
EXPORT void libxbee::XBee::setLogLevel(int level) {
	xbee_err ret;
	
	if ((ret = xbee_logLevelSet(xbee, level)) != XBEE_ENONE) throw(ret);
}
EXPORT int libxbee::XBee::getLogLevel(void) {
	xbee_err ret;
	int level;
	
	if ((ret = xbee_logLevelGet(xbee, &level)) != XBEE_ENONE) throw(ret);
	
	return level;
}

/* ========================================================================== */

EXPORT libxbee::Con::Con(XBee &parent, std::string type, struct xbee_conAddress *address) : parent(parent) {
	xbee_err ret;
	
	if ((xbee = parent.getHnd()) == NULL) throw(XBEE_EINVAL);
	
	if ((ret = xbee_conNew(xbee, &con, type.c_str(), address)) != XBEE_ENONE) throw(ret);
	if ((ret = xbee_conDataSet(con, (void*)this, NULL)) != XBEE_ENONE) {
		xbee_conEnd(con);
		throw(ret);
	}
	try {
		parent.conRegister(this);
	} catch (xbee_err ret) {
		xbee_conEnd(con);
		throw(ret);
	}
}
EXPORT libxbee::Con::~Con(void) {
	if (xbee != NULL) parent.conUnregister(this);
	if (con != NULL) xbee_conEnd(con);
}

EXPORT void libxbee::Con::xbee_conCallback(Pkt **pkt) { }

EXPORT unsigned char libxbee::Con::operator<< (std::string data) {
	return Tx(data);
}
EXPORT unsigned char libxbee::Con::operator<< (std::vector<unsigned char> data) {
	return Tx(data);
}
EXPORT unsigned char libxbee::Con::operator<< (std::vector<char> data) {
	return Tx(data);
}
EXPORT void libxbee::Con::operator>> (Pkt &pkt) {
	return Rx(pkt);
}
EXPORT void libxbee::Con::operator>> (std::string &data) {
	libxbee::Pkt p;
	p << *this;
	p >> data;
}
EXPORT void libxbee::Con::operator>> (std::vector<unsigned char> &data) {
	libxbee::Pkt p;
	p << *this;
	p >> data;
}
EXPORT void libxbee::Con::operator>> (std::vector<char> &data) {
	libxbee::Pkt p;
	p << *this;
	p >> data;
}

EXPORT struct xbee_con *libxbee::Con::getHnd(void) {
	if (con == NULL) throw(XBEE_ESHUTDOWN);
	return con;
}

EXPORT unsigned char libxbee::Con::Tx(std::string data) {
	return Tx((unsigned char *)NULL, (const unsigned char *)data.c_str(), data.size());
}
EXPORT unsigned char libxbee::Con::Tx(std::vector<unsigned char> data) {
	return Tx((unsigned char *)NULL, &(data[0]), data.size());
}
EXPORT unsigned char libxbee::Con::Tx(std::vector<char> data) {
	return Tx((unsigned char *)NULL, (unsigned char *)&(data[0]), data.size());
}
EXPORT unsigned char libxbee::Con::Tx(const unsigned char *buf, int len) {
	return Tx((unsigned char *)NULL, buf, len);
}
EXPORT unsigned char libxbee::Con::Tx(unsigned char *frameId, std::string data) {
	return Tx(frameId, (const unsigned char *)data.c_str(), data.size());
}
EXPORT unsigned char libxbee::Con::Tx(unsigned char *frameId, std::vector<unsigned char> data) {
	return Tx(frameId, &(data[0]), data.size());
}
EXPORT unsigned char libxbee::Con::Tx(unsigned char *frameId, std::vector<char> data) {
	return Tx(frameId, (unsigned char *)&(data[0]), data.size());
}
EXPORT unsigned char libxbee::Con::Tx(unsigned char *frameId, const unsigned char *buf, int len) {
	unsigned char retVal;
	xbee_err ret;
	
	if (con == NULL) throw(XBEE_ESHUTDOWN);
	if ((ret = xbee_connxTx(con, &retVal, frameId, buf, len)) == XBEE_ENONE) return retVal;

	if (ret == XBEE_ETX) throw(libxbee::xbee_etx(ret, retVal));
	throw(ret);
}

EXPORT void libxbee::Con::Rx(Pkt &pkt, int *remainingPackets) {
	struct xbee_pkt *raw_pkt;
	xbee_err ret;
	
	if (con == NULL) throw(XBEE_ESHUTDOWN);
	if ((ret = xbee_conRx(con, &raw_pkt, remainingPackets)) != XBEE_ENONE) throw(ret);
	
	pkt.setHnd(raw_pkt);
}
EXPORT int libxbee::Con::RxAvailable(void) {
	int remainingPackets;
	xbee_err ret;

	if (con == NULL) throw(XBEE_ESHUTDOWN);
	if ((ret = xbee_conRx(con, NULL, &remainingPackets)) != XBEE_ENONE) throw(ret);

	return remainingPackets;
}

EXPORT void libxbee::Con::purge(void) {
	xbee_err ret;
	
	if (con == NULL) throw(XBEE_ESHUTDOWN);
	if ((ret = xbee_conPurge(con)) != XBEE_ENONE) throw(ret);
}

EXPORT void libxbee::Con::sleep(void) {
	setSleep(CON_SLEEP);
}
EXPORT void libxbee::Con::snooze(void) {
	setSleep(CON_SNOOZE);
	std::cout << "Sent for snooze\n";
}
EXPORT void libxbee::Con::wake(void) {
	setSleep(CON_AWAKE);
}
EXPORT void libxbee::Con::setSleep(enum xbee_conSleepStates state) {
	xbee_err ret;
	
	if (con == NULL) throw(XBEE_ESHUTDOWN);
	if ((ret = xbee_conSleepSet(con, state)) != XBEE_ENONE) throw(ret);
}
EXPORT enum xbee_conSleepStates libxbee::Con::getSleep(void) {
	xbee_err ret;
	enum xbee_conSleepStates state;
	
	if (con == NULL) throw(XBEE_ESHUTDOWN);
	if ((ret = xbee_conSleepGet(con, &state)) != XBEE_ENONE) throw(ret);
	
	return state;
}

EXPORT void libxbee::Con::getSettings(struct xbee_conSettings *settings) {
	xbee_err ret;
	if (settings == NULL) throw(XBEE_EINVAL);
	
	if (con == NULL) throw(XBEE_ESHUTDOWN);
	if ((ret = xbee_conSettings(con, NULL, settings)) != XBEE_ENONE) throw(ret);
}
EXPORT void libxbee::Con::setSettings(struct xbee_conSettings *settings) {
	xbee_err ret;
	if (settings == NULL) throw(XBEE_EINVAL);
	
	if (con == NULL) throw(XBEE_ESHUTDOWN);
	if ((ret = xbee_conSettings(con, settings, NULL)) != XBEE_ENONE) throw(ret);
}


/* ========================================================================== */

EXPORT libxbee::ConCallback::ConCallback(XBee &parent, std::string type, struct xbee_conAddress *address) : Con(parent, type, address), parent(parent) {
	xbee_err ret;

	if (con == NULL) throw(XBEE_ESHUTDOWN);
	if ((ret = xbee_conCallbackSet(con, ConCallback::libxbee_callbackFunction, NULL)) != XBEE_ENONE) throw(ret);
}

void libxbee::ConCallback::libxbee_callbackFunction(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	Con *c = (libxbee::Con*)*data;
	if (c->parent.getHnd() != xbee) {
		std::cerr << " -1#[" << __FILE__ << ":" << __LINE__ << "] " << __FUNCTION__ << "(): A connection called back to the C++ interface, but it didn't provide suitable information...\n";
		return;
	}

	Pkt *p = new Pkt(*pkt);
	*pkt = NULL; /* we'll either delete its container right after the callback, or it becomes the user's responsibility */

	c->xbee_conCallback(&p);

	if (p != NULL) {
		delete p;
	}
}

/* ========================================================================== */

EXPORT libxbee::Pkt::Pkt(struct xbee_pkt *pkt) {
	this->pkt = pkt;
}
EXPORT libxbee::Pkt::~Pkt(void) {
	if (pkt != NULL) xbee_pktFree(pkt);
}

EXPORT unsigned char libxbee::Pkt::operator[] (int index) {
	if (pkt == NULL) throw(XBEE_EINVAL);
	if (index > size()) throw(XBEE_ERANGE);
	return pkt->data[index];
}
EXPORT void libxbee::Pkt::operator<< (Con &con) {
	con.Rx(*this);
}
EXPORT void libxbee::Pkt::operator>> (std::string &data) {
	data = getData();
}
EXPORT void libxbee::Pkt::operator>> (std::vector<unsigned char> &data) {
	data = getVector();
}
EXPORT void libxbee::Pkt::operator>> (std::vector<char> &data) {
	data = getVector2();
}

EXPORT int libxbee::Pkt::size(void) {
	if (pkt == NULL) throw(XBEE_EINVAL);
	return pkt->dataLen;
}

EXPORT struct xbee_pkt *libxbee::Pkt::getHnd(void) {
	return pkt;
}
EXPORT void libxbee::Pkt::setHnd(struct xbee_pkt *pkt) {
	if (this->pkt) xbee_pktFree(this->pkt);
	this->pkt = pkt;
}
EXPORT struct xbee_pkt *libxbee::Pkt::dropHnd(void) {
	struct xbee_pkt *t;
	t = this->pkt;
	this->pkt = NULL;
	return t;
}

EXPORT std::string libxbee::Pkt::getData(void) {
	return std::string((char*)pkt->data, pkt->dataLen);
}
EXPORT std::vector<unsigned char> libxbee::Pkt::getVector(void) {
	std::vector<unsigned char> data;
	for (int i = 0; i < pkt->dataLen; i++) {
		data.push_back(pkt->data[i]);
	}
	return data;
}
EXPORT std::vector<char> libxbee::Pkt::getVector2(void) {
	std::vector<char> data;
	for (int i = 0; i < pkt->dataLen; i++) {
		data.push_back((char)pkt->data[i]);
	}
	return data;
}
EXPORT void *libxbee::Pkt::getData(const char *key) {
	return getData(key, 0, 0);
}
EXPORT void *libxbee::Pkt::getData(const char *key, int id) {
	return getData(key, id, 0);
}
EXPORT void *libxbee::Pkt::getData(const char *key, int id, int index) {
	xbee_err ret;
	void *p;
	
	if ((ret = xbee_pktDataGet(pkt, key, id, index, &p)) != XBEE_ENONE) throw(ret);
	return p;
}

EXPORT std::string libxbee::Pkt::getATCommand(void) {
	std::string type(pkt->conType);
	if (type != "Local AT" && type != "Remote AT") throw(XBEE_EINVAL);
	return std::string((char*)pkt->atCommand, 2);
}

EXPORT int libxbee::Pkt::getAnalog(int channel) {
	return getAnalog(channel, 0);
}
EXPORT int libxbee::Pkt::getAnalog(int channel, int index) {
	xbee_err ret;
	int value;
	
	if ((ret = xbee_pktAnalogGet(pkt, channel, index, &value)) != XBEE_ENONE) throw(ret);
	return value;
}

EXPORT bool libxbee::Pkt::getDigital(int channel) {
	return getDigital(channel, 0);
}
EXPORT bool libxbee::Pkt::getDigital(int channel, int index) {
	xbee_err ret;
	int value;
	
	if ((ret = xbee_pktDigitalGet(pkt, channel, index, &value)) != XBEE_ENONE) throw(ret);
	return (bool)!!value;
}
