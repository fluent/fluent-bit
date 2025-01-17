// Copyright (C) 2020-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifdef __QNX__
#ifndef VSOMEIP_V3_QNX_HELPER_HPP_
#define VSOMEIP_V3_QNX_HELPER_HPP_
#include <sys/socket.h>
#include <netinet/in.h>

 #define SO_BINDTODEVICE 0x0800		/* restrict traffic to an interface */
 #define IP_PKTINFO		25   /* int; send interface and src addr */

/* Structure used for IP_PKTINFO.  */
#ifndef	_STRUCT_IN_PKTINFO
struct in_pktinfo
  {
    int ipi_ifindex;			/* Interface index  */
    struct in_addr ipi_spec_dst;	/* Routing destination address  */
    struct in_addr ipi_addr;		/* Header destination address  */
  };
#define	_STRUCT_IN_PKTINFO
#endif

 #endif // VSOMEIP_V3_QNX_HELPER_HPP_

#endif
