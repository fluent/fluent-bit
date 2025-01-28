// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_SD_DEFINES_HPP
#define VSOMEIP_SD_DEFINES_HPP

#define VSOMEIP_MAX_TCP_SD_PAYLOAD               4075 // Available for entries & options
#define VSOMEIP_MAX_UDP_SD_PAYLOAD               1380

#define VSOMEIP_SOMEIP_SD_DATA_SIZE              12
#define VSOMEIP_SOMEIP_SD_ENTRY_LENGTH_SIZE      4
#define VSOMEIP_SOMEIP_SD_ENTRY_SIZE             16
#define VSOMEIP_SOMEIP_SD_IPV3_OPTION_SIZE       12
#define VSOMEIP_SOMEIP_SD_IPV6_OPTION_SIZE       24
#define VSOMEIP_SOMEIP_SD_LOAD_BALANCING_OPTION_SIZE 8
#define VSOMEIP_SOMEIP_SD_PROTECTION_OPTION_SIZE 12

#define VSOMEIP_SOMEIP_SD_OPTION_LENGTH_SIZE     4
#define VSOMEIP_SOMEIP_SD_OPTION_HEADER_SIZE     3
#define VSOMEIP_SOMEIP_SD_EMPTY_MESSAGE_SIZE     28
#define VSOMEIP_SOMEIP_SD_SPACE_FOR_PAYLOAD      VSOMEIP_MAX_UDP_MESSAGE_SIZE - VSOMEIP_SOMEIP_SD_EMPTY_MESSAGE_SIZE;



#define VSOMEIP_SD_IPV4_OPTION_LENGTH            0x0009
#define VSOMEIP_SD_IPV6_OPTION_LENGTH            0x0015

#define VSOMEIP_SD_SERVICE                       0xFFFF
#define VSOMEIP_SD_INSTANCE                      0x0000
#define VSOMEIP_SD_METHOD                        0x8100
#define VSOMEIP_SD_CLIENT                        0x0


#define VSOMEIP_SD_DEFAULT_ENABLED                  true
#define VSOMEIP_SD_DEFAULT_PROTOCOL                 "udp"
#define VSOMEIP_SD_DEFAULT_MULTICAST                "224.224.224.0"
#define VSOMEIP_SD_DEFAULT_PORT                     30490

#define VSOMEIP_SD_DEFAULT_INITIAL_DELAY_MIN        0
#define VSOMEIP_SD_DEFAULT_INITIAL_DELAY_MAX        3000
#define VSOMEIP_SD_DEFAULT_REPETITIONS_BASE_DELAY   10
#define VSOMEIP_SD_DEFAULT_REPETITIONS_MAX          3
#define VSOMEIP_SD_DEFAULT_TTL                      DEFAULT_TTL
#define VSOMEIP_SD_DEFAULT_CYCLIC_OFFER_DELAY       1000
#define VSOMEIP_SD_DEFAULT_REQUEST_RESPONSE_DELAY   2000
#define VSOMEIP_SD_DEFAULT_OFFER_DEBOUNCE_TIME      500
#define VSOMEIP_SD_DEFAULT_FIND_DEBOUNCE_TIME       500


#endif // VSOMEIP_SD_DEFINES_HPP
