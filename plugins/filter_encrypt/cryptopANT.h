/* -*-  Mode:C; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (C) 2004-2018 by the University of Southern California
 * $Id: 58a4704e7a2580bed5f7eac76cd23b809dd558fa $
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 */


#ifndef _SCRAMBLE_CRYPT_H
#define _SCRAMBLE_CRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#define ETHER_ADDR_LEN		6
#define ETHER_VLAN_LEN		2

#define _XOR16(a, b, i)         (((uint16_t *)(a))[i] ^= ((uint16_t *)(b))[i])
#define _XOR32(a, b, i)         (((uint32_t *)(a))[i] ^= ((uint32_t *)(b))[i])

#define SCRAMBLE_ETHER_ADDR(a)  if (1) {     \
        _XOR32(a, scramble_ether_addr, 0);              \
        _XOR16(a, scramble_ether_addr, 2);              \
    }

#define SCRAMBLE_ETHER_VLAN(v)	((v) ^= scramble_ether_vlan);

#define SCRAMBLE_RANDOM_DEV	"/dev/urandom" 

typedef enum {
	SCRAMBLE_NONE		= 0x00,
	SCRAMBLE_MD5 		= 0x01,
	SCRAMBLE_BLOWFISH 	= 0x02,
	SCRAMBLE_AES 		= 0x03,
	SCRAMBLE_SHA1		= 0x04,
	SCRAMBLE_HMAC_SHA256= 0x05
} scramble_crypt_t;

typedef struct {
	scramble_crypt_t	c4;
	scramble_crypt_t	c6;
	u_char			*key;
	int			klen;
	u_char			*pad;
	int			plen;
	u_char			*mac;
	int			mlen;
	u_char			*iv;
	int			ivlen;	
} scramble_state_t;

/* external vars exported by mac scrambling macros */
extern uint8_t			scramble_ether_addr[ETHER_ADDR_LEN];
extern uint16_t			scramble_ether_vlan;
extern int		    	scramble_mac;		/* 0/1 */

/* public functions */
extern scramble_crypt_t scramble_crypto_ip4	(void);
extern scramble_crypt_t scramble_crypto_ip6	(void);
extern scramble_crypt_t	scramble_name2type	(const char *);
extern const char*	scramble_type2name	(scramble_crypt_t);
extern int		scramble_newkey		(u_char *, int);
extern int		scramble_newpad		(u_char *, int);
extern int		scramble_newmac		(u_char *, int);
extern int		scramble_readstate	(const char *, scramble_state_t *);
extern int		scramble_savestate	(const char *, const scramble_state_t *);
extern int		scramble_init		(const scramble_state_t *s);
extern int		scramble_init_from_file	(const char *, scramble_crypt_t, scramble_crypt_t, int *);
extern void     set_encrypt_key     (const char *ckey);
extern uint32_t 	scramble_ip4		(uint32_t, int);
extern uint32_t 	unscramble_ip4		(uint32_t, int);
extern struct in6_addr   scramble_ip6		(struct in6_addr *, int);
extern struct in6_addr	 unscramble_ip6		(struct in6_addr *, int);
void   ipv6_to_str_unexpanded               (char *str, const struct in6_addr *addr);

#ifdef __cplusplus
}
#endif

#endif /* _SCRAMBLE_CRYPT_H */
