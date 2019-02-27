/*
 * Copyright © 2006, DoCoMo Communications Laboratories USA, Inc.,
 *   the DoCoMo SEND Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of DoCoMo Communications Laboratories USA, Inc., its
 *    parents, affiliates, subsidiaries, theDoCoMo SEND Project nor the names
 *    of the Project's contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL DOCOMO COMMUNICATIONS LABORATORIES USA,
 *  INC., ITS PARENTS, AFFILIATES, SUBSIDIARIES, THE PROJECT OR THE PROJECT'S
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
 */

#ifndef	_SND_PROTO_H
#define	_SND_PROTO_H

#include <stdint.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include "os/os_defines.h"

#define	ND_OPT_CGA		11
#define	ND_OPT_SIG		12
#define	ND_OPT_TIMESTAMP	13
#define	ND_OPT_NONCE		14
#define	ND_OPT_TRUST_ANCHOR	15
#define	ND_OPT_CERTIFICATE	16

#define	ND_OPT_MAX		ND_OPT_CERTIFICATE

#define NDISC_OPT_SPACE(len) (((len)+2+7)&~7)

#define ND_ROUTER_SOLICIT	133
#define ND_ROUTER_ADVERT	134
#define ND_NEIGHBOR_SOLICIT	135
#define ND_NEIGHBOR_ADVERT	136
#define ND_REDIRECT		137

#define	ICMP6_SND_CPS		148
#define	ICMP6_SND_CPA		149

#define	TRUST_ANCHOR_DN		1
#define	TRUST_ANCHOR_FQDN	2

#define	SND_NONCE_LEN		6
#define	SND_KEYHASH_LEN		16
#define	SND_ALL_COMPONENTS	0xffff

#define	SEND_MSG_TYPE_TAG { \
	0x08, 0x6f, 0xca, 0x5e, 0x10, 0xb2, 0x00, 0xc9, \
	0x9c, 0x8c, 0xe0, 0x01, 0x64, 0x27, 0x7c, 0x08 }

#define	SND_TIMESTAMP_DELTA		300	/* seconds */

struct snd_opt_sig {
	uint32_t		reserved;	/* opt hdr + reserved */
	uint8_t			keyhash[SND_KEYHASH_LEN];
	uint8_t			sig[0];
};

struct snd_opt_timestamp {
	uint8_t			type;
	uint8_t			len;
	uint16_t		reserved1;
	uint32_t		reserved2;
	uint64_t		ts;
};

struct snd_opt_trustanchor {
	uint8_t			type;
	uint8_t			len;
	uint8_t			nametype;
	uint8_t			padlen;
};

struct snd_opt_cert {
	uint8_t			type;
	uint8_t			len;
	uint8_t			cert_type;
	uint8_t			reserved;
};

struct snd_cps {
	uint8_t			type;
	uint8_t			code;
	uint16_t		cksum;
	uint16_t		id;
	uint16_t		component;
};

struct snd_cpa {
	uint8_t			type;
	uint8_t			code;
	uint16_t		cksum;
	uint16_t 		id;
	uint16_t		cnt;
	uint16_t		component;
	uint16_t		rsvd;
};

struct ndopts {
	uint8_t			*opt[ND_OPT_MAX + 1];
};

extern void snd_proto_nonce_fini(void);
extern int snd_proto_nonce_init(void);
extern void snd_proto_timestamp_fini(void);
extern int snd_proto_timestamp_init(void);

extern void snd_del_solicit_ent(struct in6_addr *, int);
extern int snd_proto_check_solicit_nonce(struct in6_addr *, int, uint8_t *);
extern int snd_check_timestamp(struct in6_addr *, int, uint8_t *,
    uint64_t *, uint64_t *, int);
extern int snd_proto_add_advert_nonce(struct sbuff *, struct in6_addr *,
    struct in6_addr *, int);
extern int snd_proto_add_solicit_nonce(struct sbuff *, struct in6_addr *, int);
extern int snd_proto_cache_nonce(struct in6_addr *, struct in6_addr *, int,
    uint8_t *);
extern int snd_proto_verify_sig(uint8_t *, uint8_t *, int,
    struct ip6_hdr *, struct icmp6_hdr *, int);
extern uint8_t *snd_proto_calc_sig(struct ip6_hdr *, struct icmp6_hdr *, int,
    int *, struct snd_cga_params *);
extern int snd_timestamp_cache_upd(struct in6_addr *, int, uint64_t, uint64_t);
extern uint64_t snd_timestamp_get_delta(void);
extern uint64_t snd_timestamp_get_fuzz(void);

extern uint8_t *snd_get_opt(uint8_t *, int, int);
extern int snd_parse_opts(struct ndopts *, uint8_t *, int);

static __inline__ void
ipv6_addr_set(struct in6_addr *addr,  uint32_t w1, uint32_t w2,
    uint32_t w3, uint32_t w4)
{
	addr->s6_addr32[0] = w1;
	addr->s6_addr32[1] = w2;
	addr->s6_addr32[2] = w3;
	addr->s6_addr32[3] = w4;
}

#endif	/* _SND_PROTO_H */
