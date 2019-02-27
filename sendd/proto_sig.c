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

#include <string.h>
#include <sys/types.h>
#include <openssl/sha.h>

#include "config.h"
#include <applog.h>

#include "sendd_local.h"
#include "snd_proto.h"
#include "dbg.h"

static uint8_t send_msg_type_tag[] = SEND_MSG_TYPE_TAG;

struct snd_pseudo_hdr {
	uint8_t		msgtype[16];
	struct in6_addr	src;
	struct in6_addr	dst;
};

static void
fill_snd_pseudo_hdr(struct in6_addr *src, struct in6_addr *dst,
    struct snd_pseudo_hdr *psh)
{
	memcpy(psh->msgtype, send_msg_type_tag, sizeof (psh->msgtype));
	psh->src = *src;
	psh->dst = *dst;
}

int
snd_proto_verify_sig(uint8_t *nd_so, uint8_t *key, int klen,
    struct ip6_hdr *iph, struct icmp6_hdr *icmp, int tlen)
{
	struct snd_pseudo_hdr psh[1];
	struct iovec iov[2];
	struct snd_opt_sig *so;
	struct snd_sig_method *m;
	uint8_t hash[SHA_DIGEST_LENGTH];
	int slen;

	so = (struct snd_opt_sig *)(nd_so);
	if ((m = snd_find_sig_method_bytype(nd_so[0])) == NULL) {
		DBG(&dbg_snd, "Can't find signature method for type %d",
		    nd_so[0]);
		return (-1);
	}

	/* Verify key hash against given key */
	SHA1(key, klen, hash);
	if (memcmp(so->keyhash, hash, sizeof (so->keyhash)) != 0) {
		DBG(&dbg_snd, "keyhash does not match");
		DBG_HEXDUMP(&dbg_snd, "option   keyhash", so->keyhash,
			    sizeof (so->keyhash));
		DBG_HEXDUMP(&dbg_snd, "computed keyhash", hash,
			    sizeof (hash));
		return (-1);
	}

	/* Set up for signature verification */
	fill_snd_pseudo_hdr(&iph->ip6_src, &iph->ip6_dst, psh);
	iov[0].iov_base = psh;
	iov[0].iov_len = sizeof (*psh);
	iov[1].iov_base = icmp;
	iov[1].iov_len = tlen - sizeof (*iph);

	/* Verify signature */
	slen = nd_so[1] << 3;
	slen -= sizeof (*so);
	if (m->verify(iov, ARR_SZ(iov), key, klen, so->sig, slen) < 0) {
		DBG(&dbg_snd, "signature verification failed");
		return (-1);
	}

	return (0);
}

uint8_t *
snd_proto_calc_sig(struct ip6_hdr *iph, struct icmp6_hdr *icmp, int tlen,
    int *slen, struct snd_cga_params *p)
{
	struct snd_pseudo_hdr psh[1];
	struct iovec iov[2];

	/* Set up for signature calculation */
	fill_snd_pseudo_hdr(&iph->ip6_src, &iph->ip6_dst, psh);
	iov[0].iov_base = psh;
	iov[0].iov_len = sizeof (*psh);
	iov[1].iov_base = icmp;
	iov[1].iov_len = tlen - sizeof (*iph);

	/* Calculate signature */
	return (p->sigmeth->sign(iov, ARR_SZ(iov), slen, p->key));
}
