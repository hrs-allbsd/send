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

/*
 * This file contains the main SEND neighbor discovery protocol
 * functionality.
 *
 * Threading model:
 * One main thread handles all I/O, and does some initial packet processing
 * that is not CPU-intensive. Once a packet passes the basic checks, it
 * is handed off to a thread pool with thrpool_req, where cryptographic tasks
 * are performed.
 * There are two sources of packets: the OS-specific packet intercept
 * mechanism, and an ICMPv6 socket. This file handles the intercepted
 * ND packets. The ICMPv6 packets of interest are RA, CPS, and CPA,
 * which are handled by their respective files.
 * If sendd is built withouth multi-threading support, thrpool_req
 * simple calls the function directly.
 */

#include <string.h>
#include <sys/socket.h>

#include "config.h"
#include <applog.h>
#include <in_cksum.h>
#include <thrpool.h>
#include <cga.h>

#include "sendd_local.h"
#include "os_specific.h"
#include "os/os_defines.h"
#include "snd_proto.h"
#include "snd_config.h"
#include "dbg.h"

#ifdef	DEBUG
#include <arpa/inet.h>
static char abuf[INET6_ADDRSTRLEN];
static struct dlog_desc dbg = {
	.desc = "proto",
	.ctx = SENDD_NAME
};
#endif

struct snd_pkt_info {
	struct sbuff	*b;
	struct ip6_hdr	*iph;
	struct icmp6_hdr *icmp;
	struct in6_addr	*cga;
	void		*start;
	void		*os_pkt;
	struct snd_sig_method *sigmeth;  // for incoming pkts
	struct snd_cga_params *params;   // for outgoing pkts
	uint8_t		*key;
	int		klen;
	int		ifidx;
	uint64_t	ts;
	uint64_t	now;
	struct ndopts	ndopts;
};

enum snd_pkt_decision {
	SND_STOLEN,
	SND_ACCEPT_CHANGED,
	SND_ACCEPT_NOTCHANGED,
	SND_DROP,
};

static inline void
ipv6_addr_all_routers(struct in6_addr *addr)
{
	ipv6_addr_set(addr, htonl(0xFF020000), 0, 0, htonl(0x2));
}

static int
verify_cga(uint8_t *cgaopt, struct in6_addr *saddr,
    struct snd_pkt_info *pi)
{
	uint8_t *cgap = cgaopt + 2;
	int plen;

	/* calculate true params length */
	plen = cgaopt[1] << 3; /* whole option len */
	plen -= *cgap; /* subtract padding */
	plen -= (2 + 2); /* subtract opt header and pad len / reserved */

	cgap += 2; /* skip pad len and reserved */

	DBG(&dbg, "CGA verification for %s",
	    inet_ntop(AF_INET6, saddr, abuf, sizeof (abuf)));

	if (snd_cga_verify(saddr, cgap, plen, &pi->key, &pi->klen) != 0) {
		DBG(&dbg_snd, "CGA verification for %s failed",
		    inet_ntop(AF_INET6, saddr, abuf, sizeof (abuf)));
		return (-1);
	}
	DBG(&dbg, "ok");

	return (0);
}

static int
handle_incoming_nonce(struct snd_pkt_info *pi, int *secure)
{
	struct in6_addr tbuf[1], *tgt = NULL;

	switch (pi->icmp->icmp6_type) {
	case ND_ROUTER_SOLICIT:
	case ND_NEIGHBOR_SOLICIT:
		if (!pi->ndopts.opt[ND_OPT_NONCE]) {
			DBG(&dbg_snd, "RS / NS: no nonce; dropping");
			return (-1);
		}
		break;
	case ND_ROUTER_ADVERT:
	case ND_NEIGHBOR_ADVERT:
		if (!pi->ndopts.opt[ND_OPT_NONCE]) {
			DBG(&dbg, "RA / NA: no nonce; treating as "
			    "unsolicited");
			break;
		}

		if (pi->icmp->icmp6_type == ND_NEIGHBOR_ADVERT) {
			struct nd_neighbor_advert *na;

			na = (struct nd_neighbor_advert *)(pi->icmp);
			tgt = &na->nd_na_target;
		} else { /* RA */
			ipv6_addr_all_routers(tbuf);
			tgt = tbuf;
		}

		if (snd_proto_check_solicit_nonce(tgt, pi->ifidx,
				  (uint8_t *)(pi->ndopts.opt[ND_OPT_NONCE]))
		    < 0) {
			return (-1);
		}
		/* nonce is ok, so skip timestamp check */
		*secure = 2;
		break;
	}

	return (0);
}

static int
handle_outgoing_nonce(struct snd_pkt_info *pi)
{
	struct in6_addr tbuf[1], *tgt = NULL;

	switch (pi->icmp->icmp6_type) {
	case ND_ROUTER_SOLICIT:
		ipv6_addr_all_routers(tbuf);
		tgt = tbuf;
		break;
	case ND_NEIGHBOR_SOLICIT: {
		struct nd_neighbor_solicit *ns;

		ns = (struct nd_neighbor_solicit *)(pi->icmp);
		tgt = &ns->nd_ns_target;
		break;
	}
	case ND_ROUTER_ADVERT:
		tgt = NULL;
		break;
	case ND_NEIGHBOR_ADVERT: {
		struct nd_neighbor_advert *na;

		na = (struct nd_neighbor_advert *)(pi->icmp);
		tgt = &na->nd_na_target;
		break;
	}
	}

	switch (pi->icmp->icmp6_type) {
	case ND_ROUTER_SOLICIT:
	case ND_NEIGHBOR_SOLICIT:
		if (snd_proto_add_solicit_nonce(pi->b, tgt, pi->ifidx) < 0) {
			return (-1);
		}
		break;
	case ND_ROUTER_ADVERT:
	case ND_NEIGHBOR_ADVERT:
		if (snd_proto_add_advert_nonce(pi->b, &pi->iph->ip6_dst, tgt,
					       pi->ifidx) < 0) {
			/* catastrophic failure */
			return (-1);
		}
		break;
	}

	return (0);
}

static void
cksum(struct ip6_hdr *iph, struct icmp6_hdr *icmp, int len)
{
	vec_t cv[2];
	struct {
		struct in6_addr src, dst;
		uint32_t len;
		uint32_t nxt;
	} psh[1];

	/* checksum pseudo header */
	memset(psh, 0, sizeof (*psh));
	memcpy(&psh->src, &iph->ip6_src, sizeof (psh->src));
	memcpy(&psh->dst, &iph->ip6_dst, sizeof (psh->dst));
	psh->len = htonl(len);
	psh->nxt = htonl(IPPROTO_ICMPV6);

	/* ICMP6 checksum */
	icmp->icmp6_cksum = 0;
	cv[0].ptr = (uint8_t *)psh;
	cv[0].len = sizeof (*psh);
	cv[1].ptr = (uint8_t *)icmp;
	cv[1].len = len;
	icmp->icmp6_cksum = in_cksum(cv, ARR_SZ(cv));
}

static int
upd_caches(struct snd_pkt_info *pi)
{
	struct in6_addr tbuf[1], *tgt = NULL;
	uint8_t *nonceopt = NULL;

	switch (pi->icmp->icmp6_type) {
	case ND_ROUTER_SOLICIT:
	case ND_NEIGHBOR_SOLICIT:
		nonceopt = (uint8_t *)pi->ndopts.opt[ND_OPT_NONCE];

		if (pi->icmp->icmp6_type == ND_NEIGHBOR_SOLICIT) {
			struct nd_neighbor_solicit *ns;

			ns = (struct nd_neighbor_solicit *)(pi->icmp);
			tgt = &ns->nd_ns_target;
		}

		if (snd_proto_cache_nonce(&pi->iph->ip6_src, tgt, pi->ifidx,
					  nonceopt) < 0) {
			return (-1);
		}
		break;
	case ND_ROUTER_ADVERT:
	case ND_NEIGHBOR_ADVERT:
		if (!pi->ndopts.opt[ND_OPT_NONCE]) {
			break;
		}

		if (pi->icmp->icmp6_type == ND_NEIGHBOR_ADVERT) {
			struct nd_neighbor_advert *na;

			na = (struct nd_neighbor_advert *)(pi->icmp);
			tgt = &na->nd_na_target;
		} else { /* RA */
			ipv6_addr_all_routers(tbuf);
			tgt = tbuf;
		}

		snd_del_solicit_ent(tgt, pi->ifidx);
		break;
	}
	snd_timestamp_cache_upd(pi->cga, pi->ifidx, pi->now, pi->ts);

	return (0);
}

/*
 * Walk the supported signature method list until we find one that
 * matches a signature option in the incoming packet.
 */
struct sigmeth_info {
	struct snd_sig_method *m;
	struct ndopts *ndopts;
};

static int
sigmeth_walker(struct snd_sig_method *m, void *c)
{
	struct sigmeth_info *si = c;

	if (si->ndopts->opt[m->type] != NULL) {
		si->m = m;
		/* Found it; don't continue walking */
		return (0);
	}

	/* Continue searching */
	return (1);
}

static struct snd_sig_method *
find_incoming_sig_method(struct ndopts *ndopts)
{
	struct sigmeth_info si;

	si.m = NULL;
	si.ndopts = ndopts;
	snd_walk_sig_methods(sigmeth_walker, &si);

	return (si.m);
}

struct snd_sig_method *
snd_packetinfo_sigmeth(void *p)
{
	struct snd_pkt_info *pi = p;
	return (pi->sigmeth);
}

static void
incoming_thr(void *p)
{
	struct snd_pkt_info *pi = p;
	int tlen;
	int drop = 0;
	uint8_t sigtype = pi->sigmeth->type;

	/* Snip off signature option */
	tlen = (int)((uint8_t *)(pi->ndopts.opt[sigtype]) -
		     (uint8_t *)(pi->iph));
	pi->iph->ip6_plen = htons(tlen - sizeof (*pi->iph));
	DBG(&dbg, "siglen: %d", pi->b->len - tlen);

	/* recalculate cksum */
	cksum(pi->iph, pi->icmp, tlen - sizeof (*pi->iph));

	if (snd_proto_verify_sig(pi->ndopts.opt[sigtype], pi->key,
				 pi->klen, pi->iph, pi->icmp, tlen)
	    < 0) {
		DBG(&dbg_snd, "verify sig: failed");
		drop = 1;
	} else {
		DBG(&dbg, "verify sig: ok");

		/*
		 * Now that the sig is verified, we can go ahead and update
		 * our caches as needed.
		 */
		if (upd_caches(pi) < 0) {
			drop = 1;
		}
	}

	if (!drop && pi->icmp->icmp6_type == ND_ROUTER_ADVERT) {
		DBG(&dbg, "Checking RA");
		snd_verify_ra((uint8_t *)(pi->iph), pi->b->len, pi->ifidx,pi);
		return;
	}

	pi->b->data = pi->start;
	pi->b->len = tlen;

	DBG(&dbg, "%s pkt (%d bytes)", drop ? "dropping" : "delivering",
	    pi->b->len);

	os_specific_deliver_pkt(pi->os_pkt, pi->b, drop, 1);

	free(pi);
}

static void
outgoing_thr(void *p)
{
	struct snd_pkt_info *pi = p;
	uint8_t *sig = NULL;
	int slen;
	int drop = 0;

	pi->iph->ip6_plen = htons(pi->b->len - sizeof (*pi->iph));
	cksum(pi->iph, pi->icmp, pi->b->len - sizeof (*pi->iph));

	DBG(&dbg, "Adding signature using method '%s'",
	    pi->params->sigmeth->name);
	if ((sig = snd_proto_calc_sig(pi->iph, pi->icmp, pi->b->len, &slen,
				      pi->params)) == NULL) {
		DBG(&dbg_snd, "calculate sig failed; dropping");
		drop = 1;
		goto done;
	}

	/* Add signature option */
	if (snd_add_sig_opt(pi->b, pi->params->keyhash, sig, slen,
			    pi->params->sigmeth->type) < 0) {
		DBG(&dbg_snd, "snd_add_sig_opt() failed; dropping");
		drop = 1;
		goto done;
	}

	/* Recalculate payload length in IP hdr now that sig is in */
	pi->iph->ip6_plen = htons(pi->b->len - sizeof (*pi->iph));

	/* Recalculate checksum */
	cksum(pi->iph, pi->icmp, pi->b->len - sizeof (*pi->iph));

done:
	DBG(&dbg, "%s pkt (%d bytes)", drop ? "dropping" : "delivering",
	    pi->b->len);
	snd_put_cga_params(pi->params);
	if (sig) free(sig);
	pi->b->data = pi->start;
	os_specific_deliver_pkt(pi->os_pkt, pi->b, drop, 1);

	free(pi);
}

static enum snd_pkt_decision
handle_incoming(struct snd_pkt_info *pi)
{
	int secure = 0;
	int is_response = 0;
	int prio;

	DBG(&dbg, "");

	if ((pi->sigmeth = find_incoming_sig_method(&pi->ndopts)) == NULL) {
		DBG(&dbg_snd, "No supported signature types found");
		return (SND_DROP);
	}
	DBG(&dbg, "Incoming packet uses signature method '%s'",
	    pi->sigmeth->name);

	if (!pi->ndopts.opt[ND_OPT_CGA] ||
	    !pi->ndopts.opt[pi->sigmeth->type]) {
		DBG(&dbg, "no CGA / SIG option");
		/* treat as unsecured */
		if (!secure && snd_conf_get_int(snd_full_secure)) {
			DBG(&dbg_snd, "secure mode; dropping unsecured ND");
			return (SND_DROP);
		}

		/* Else do mixed mode checks */
		goto timestamp_check;
	}
	secure = 1; /* ND msg has a RSA sig option */
	if (!pi->ndopts.opt[ND_OPT_TIMESTAMP]) {
		DBG(&dbg_snd, "Sig option, but no timestamp; dropping");
		return (SND_DROP);
	}
	if (verify_cga(pi->ndopts.opt[ND_OPT_CGA], pi->cga, pi) < 0 ||
	    handle_incoming_nonce(pi, &secure) < 0) {
		return (SND_DROP);
	}
	if (secure == 2) {
		is_response = 1;
	}

timestamp_check:
	/*
	 * check_timestamp also ensures that unsecured ND won't
	 * override secured ND, so it is OK to get here if
	 * there is no timestamp option.
	 */
	if (snd_check_timestamp(pi->cga, pi->ifidx,
				pi->ndopts.opt[ND_OPT_TIMESTAMP],
				&pi->ts, &pi->now, secure) < 0) {
		return (SND_DROP);
	}
	if (!secure &&
	    pi->icmp->icmp6_type == ND_ROUTER_ADVERT &&
	    snd_process_ra((uint8_t *)(pi->icmp),
			   pi->b->len - sizeof (*pi->iph), pi->ifidx,
			   pi->cga) < 0) {
		return (SND_DROP);
	}

	if (!secure) {
		DBG(&dbg, "mixed mode; accepting unsecured ND");
		return (SND_ACCEPT_NOTCHANGED);
	}

	prio = cga_get_sec(pi->cga);
	prio += SND_THR_PRIO_IN + (is_response ? SND_THR_PRIO_RESP : 0);
	DBG(&dbg, "Handing off to thrpool, prio %d", prio);
	if (thrpool_req(incoming_thr, pi, NULL, prio) < 0) {
		DBG(&dbg_snd, "thrpool_req() failed; dropping pkt");
		return (SND_DROP);
	}
	return (SND_STOLEN);
}

static enum snd_pkt_decision
handle_outgoing(struct snd_pkt_info *pi)
{
	int prio;

	pi->params = snd_cga_get_params(pi->cga, pi->ifidx);
	snd_hold_cga_params(pi->params);

	DBG(&dbg, "Adding SEND options");
	if (snd_add_cga_opt(pi->b, pi->params->der, pi->params->dlen) < 0 ||
	    snd_add_timestamp_opt(pi->b) < 0 ||
	    handle_outgoing_nonce(pi) < 0) {
		snd_put_cga_params(pi->params);
		return (SND_DROP);
	}

	/*
	 * Since we will always add a signature from this point, push
	 * the rest of the operations into the thrpool.
	 */
	prio = SND_THR_PRIO_OUT;
	DBG(&dbg, "Handing off to thrpool, prio %d", prio);
	if (thrpool_req(outgoing_thr, pi, NULL, 1) < 0) {
		snd_put_cga_params(pi->params);
		DBG(&dbg_snd, "thrpool_req() failed; dropping pkt");
		return (SND_DROP);
	}
	return (SND_STOLEN);
}

/*
 * Do some light checks for ND message validity per RFC2461. We don't
 * need to do the full checks here since the kernel IPv6 stack will
 * do them later. We are mostly interested in preventing DOS attacks
 * from attackers off-link and multicast DOS attacks.
 *
 * If the checks pass, sets the CGA to be verified in pi->cga, and
 * returns 1 if the packet it OK and should be checked, 2 if we can
 * pass it without checking, 0 if not OK.
 */
static int
pkt_is_valid_nd(struct snd_pkt_info *pi, int *dad)
{
	if (pi->iph->ip6_hlim != 255) {
		DBG(&dbg_snd, "hop limit != 255 (%d)", pi->iph->ip6_hlim);
		return (0);
	}
	/* Don't check the code to allow RA extension by eg. FMIP */

	switch (pi->icmp->icmp6_type) {
	case ND_ROUTER_SOLICIT:
		if (!sbuff_pull(pi->b, sizeof (struct nd_router_solicit))) {
			DBG(&dbg_snd, "pkt too small (RS)");
			return (0);
		}
		if (IN6_IS_ADDR_UNSPECIFIED(&pi->iph->ip6_src)) {
			/* No CGA on this */
			return (2);
		}
		pi->cga = &pi->iph->ip6_src;
		break;
	case ND_ROUTER_ADVERT:
#ifndef SND_OS_freebsd
		if (!IN6_IS_ADDR_LINKLOCAL(&pi->iph->ip6_src)) {
			DBG(&dbg_snd, "RA src addr is not link local");
			return (0);
		}
#endif
		if (!sbuff_pull(pi->b, sizeof (struct nd_router_advert))) {
			DBG(&dbg_snd, "pkt too small (RA)");
			return (0);
		}
		pi->cga = &pi->iph->ip6_src;
		break;
	case ND_NEIGHBOR_SOLICIT: {
		struct nd_neighbor_solicit *ns;
		if ((ns = sbuff_pull(pi->b, sizeof (*ns))) == NULL) {
			DBG(&dbg_snd, "pkt too small (NS)");
			return (0);
		}
		if (IN6_IS_ADDR_MULTICAST(&ns->nd_ns_target)) {
			DBG(&dbg_snd, "NS target is multicast");
			return (0);
		}
		if (IN6_IS_ADDR_UNSPECIFIED(&pi->iph->ip6_src)) {
			/* DAD */
			*dad = 1;
			pi->cga = &ns->nd_ns_target;
		} else {
			pi->cga = &pi->iph->ip6_src;
		}
		break;
	}
	case ND_NEIGHBOR_ADVERT: {
		struct nd_neighbor_advert *na;

		if ((na = sbuff_pull(pi->b, sizeof (*na))) == NULL) {
			DBG(&dbg_snd, "pkt too small (NA)");
			return (0);
		}
		if (IN6_IS_ADDR_MULTICAST(&na->nd_na_target)) {
			DBG(&dbg_snd, "NA target is multicast");
			return (0);
		}
		pi->cga = &pi->iph->ip6_src;
		break;
	}
	case ND_REDIRECT:
		if (!IN6_IS_ADDR_LINKLOCAL(&pi->iph->ip6_src)) {
			DBG(&dbg_snd, "redirect src addr is not link local");
			return (0);
		}
		/* No way for us to check if src == 1st hop router */
		if (IN6_IS_ADDR_MULTICAST(&pi->iph->ip6_dst)) {
			DBG(&dbg_snd, "redirect dst is multicast");
			return (0);
		}
		if (!sbuff_pull(pi->b, sizeof (struct nd_redirect))) {
			DBG(&dbg_snd, "pkt too small (redirect)");
			return (0);
		}
		pi->cga = &pi->iph->ip6_src;
		break;
	default:
		DBG(&dbg, "Don't care about this icmp6 type");
		break;
	}

	return (1);
}

void
snd_finish_racheck(void *p, int ok)
{
	int tlen, drop = ok ? 0 : 1;
	struct snd_pkt_info *pi = p;

	tlen = (int)((uint8_t *)(pi->ndopts.opt[pi->sigmeth->type]) -
		     (uint8_t *)(pi->iph));

	pi->b->data = pi->start;
	pi->b->len = tlen;

	DBG(&dbg, "%s pkt (%d bytes)", drop ? "dropping" : "delivering",
	    pi->b->len);

	os_specific_deliver_pkt(pi->os_pkt, pi->b, drop, 1);

	free(pi);
}

void
snd_recv_pkt(struct sbuff *b, int ifidx, int in, void *pkt)
{
	int tlen, drop = 0;
	int changed = 0;
	int dad = 0;
	struct snd_pkt_info *pi = NULL;
	enum snd_pkt_decision r;
	void *start;
	struct ip6_hdr *iph;

	if (!snd_iface_ok(ifidx)) {
		return;
	}

	DBG(&dbg_snd, "pi->ifinfo->ifidx = %d", ifidx);

#ifndef SND_OS_freebsd
	if (!in)
		if (sbuff_pull(b, sizeof (struct ether_header)) == NULL) {
			DBG(&dbg_snd, "invalid pkt (not enough for ether header");
			goto drop;
		}
	}
#endif
	start = sbuff_data(b);

	DBG(&dbg, "%s", in ? "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" :
	    ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

	if ((pi = malloc(sizeof (*pi))) == NULL) {
		APPLOG_NOMEM();
		goto drop;
	}
	memset(pi, 0, sizeof (*pi));
	pi->b = b;
	pi->os_pkt = pkt;
	pi->ifidx = ifidx;

	/* Save packet start and len */
	pi->start = sbuff_data(b);
	tlen = b->len;

	if ((iph = pi->iph = sbuff_pull(b, sizeof (*(pi->iph)))) == NULL) {
		DBG(&dbg_snd, "pkt too small (ip6 hdr)");
		goto drop;
	}
	pi->icmp = sbuff_data(b);
	if (b->len < sizeof (*(pi->icmp))) {
		DBG(&dbg_snd, "pkt too small (icmp6 hdr)");
		goto drop;
	}

	DBG(&dbg_snd, "%s %s (%d) (if %d)", in ? "Incoming" : "Outgoing",
	    pi->icmp->icmp6_type == ND_ROUTER_SOLICIT ? "Router Solicit" :
	    pi->icmp->icmp6_type == ND_ROUTER_ADVERT ? "Router Advert" :
	    pi->icmp->icmp6_type == ND_NEIGHBOR_SOLICIT ? "Neighbor Solicit" :
	    pi->icmp->icmp6_type == ND_NEIGHBOR_ADVERT ? "Neighbor Advert" :
	    pi->icmp->icmp6_type == ND_REDIRECT ? "Redirect" :
	    "<unknown>", pi->icmp->icmp6_type, ifidx);
	DBG(&dbg_snd, "src: %s",
	    inet_ntop(AF_INET6, &iph->ip6_src, abuf, sizeof (abuf)));
	DBG(&dbg_snd, "dst: %s",
	    inet_ntop(AF_INET6, &iph->ip6_dst, abuf, sizeof (abuf)));

	/* Do we need to secure this type? */
	switch (pkt_is_valid_nd(pi, &dad)) {
	case 1:
		break;
	case 2:
		goto done;
	default:
	case 0:
		goto drop;
	}

	if (in) {
		if (snd_is_lcl_cga(pi->cga, ifidx)) {
			DBG(&dbg, "is local; don't need to check");
			drop = 0;
			goto done;
		}
		if (snd_parse_opts(&pi->ndopts, sbuff_data(b), b->len) < 0) {
			goto drop;
		}
		b->len = tlen;
		r = handle_incoming(pi);
	} else {
		/* skip all options */
		sbuff_advance(b, b->len);
		b->len = tlen;

		if (!snd_is_lcl_cga(pi->cga, ifidx)) {
			DBG(&dbg_snd, "outgoing: not CGA, dropping");
			if (dad && IN6_IS_ADDR_LINKLOCAL(pi->cga)) {
				snd_replace_this_non_cga_linklocal(pi->cga,
								   pi->ifidx);
			}
			goto drop;
		}
		r = handle_outgoing(pi);
	}

	switch (r) {
	case SND_STOLEN:
		return;
	case SND_ACCEPT_CHANGED:
		changed = 1;
		/* fallthru */
	case SND_ACCEPT_NOTCHANGED:
		free(pi);
		goto done;
	case SND_DROP:
		break;
	}

drop:
	if (pi) free(pi);
	drop = 1;
done:
	b->data = start;
	os_specific_deliver_pkt(pkt, b, drop, changed);
}

int
snd_proto_init(void)
{
#ifdef	DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg,
		NULL
	};

	if (snd_applog_register(dbgs) < 0) {
		return (-1);
	}
#endif
	if (snd_proto_nonce_init() < 0 ||
	    snd_proto_timestamp_init() < 0) {
		return (-1);
	}
	return (0);
}

void
snd_proto_fini(void)
{
	snd_proto_nonce_fini();
	snd_proto_timestamp_fini();
}
