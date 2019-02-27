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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "config.h"
#include <applog.h>
#include <timer.h>
#include <pkixip_ext.h>

#include "sendd_local.h"
#include "snd_proto.h"
#include "snd_config.h"
#include "os_specific.h"
#include "dbg.h"

#ifdef	DEBUG
static struct dlog_desc dbg = {
	.desc = "ra",
	.ctx = SENDD_NAME
};
static char abuf[INET6_ADDRSTRLEN];
#endif

static timer_item_t gc_timer_item;

#ifdef	LOG_TIMESTAMP
static struct timeval deferred_ts[1];
#endif

static DEFINE_LIST_HEAD(pfxlist);
struct snd_pfx {
	struct list_head list;
	struct in6_addr	pfx;
	int		ifidx;
	uint32_t	valid_time;
	uint32_t	pref_time;
	time_t		exp;
	uint8_t		plen;
	uint8_t		flags;
};

static void set_gc_timer(void);

static void
del_pfx(struct snd_pfx *p)
{
	DBG(&dbg, "%s/%d",
	    inet_ntop(AF_INET6, &p->pfx, abuf, sizeof (abuf)), p->plen);

	list_del(&p->list);
	free(p);
}

static void
pfx_gc_timer(void *a)
{
	struct timeval now[1];
	struct snd_pfx *p, *n;

	DBG(&dbg, "");

	gettimeofday(now, NULL);

	list_for_each_entry_safe(p, n, &pfxlist, list) {
		DBG(&dbg, "%s/%d",
		    inet_ntop(AF_INET6, &p->pfx, abuf, sizeof (abuf)),
		    p->plen);

		if (p->exp < now->tv_sec) {
			del_pfx(p);
			DBG(&dbg, "expired");
		}
	}

	if (!list_empty(&pfxlist)) {
		set_gc_timer();
		return;
	}
	timerclear(&gc_timer_item.tv);
	DBG(&dbg, "idling");
}

static void
set_gc_timer(void)
{
	struct timeval tv[1];

	if (timerisset(&gc_timer_item.tv)) {
		return;
	}

	tv->tv_sec = snd_conf_get_int(snd_pfx_cache_gc_intvl);
	tv->tv_usec = 0;
	timer_set(tv, pfx_gc_timer, NULL, &gc_timer_item);
	DBG(&dbg, "next gc in %d seconds",
	    snd_conf_get_int(snd_pfx_cache_gc_intvl));
}

static void
add_addr(struct nd_opt_prefix_info *pfxinfo, int ifidx)
{
	struct in6_addr a[1];

	if (!(pfxinfo->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) ||
	    !snd_conf_get_int(snd_addr_autoconf)) {
		return;
	}

	if (pfxinfo->nd_opt_pi_prefix_len != 64) {
		DBG(&dbg, "prefix len != 64; can't create a cga");
		return;
	}

	memcpy(a, &pfxinfo->nd_opt_pi_prefix, sizeof (*a));
	if (snd_cga_gen(a, snd_find_params_byifidx(ifidx)) < 0) {
		return;
	}
	DBG(&dbg, "CGA: %s",
	    inet_ntop(AF_INET6, a, abuf, sizeof (abuf)));

	os_specific_add_addr(a, ifidx, 64,
			     ntohl(pfxinfo->nd_opt_pi_valid_time),
			     ntohl(pfxinfo->nd_opt_pi_preferred_time));
}

static inline int
prefix_match(void *a, struct snd_pfx *p)
{
	int bytes, bits, plen = p->plen;
	uint8_t abits, pbits, m, v;

	bytes = plen / 8;
	bits = plen % 8;

	if (bytes && memcmp(a, &p->pfx, bytes) != 0) {
		return (0);
	}
	if (bits == 0) {
		return (1);
	}

	for (m = 0, v = 0x80; plen; plen--) {
		m += v;
		v /= 2;
	}

	abits = ((uint8_t *)a)[bytes];
	abits &= m;
	pbits = *(((uint8_t *)&p->pfx) + bytes);
	pbits &= m;

	if (abits == pbits) {
		return (1);
	}
	return (0);
}

static struct snd_pfx *
find_pfx(struct in6_addr *p1, int ifidx)
{
	struct snd_pfx *p2;

	list_for_each_entry(p2, &pfxlist, list) {
		if (ifidx == p2->ifidx && prefix_match(p1, p2)) {
			return (p2);
		}
	}

	return (NULL);
}

static int
process_pfx(struct nd_opt_prefix_info *pi, int ifidx, int secure)
{
	struct snd_pfx *p;
	uint32_t vlife = ntohl(pi->nd_opt_pi_valid_time);
	uint32_t plife = ntohl(pi->nd_opt_pi_preferred_time);
	struct timeval tv[1];

	if (plife > vlife) {
		DBG(&dbg_snd, "pref life > valid life; ignoring");
		return (0);
	}

	p = find_pfx(&pi->nd_opt_pi_prefix, ifidx);

	/* Ensure that an unsecured RA can't override a secured RA */
	if (!secure) {
		if (p) {
			return (-1);
		}
		/* else no override; autoconf, but don't add any state */
		add_addr(pi, ifidx);
		return (0);
	}

	if (vlife == 0) {
		if (p) {
			del_pfx(p);
		}
		return (0);
	}

	if (p) {
		DBG(&dbg, "Already have prefix; refreshing");
		goto refresh;
	}

	if ((p = malloc(sizeof (*p))) == NULL) {
		APPLOG_NOMEM();
		return (-1);
	}

	memset(p, 0, sizeof (*p));
	p->pfx = pi->nd_opt_pi_prefix;
	p->ifidx = ifidx;
	p->plen = pi->nd_opt_pi_prefix_len;
	p->flags = pi->nd_opt_pi_flags_reserved;

	list_add_tail(&p->list, &pfxlist);

refresh:
	add_addr(pi, ifidx);

	p->valid_time = vlife;
	p->pref_time = plife;

	/* set expiration */
	gettimeofday(tv, NULL);
	if (vlife == 0xffffffff) {
		/* never expires */
		p->exp = vlife;
	} else {
		p->exp = tv->tv_sec + vlife;
	}
	set_gc_timer();

	return (0);
}

/*
 * Called in two different scenarios: First when checking an unsecured
 * RA (via the IP filter), second when an RA is received on the icmp6
 * socket.
 * When checking an unsecured RA, this just ensures that the RA would
 * not override any prefix info generated by a secured RA. No state is
 * updated.
 * When processing a secured RA from the icmp6 socket, this caches the
 * prefix info.
 * The prefix list (pfxlist) only contains information from secured RAs.
 */
int
snd_process_ra(uint8_t *raw, int ralen, int ifidx, struct in6_addr *from)
{
	struct ndopts ndopts[1];
	struct nd_router_advert *ra;
	struct nd_opt_prefix_info *pfxinfo;
	uint8_t *nopt;
	int len;
	int secure = 0;

	DBG(&dbg, "");

	if (!snd_iface_ok(ifidx)) {
		DBG(&dbg, "SEND not active on this interface");
		return (0);
	}

	if (snd_is_lcl_cga(from, ifidx)) {
		DBG(&dbg, "is local; don't need to process");
		return (0);
	}

	ra = (struct nd_router_advert *)raw;
	if (ra->nd_ra_router_lifetime == 0) {
		DBG(&dbg, "router lifetime is 0");
		return (0);
	}

	nopt = (uint8_t *)(ra + 1);
	len = ralen - sizeof (*ra);

	while (len > 0) {
		if (snd_parse_opts(ndopts, nopt, len) < 0) {
			DBG(&dbg_snd, "invalid option format");
			return (-1);
		}
		if (ndopts->opt[ND_OPT_CGA]) {
			/* really only happens once */
			DBG(&dbg, "secured RA");
			secure = 1;
		}

		if (!ndopts->opt[ND_OPT_PREFIX_INFORMATION]) {
			break;
		}
		pfxinfo = (struct nd_opt_prefix_info *)
			ndopts->opt[ND_OPT_PREFIX_INFORMATION];
		nopt = (uint8_t *)(pfxinfo + 1);
		len = ralen - (nopt - raw);

		DBG(&dbg, "prefix: %s/%d",
		    inet_ntop(AF_INET6, &pfxinfo->nd_opt_pi_prefix, abuf,
			      sizeof (abuf)), pfxinfo->nd_opt_pi_prefix_len);

		if (process_pfx(pfxinfo, ifidx, secure) < 0) {
			return (-1);
		}
	}

	return (0);
}

/*
 * RA verification support routines
 */
static IPAddrBlocks *
mkblock(IPAddressFamily *ipf)
{
	IPAddrBlocks *ipb;
	uint8_t afbuf[3];
	uint16_t af;

	if ((ipb = IPAddrBlocks_new()) == NULL) {
		applog(LOG_CRIT, "no memory");
		goto fail;
	}

	if (sk_push(ipb, (char *)ipf) == 0) {
		applog(LOG_CRIT, "sk_push() failed");
		goto fail;
	}

	af = htons(IANA_AF_IPV6);
	memcpy(afbuf, &af, sizeof (af));
	afbuf[2] = IANA_SAFI_UNICAST;
	ASN1_OCTET_STRING_set(ipf->addressFamily, afbuf, sizeof (afbuf));

	/* Sort prefixes */
	sk_sort(ipf->ipAddressChoice->u.addressesOrRanges);

	return (ipb);

fail:
	IPAddressFamily_free(ipf);
	return (NULL);
}

static inline void
set_bits(ASN1_BIT_STRING *abs, uint8_t *data, int bytes, int bits)
{
	ASN1_BIT_STRING_set(abs, data, bytes);
	abs->flags |= ASN1_STRING_FLAG_BITS_LEFT;
	abs->flags |= bits;
}

static int
add_prefix(IPAddressFamily *ipf, struct in6_addr *pfx, uint8_t plen)
{
	IPAddressChoice *ipc = ipf->ipAddressChoice;
	IPAddressOrRange *aor;
	int bytes, bits;

	if ((aor = IPAddressOrRange_new()) == NULL) {
		applog(LOG_CRIT, "no memory");
		goto fail;
	}
	if (sk_push(ipc->u.addressesOrRanges, (char *)aor) == 0) {
		applog(LOG_CRIT, "sk_push() failed");
		IPAddressOrRange_free(aor);
		goto fail;
	}

	if ((aor->u.addressPrefix = ASN1_BIT_STRING_new()) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		goto fail;
	}

	bytes = plen / 8;
	bits = plen % 8;
	if (bits) {
		bits = 8 - bits;
		bytes++;
	}

	aor->type = IP_AOR_PREFIX;
	set_bits(aor->u.addressPrefix, pfx->s6_addr, bytes, bits);

	return (0);

fail:
	IPAddressFamily_free(ipf);
	return (-1);
}

/*
 * Verifies the sending router's authority over the prefixes advertised
 * in this RA by checking the associated cert path and PKIX IP extentions.
 * This must happen before we can call snd_process_ra().
 */
void
snd_verify_ra(uint8_t *raw, int ralen, int ifidx, void *pi)
{
	struct ip6_hdr *hdr;
	struct ndopts ndopts[1];
	uint8_t *nopt;
	struct nd_opt_prefix_info *pfxinfo;
	int len;
	IPAddrBlocks *ipbp, *ipb = NULL;
	IPAddressFamily *ipf = NULL;
	IPAddressChoice *ipc;
	void *x; /* X509 */
	uint8_t *khash, *sigopt;
	struct snd_sig_method *m = snd_packetinfo_sigmeth(pi);
	int rv = 0;
	DEFINE_TIMESTAMP_VARS();

	hdr = (struct ip6_hdr *)raw;
	
	DBG(&dbg, "RA from %s on ifidx %d",
	    inet_ntop(AF_INET6, &hdr->ip6_src, abuf, sizeof (abuf)), ifidx);

	nopt = raw + sizeof (*hdr) + sizeof (struct nd_router_advert);
	len = ralen - (sizeof (*hdr) + sizeof (struct nd_router_advert));

	if ((ipf = IPAddressFamily_new()) == NULL) {
		applog(LOG_CRIT, "no memory");
		snd_finish_racheck(pi, 0);
		return;
	}
	ipc = ipf->ipAddressChoice;
	ipc->type = IPA_CHOICE_AOR;

	if ((ipc->u.addressesOrRanges = sk_new(pkixip_aor_cmp)) == NULL) {
		applog(LOG_CRIT, "no memory");
		rv = -1;
		goto done;
	}

	while (len > 0) {
		if (snd_parse_opts(ndopts, nopt, len) < 0) {
			DBG(&dbg_snd, "invalid option format");
			rv = -1;
			goto done;
		}

		if (!ndopts->opt[ND_OPT_PREFIX_INFORMATION]) {
			break;
		}
		pfxinfo = (struct nd_opt_prefix_info *)
			ndopts->opt[ND_OPT_PREFIX_INFORMATION];
		nopt = (uint8_t *)(pfxinfo + 1);
		len = ralen - (nopt - raw);

		DBG(&dbg, "prefix: %s",
		    inet_ntop(AF_INET6, &pfxinfo->nd_opt_pi_prefix, abuf,
			      sizeof (abuf)));

		if (add_prefix(ipf, &pfxinfo->nd_opt_pi_prefix,
			       pfxinfo->nd_opt_pi_prefix_len) < 0) {
			rv = -1;
			goto done;
		}
	}

	if ((sigopt = ndopts->opt[m->type]) == NULL) {
		DBG(&dbg_snd, "Missing signature option");
		rv = -1;
		goto done;
	}
	khash = sigopt + 4;

	if (sk_num(ipc->u.addressesOrRanges) == 0) {
		DBG(&dbg_snd, "Found no prefixes");
		rv = -1;
		goto done;
	}
	if ((ipb = mkblock(ipf)) == NULL) {
		rv = -1;
		goto done;
	}

	/* Verify */
#ifdef	DEBUG
	DBG(&dbg, "Block to be verified:");
	X509V3_EXT_val_prn(BIO_new_fp(stderr, BIO_NOCLOSE),
			   i2v_IPAddrBlocks(NULL, ipb, NULL), 8, 1);
#endif

	if (!snd_can_verify_now(khash, (void **)&x)) {
		TIMESTAMP_START_GLOBAL(deferred_ts);
		if (snd_make_cps(khash, x, ipb, &hdr->ip6_src, ifidx, pi)
		    == 0) {
			return;
		}
		rv = -1;
		goto done;
	}

	if (snd_conf_get_int(snd_accept_unconstrained_ra) &&
	    !pkixip_has_ext(x)) {
		DBG(&dbg, "Unconstrained certificate");
		ipbp = NULL;
	} else {
		ipbp = ipb;
	}

	TIMESTAMP_START();
	if (pkixip_verify_cert(x, ipbp) < 0) {
		TIMESTAMP_END("Full chain verification (fail)");
		DBG(&dbg_snd, "PKIX IP Ext check failed");
		rv = -1;
		goto done;
	}
	TIMESTAMP_END("Full chain verification");

done:
	if (rv < 0) {
		if (ipb) {
			IPAddrBlocks_free(ipb);
		} else if (ipf) {
			IPAddressFamily_free(ipf);
		}
		snd_finish_racheck(pi, 0);
	} else {
		snd_finish_racheck(pi, 1);
	}
}

#ifdef	USE_CONSOLE
void
dump_pfx_cache(void)
{
	struct snd_pfx *p;
	char abuf[INET6_ADDRSTRLEN];

	list_for_each_entry(p, &pfxlist, list) {
		printf("\t%s/%d (ifidx %d)\n\t\tvalid %u pref %u\n",
		       inet_ntop(AF_INET6, &p->pfx, abuf, sizeof (abuf)),
		       p->plen, p->ifidx, p->valid_time, p->pref_time);
		printf("\t\texp %s", ctime(&p->exp));
	}
}
#endif

int
snd_ra_init(void)
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

	return (0);
}

void
snd_ra_fini(void)
{
	struct snd_pfx *p, *n;

	DBG(&dbg, "");
	list_for_each_entry_safe(p, n, &pfxlist, list) {
		del_pfx(p);
	}
}
