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
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/x509.h>

#include "config.h"
#include <applog.h>
#include <pkixip_ext.h>
#include <sbuff.h>

#include "sendd_local.h"
#include "snd_proto.h"
#include "dbg.h"

#ifdef	DEBUG
struct dlog_desc dbg_cp = {
	.desc = "cert_path",
	.ctx = SENDD_NAME
};
static struct dlog_desc *dbg = &dbg_cp;
static char nbuf[1024];
static char abuf[INET6_ADDRSTRLEN];
#endif

static inline void
addrconf_addr_solict_mult(const struct in6_addr *addr,
    struct in6_addr *solicited)
{
	ipv6_addr_set(solicited,
		      htonl(0xFF020000), 0,
		      htonl(0x1),
		      htonl(0xFF000000) | addr->s6_addr32[3]);
}


static inline void
ipv6_addr_all_nodes(struct in6_addr *addr)
{
	ipv6_addr_set(addr, htonl(0xFF020000), 0, 0, htonl(0x1));
}

static void
send_cpa(uint16_t id, struct sockaddr_in6 *to, X509 *x, int nrem, int tot,
    X509 *trx, int ifidx)
{
	struct snd_cpa *cpa;
	struct sbuff *b;
	struct sockaddr_in6 sin[1];

	if ((b = snd_get_buf()) == NULL) {
		DBG(&dbg_cp, "snd_get_buf() failed");
		return;
	}

	cpa = sbuff_data(b);
	if (sbuff_advance(b, sizeof (*cpa)) < 0) {
		DBG(&dbg_cp, "buffer too small");
		goto done;
	}
	memset(cpa, 0, sizeof (*cpa));

	cpa->type = ICMP6_SND_CPA;
	cpa->id = id;
	cpa->cnt = htons(tot);
	cpa->component = htons(nrem);

	if (x != NULL) {
		if (trx != NULL && snd_add_trustanchor_opt(b, trx) < 0) {
			goto done;
		}
		if (snd_add_cert_opt(b, x) < 0) {
			goto done;
		}
	}

	memset(sin, 0, sizeof (*sin));
	if (!IN6_IS_ADDR_UNSPECIFIED(&to->sin6_addr)) {
		addrconf_addr_solict_mult(&to->sin6_addr, &sin->sin6_addr);
	} else {
		ipv6_addr_all_nodes(&sin->sin6_addr);
	}		
	sin->sin6_port = htons(IPPROTO_ICMPV6);
	sin->sin6_scope_id = ifidx;

	DBG(dbg, "sending %d bytes to %s", b->len,
	    inet_ntop(AF_INET6, &to->sin6_addr, abuf, sizeof (abuf)));

	snd_send_icmp(b, sin, to->sin6_scope_id);

done:
	snd_put_buf(b);
}

STACK_OF(X509_NAME) *
snd_get_trustanchors_from_opts(uint8_t *ops, int len)
{
	uint8_t *op, *p;
	X509_NAME *dn;
	int olen;
	struct snd_opt_trustanchor *ta;
	STACK_OF(X509_NAME) *dns;

	if ((dns = sk_X509_NAME_new_null()) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (NULL);
	}

	op = ops;
	while (len > 0) {
		if ((op = snd_get_opt(op, len, ND_OPT_TRUST_ANCHOR))
		    == NULL) {
			break;
		}

		ta = (struct snd_opt_trustanchor *)op;
		p = op + sizeof (*ta);
		olen = ta->len << 3;
		if (ta->nametype != TRUST_ANCHOR_DN) {
			DBG(&dbg_snd, "Only handle DN name types (got %d)",
			    (int)ta->nametype);
			goto next;
		}

		if ((dn = d2i_X509_NAME(NULL,
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
					(const unsigned char **)
#endif
					&p, olen))
		    == NULL) {
			DBG(dbg, "d2i_X509_NAME() failed");
			goto next;
		}
		DBG(dbg, "got %s",
		    X509_NAME_oneline(dn, nbuf, sizeof (nbuf)));

		if (sk_X509_NAME_push(dns, dn) == 0) {
			applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
			break;
		}
next:
		op += olen;
		len -= olen;
	}

	return (dns);
}

static int
can_handle_cps(uint8_t *ops, int len, STACK *chain, X509 **x)
{
	int i, j, r = 0;
	X509_NAME *dn;
	X509 x509_s;
	X509_CINF cinf_s;
	STACK *dchain;
	STACK_OF(X509_NAME) *dns;

	*x = NULL;

	if ((dns = snd_get_trustanchors_from_opts(ops, len)) == NULL) {
		return (1);
	}
	if (sk_num(dns) == 0) {
		sk_free(dns);
		return (1);
	}

	/*
	 * If the name is in our chain, we can handle this CPS.
	 * First kludge up a dummy cert for searching. We also need
	 * to dup the chain since it will probably be reordered when
	 * sorting (triggered by sk_find), and we need to chain order
	 * preserved so we can send out the certs in correct order.
	 */
	if ((dchain = sk_dup(chain)) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		goto done;
	}
	x509_s.cert_info= &cinf_s;

	for (i = 0; i < sk_num(dns); i++) {
		dn = sk_X509_NAME_value(dns, i);
		cinf_s.subject=dn;

		if ((j = sk_X509_find(dchain, &x509_s)) >= 0) {
			r = 1;
			*x = sk_X509_value(dchain, j);
			DBG(dbg, "found");
			break;
		}
	}
	sk_free(dchain);

done:
	sk_X509_NAME_pop_free(dns, X509_NAME_free);

	return (r);
}

void
snd_handle_cps(struct sbuff *b, struct sockaddr_in6 *from, int ifidx)
{
	uint8_t *msg = sbuff_data(b);
	int len = b->len;
	STACK *chain;
	X509 *x, *trx = NULL;
	int i, tot, olen;
	uint8_t *ops;
	uint16_t comp;
	struct snd_cps *cps = (struct snd_cps *)msg;

	DBG(dbg, "");

	if (len < sizeof (*cps)) {
		DBG(&dbg_snd, "CPS too short");
		return;
	}

	if ((chain = pkixip_get_mychain()) != NULL) {
		ops = msg + sizeof (*cps);
		olen = len - sizeof (*cps);
		if (!can_handle_cps(ops, olen, chain, &trx)) {
			return;
		}
	} else {
		DBG(dbg, "mychain is NULL; sending empty CPA");
		send_cpa(cps->id, from, NULL, 0, 0, NULL, ifidx);
		return;
	}

	comp = ntohs(cps->component);

	for (i = tot = sk_num(chain) - 1; i >= 0; i--) {
		x = sk_X509_value(chain, i);

		/* don't need to send trust anchor cert */
		if (x == trx) {
			continue;
		}

		/* if the host specified a component, filter now */
		if (comp != SND_ALL_COMPONENTS && comp != i) {
			continue;
		}
		send_cpa(cps->id, from, x, i, tot, trx, ifidx);
	}
}

int
snd_certpath_init(void)
{
	struct timeval tv[1];
#ifdef	DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg_cp,
		NULL
	};

	if (snd_applog_register(dbgs) < 0) {
		return (-1);
	}
#endif

	gettimeofday(tv, NULL);
	srand(tv->tv_usec);

	return (0);
}
