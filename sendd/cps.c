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
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/x509.h>

#include "config.h"
#include <applog.h>
#include <list.h>
#include <thrpool.h>
#include <pkixip_ext.h>
#include <sbuff.h>

#include "sendd_local.h"
#include "snd_proto.h"
#include "dbg.h"

#ifdef	DEBUG
#include <arpa/inet.h>
extern struct dlog_desc dbg_cp;
static struct dlog_desc *dbg = &dbg_cp;
static char abuf[INET6_ADDRSTRLEN];
static char nbuf[1024];
#endif

extern STACK_OF(X509) *snd_trustanchors;
extern STACK_OF(X509_NAME) *snd_get_trustanchors_from_opts(uint8_t *, int);

/* certificate path request records */
static DEFINE_LIST_HEAD(cprs);
static pthread_mutex_t cprs_lock = PTHREAD_MUTEX_INITIALIZER;

struct snd_cpr {
	struct list_head list;
	uint8_t		khash[SHA_DIGEST_LENGTH];
	X509		*x;
	IPAddrBlocks	*ipb;
	struct in6_addr	to;
	int		ifidx;
	void		*pi;
	uint16_t	id;
};

/* Reordering cache */
#define	MAX_REORDERS	4
static DEFINE_LIST_HEAD(reorders);
static pthread_mutex_t reorder_lock = PTHREAD_MUTEX_INITIALIZER;
static int reorder_cnt;

struct reorder_entry {
	struct list_head list;
	X509 *		x;
};

/* CPA handling: info struct for the thrpool */
struct cpa_info {
	X509		*x;
	uint16_t	id;
};

static int
send_cps(struct in6_addr *to, int ifidx, uint16_t id)
{
	struct sbuff *b;
	struct snd_cps *cps;
	struct sockaddr_in6 sin6[1];
	int i, r = -1;
	X509 *x;

	if ((b = snd_get_buf()) == NULL) {
		return (-1);
	}

	cps = sbuff_data(b);
	if (sbuff_advance(b, sizeof (*cps)) < 0) {
		DBG(dbg, "buffer too small");
		goto done;
	}
	memset(cps, 0, sizeof (*cps));

	cps->type = ICMP6_SND_CPS;
	cps->id = htons(id);
	cps->component = htons(SND_ALL_COMPONENTS);

	for (i = 0; i < sk_num(snd_trustanchors); i++) {
		x = sk_X509_value(snd_trustanchors, i);
		if (snd_add_trustanchor_opt(b, x) < 0) {
			goto done;
		}

		DBG(dbg, "added trust anchor: %s",
		    snd_x509_name(x, nbuf, sizeof (nbuf)));
	}

	memset(sin6, 0, sizeof (*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = *to;
	sin6->sin6_port = htons(IPPROTO_ICMPV6);

	if (snd_send_icmp(b, sin6, ifidx) == 0) {
		r = 0;
	}

done:
	snd_put_buf(b);
	return (r);
}

static uint16_t
make_cp_id(void)
{
	int r = rand() >> 16;

	while ((r = rand()) == 0)
		;
	return (1 + (int)(65535.0 * r / (RAND_MAX + 1.0)));
}

static void
cpr_notify(uint16_t id, int empty)
{
	struct list_head *pos, *n;
	struct snd_cpr *cpr;

	pthread_mutex_lock(&cprs_lock);
	list_for_each_safe(pos, n, &cprs) {
		cpr = list_entry(pos, struct snd_cpr, list);

		if (cpr->id != id && id != 0) {
			continue;
		}

		DBG(dbg, "CPA from %s IF %d ID %hu empty %d",
		    inet_ntop(AF_INET6, &cpr->to, abuf, sizeof (abuf)),
		    cpr->ifidx, id, empty);

		if (snd_cert_rcvd(cpr->khash, cpr->ipb, cpr->pi, empty)) {
			DBG(dbg, "Finished with CPR");
			list_del(&cpr->list);
			free(cpr);
		}
	}
	pthread_mutex_unlock(&cprs_lock);
}

static int
is_response(uint16_t id)
{
	struct list_head *pos;
	struct snd_cpr *cpr;
	int r = 0;

	pthread_mutex_lock(&cprs_lock);
	list_for_each(pos, &cprs) {
		cpr = list_entry(pos, struct snd_cpr, list);
		if (id == cpr->id) {
			r = 1;
			break;
		}
	}
	pthread_mutex_unlock(&cprs_lock);

	return (r);
}

static void
add2reorder_cache(X509 *x)
{
	struct reorder_entry *re;

	pthread_mutex_lock(&reorder_lock);

	if (reorder_cnt > MAX_REORDERS) {
		re = list_entry(&reorders.prev, struct reorder_entry, list);
		list_del(&re->list);
		DBG(&dbg_snd, "reorder cache full; dropping %s",
		    X509_NAME_oneline(X509_get_subject_name(re->x), nbuf,
				      sizeof (nbuf)));

		X509_free(re->x);
		free(re);
		reorder_cnt--;
	}

	if ((re = malloc(sizeof (*re))) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		goto done;
	}

	re->x = x;
	list_add(&re->list, &reorders);
	reorder_cnt++;

	DBG(dbg, "added to reorder cache");

done:
	pthread_mutex_unlock(&reorder_lock);
}

static void
check_reorder_cache(void)
{
	struct reorder_entry *re;
	struct list_head *pos, *n;

	DBG(dbg, "");

	pthread_mutex_lock(&reorder_lock);

	list_for_each_safe(pos, n, &reorders) {
		re = list_entry(pos, struct reorder_entry, list);
		if (pkixip_verify_cert(re->x, NULL) < 0) {
			continue;
		}

		DBG(dbg, "Cert verified!");
		pkixip_add2stores_cert(re->x);

		list_del(&re->list);
		free(re);
		reorder_cnt--;
	}

	pthread_mutex_unlock(&reorder_lock);
}

static int
interested_in_cpa(uint8_t *ops, int len)
{
	int i, r = 0;
	X509 *x;
	X509_NAME *dn;
	STACK_OF(X509_NAME) *dns;

	if (sk_num(snd_trustanchors) == 0) {
		return (1);
	}

	if ((dns = snd_get_trustanchors_from_opts(ops, len)) == NULL) {
		return (1);
	}
	if (sk_num(dns) == 0) {
		sk_free(dns);
		return (1);
	}
	/* We only expect one opt here */
	dn = sk_X509_NAME_value(dns, 0);

	for (i = 0; i < sk_num(snd_trustanchors); i++) {
		x = sk_X509_value(snd_trustanchors, i);
		if (X509_NAME_cmp(X509_get_subject_name(x), dn) == 0) {
			DBG(dbg, "trust anchor matches one of ours");
			r = 1;
			break;
		}
	}
	sk_X509_NAME_pop_free(dns, X509_NAME_free);

	return (r);
}

/*
 * We offload this to a prioritized thrpool so that we can give
 * processing priority to CPAs that appear to have been sent in
 * response to a CPS that we sent (according on the ID). Responses
 * get a higher priority, so if we are being blasted with CPAs
 * in an attempted DOS attack, it is more likely that legitimate
 * CPAs will still be processed. The following code is where the
 * heavy lifting takes place.
 */
static void
handle_cpa_thr(void *a)
{
	struct cpa_info *dp = a;

	DBG(dbg, "Verifying new cert");
	if (pkixip_verify_cert(dp->x, NULL) < 0) {
		add2reorder_cache(dp->x);
		free(dp);
		return;
	}

	/*
	 * Any error here could be a soft error (such as cert already in
	 * store), so we don't check the return value.
	 */
	DBG(dbg, "Adding new cert to stores");
	pkixip_add2stores_cert(dp->x);

	check_reorder_cache();

	cpr_notify(dp->id, 0);
	free(dp);
}

void
snd_handle_cpa(struct sbuff *b, struct sockaddr_in6 *from)
{
	uint8_t *msg = sbuff_data(b);
	int len = b->len;
	struct snd_cpa *cpa = (struct snd_cpa *)msg;
	uint8_t *p, *op;
	X509 *x;
	int clen;
	uint16_t id;
	uint8_t *ops;
	int olen;
	int prio;
	struct cpa_info *dp;

	DBG(dbg, "");

	if (len < sizeof (*cpa)) {
		DBG(dbg, "CPA too short (%d)", len);
		return;
	}

	id = ntohs(cpa->id);

	ops = msg + sizeof (*cpa);
	olen = len - sizeof (*cpa);

	if ((op = snd_get_opt(ops, olen, ND_OPT_CERTIFICATE)) == NULL) {
		DBG(&dbg_snd, "No certificate option");
		cpr_notify(id, 1);
		return;
	}

	p = op;
	p += sizeof (struct snd_opt_cert);
	clen = op[1] << 3;
	DBG(dbg, "DER cert opt len=%d", clen);
	if ((x = d2i_X509(NULL,
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
			  (const unsigned char **)
#endif
			  &p, clen)) == NULL) {
		DBG(&dbg_snd, "d2i_X509() failed");
		return;
	}
	DBG(dbg, "cert: %s", snd_x509_name(x, nbuf, sizeof (nbuf)));

	if (!interested_in_cpa(ops, olen)) {
		DBG(dbg, "not interested");
		X509_free(x);
		return;
	}

	if ((dp = malloc(sizeof (*dp))) == NULL) {
		applog(LOG_CRIT, "%s: no memory; dropping CPA", __FUNCTION__);
		return;
	}
	dp->x = x;
	dp->id = id;
	prio = SND_THR_PRIO_IN;
	if (is_response(id)) {
		DBG(dbg, "is a response");
		prio += SND_THR_PRIO_RESP;
	} else {
		DBG(dbg, "is not a response");
	}

	DBG(dbg, "Handing off to thrpool, prio %d", prio);
	if (thrpool_req(handle_cpa_thr, dp, NULL, prio) < 0) {
		DBG(&dbg_snd, "thrpool_req() failed; dropping request");
		free(dp);
	}
}

int
snd_make_cps(uint8_t *khash, void *x, void *ipbp, struct in6_addr *to,
    int ifidx, void *pi)
{
	struct snd_cpr *cpr;
	IPAddrBlocks *ipb = ipbp;

	/* Create a record of this request */
	if ((cpr = malloc(sizeof (*cpr))) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (-1);
	}
	memcpy(cpr->khash, khash, sizeof (cpr->khash));
	cpr->x = x;
	cpr->ipb = ipb;
	cpr->to = *to;
	cpr->ifidx = ifidx;
	cpr->id = make_cp_id();
	cpr->pi = pi;

	pthread_mutex_lock(&cprs_lock);
	list_add(&cpr->list, &cprs);
	pthread_mutex_unlock(&cprs_lock);

	if (send_cps(to, ifidx, cpr->id) < 0) {
		list_del(&cpr->list);
		free(cpr);
		return (-1);
	}

	return (0);
}

