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
 * Checks nonce validity by caching.
 * There are two nonce caches managed by this file:
 * Solicit cache - caches nonces for solicits sent from this host. All
 *		incoming adverts are checked against this cache.
 * Advert cache - caches nonces for solicits received by this host.
 *		When a valid solicit is received, its nonce is stored
 *		the advert cache. When sendd gets an outgoing advert,
 *		it pulls the corresponding nonce from the advert cache.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>

#include "config.h"
#include <applog.h>
#include <hashtbl.h>
#include <timer.h>

#include "sendd_local.h"
#include "snd_proto.h"
#include "snd_config.h"
#include "os_specific.h"
#include "dbg.h"

#ifdef	DEBUG
#include <arpa/inet.h>
static char abuf[INET6_ADDRSTRLEN];

static struct dlog_desc dbg = {
	.desc = "nonce",
	.ctx = SENDD_NAME
};
#else
#ifdef	USE_CONSOLE
#include <arpa/inet.h>
static char abuf[INET6_ADDRSTRLEN];
#endif
#endif

struct snd_solicit_ent {
	struct in6_addr		tgt;
	int			ifidx;
	htbl_item_t		hit;
	time_t			exp;
	uint8_t			nonce[SND_NONCE_LEN];
};

/*
 * Solicit cache needs to be locked, since sig threads will remove the
 * entry after checking the sig.
 */
static htbl_t *solicit_cache;
static pthread_mutex_t solicit_cache_lock = PTHREAD_MUTEX_INITIALIZER;

struct snd_advert_tgt {
	struct in6_addr		tgt;
	struct list_head	list;
	time_t			exp;
	int			nlen;
	uint8_t			nonce[];
};

struct snd_advert_ent {
	struct in6_addr		src;
	int			ifidx;
	struct list_head	tgts; /* list of snd_advert_tgt */
	htbl_item_t		hit;
};

/*
 * Advert cache also needs to be locked
 */
static htbl_t *advert_cache;
static pthread_mutex_t advert_cache_lock = PTHREAD_MUTEX_INITIALIZER;

/* garbage collection state */
static int ent_cnt;
static timer_item_t gc_timer_item;
static void set_gc_timer(void);

static void
gc_solicit_walker(void *p, void *c)
{
	struct snd_solicit_ent *ep = p;
	struct timeval *now = c;

	DBG(&dbg, "%s (ifidx %d)",
	    inet_ntop(AF_INET6, &ep->tgt, abuf, sizeof (abuf)), ep->ifidx);

	if (ep->exp < now->tv_sec) {
		htbl_rem_hit(solicit_cache, &ep->hit);
		free(ep);
		DBG(&dbg, "expired");
	} else {
		ent_cnt++;
	}
}

static void
gc_advert_walker(void *p, void *c)
{
	struct snd_advert_ent *ep = p;
	struct timeval *now = c;
	struct snd_advert_tgt *tp, *n;

	DBG(&dbg, "%s (ifidx %d)",
	    inet_ntop(AF_INET6, &ep->src, abuf, sizeof (abuf)), ep->ifidx);

	list_for_each_entry_safe(tp, n, &ep->tgts, list) {
		DBG(&dbg, "\t%s %s",
		    inet_ntop(AF_INET6, &tp->tgt, abuf, sizeof (abuf)),
		    tp->exp < now->tv_sec ? "(expired)" : "");

		if (tp->exp < now->tv_sec) {
			list_del(&tp->list);
			free(tp);
		}
	}

	if (list_empty(&ep->tgts)) {
		DBG(&dbg, "All targets gone; removing entry");
		htbl_rem_hit(advert_cache, &ep->hit);
		free(ep);
	} else {
		ent_cnt++;
	}
}

static void
nonce_gc_timer(void *a)
{
	struct timeval now[1];
	DBG(&dbg, "");

	gettimeofday(now, NULL);
	ent_cnt = 0;

	pthread_mutex_lock(&solicit_cache_lock);
	htbl_walk(solicit_cache, gc_solicit_walker, now);
	pthread_mutex_unlock(&solicit_cache_lock);

	pthread_mutex_lock(&advert_cache_lock);
	htbl_walk(advert_cache, gc_advert_walker, now);
	pthread_mutex_unlock(&advert_cache_lock);

	if (ent_cnt > 0) {
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

	tv->tv_sec = snd_conf_get_int(snd_nonce_cache_gc_intvl);
	tv->tv_usec = 0;
	timer_set(tv, nonce_gc_timer, NULL, &gc_timer_item);
	DBG(&dbg, "next gc in %d seconds",
	    snd_conf_get_int(snd_nonce_cache_gc_intvl));
}

/*
 * hash and match functions can be used for both advert and solicit
 * entries, since the functions only look at the first two members,
 * which are the same for both structures.
 */
static uint32_t
hash_ent(void *a, int sz)
{
	struct snd_solicit_ent *p = a;
	return (hash_in6_addr(&p->tgt, sz));
}

static int
match_ent(void *a, void *b)
{
	struct snd_solicit_ent *x = a;
	struct snd_solicit_ent *y = b;

	if (x->ifidx != y->ifidx) {
		return (x->ifidx - y->ifidx);
	}
	return (memcmp(&x->tgt, &y->tgt, sizeof (x->tgt)));
}

/*
 * Looks up a nonce value and returns it in nonce. If add is set and the
 * target is not found, this atomically adds a new entry with the nonce
 * provided in nonce. If add is 0, returns 0 if the nonce was found,
 * -1 if not found. If add is non-zero, returns -1 on memory failure,
 * 0 on success.
 */
static int
get_solicit_nonce(struct in6_addr *tgt, int ifidx, uint8_t *nonce, int add)
{
	struct snd_solicit_ent *se, k[1];
	struct timeval tv[1];
	int r = -1;

	memcpy(&k->tgt, tgt, sizeof (k->tgt));
	k->ifidx = ifidx;

	pthread_mutex_lock(&solicit_cache_lock);

	if ((se = htbl_find(solicit_cache, k)) != NULL) {
		/* reuse existing nonce */
		memcpy(nonce, se->nonce, SND_NONCE_LEN);
		r = 0;
		goto done;
	} else if (!add) {
		goto done;
	}

	/* add a new entry */
	if ((se = malloc(sizeof (*se))) == NULL) {
		APPLOG_NOMEM();
		goto done;
	}
	memset(se, 0, sizeof (*se));
	memcpy(&se->tgt, tgt, sizeof (se->tgt));
	se->ifidx = ifidx;
	memcpy(se->nonce, nonce, sizeof (se->nonce));
	gettimeofday(tv, NULL);
	se->exp = tv->tv_sec + snd_sol_nonce_cache_life;
	set_gc_timer();

	htbl_add(solicit_cache, se, &se->hit);
	r = 0;

done:
	pthread_mutex_unlock(&solicit_cache_lock);
	return (r);
}

static int
add_advert_tgt(struct snd_advert_ent *ep, struct in6_addr *tgt, uint8_t *nonce,
    int nlen)
{
	struct snd_advert_tgt *tp;

	if ((tp = malloc(sizeof (*tp) + nlen)) == NULL) {
		APPLOG_NOMEM();
		return (-1);
	}
	memset(tp, 0, sizeof (*tp));
	if (tgt != NULL) {
		memcpy(&tp->tgt, tgt, sizeof (tp->tgt));
	}
	memcpy(tp->nonce, nonce, nlen);
	tp->nlen = nlen;
	list_add_tail(&tp->list, &ep->tgts);

	return (0);
}

static int
replace_nonce(struct snd_advert_ent *ep, struct snd_advert_tgt *tp,
    uint8_t *nonce, int nlen)
{
	int r;

	if (tp->nlen == nlen) {
		memcpy(tp->nonce, nonce, nlen);
		return (0);
	}

	/* need to replace old entry */
	list_del(&tp->list);
	r = add_advert_tgt(ep, &tp->tgt, nonce, nlen);
	free(tp);
	return (r);
}

static struct snd_advert_tgt *
find_advert_tgt(struct snd_advert_ent *ep, struct in6_addr *tgt)
{
	struct snd_advert_tgt *tp;
	struct in6_addr zero[1];

	if (tgt == NULL) {
		memset(zero, 0, sizeof (*zero));
		tgt = zero;
	}

	list_for_each_entry(tp, &ep->tgts, list) {
		if (memcmp(&tp->tgt, tgt, sizeof (*tgt)) == 0) {
			return (tp);
		}
	}
	return (NULL);
}

static void
free_advert_ent(void *p)
{
	struct snd_advert_ent *ep = p;
	struct snd_advert_tgt *tp, *n;

	list_for_each_entry_safe(tp, n, &ep->tgts, list) {
		list_del(&tp->list);
		free(tp);
	}
	free(ep);
}

void
snd_del_solicit_ent(struct in6_addr *tgt, int ifidx)
{
	struct snd_solicit_ent se[1], *ep;

	memcpy(&se->tgt, tgt, sizeof (se->tgt));
	se->ifidx = ifidx;

	pthread_mutex_lock(&solicit_cache_lock);
	if ((ep = htbl_rem(solicit_cache, se)) != NULL) {
		free(ep);
	}
	pthread_mutex_unlock(&solicit_cache_lock);
}

/*
 * tgt can be NULL in case of RS.
 */
int
snd_add_advert_nonce(struct in6_addr *src, struct in6_addr *tgt, int ifidx,
    uint8_t *nonce, int nlen)
{
	struct snd_advert_ent *ep, k[1];
	struct snd_advert_tgt *tp;
	int r = -1;

	memcpy(&k->src, src, sizeof (k->src));
	k->ifidx = ifidx;

	pthread_mutex_lock(&advert_cache_lock);

	if ((ep = htbl_find(advert_cache, k)) != NULL) {
		if ((tp = find_advert_tgt(ep, tgt)) != NULL) {
			r = replace_nonce(ep, tp, nonce, nlen);
			goto done;
		}
		/* add new target entry */
		r = add_advert_tgt(ep, tgt, nonce, nlen);
		goto done;
	}

	if ((ep = malloc(sizeof (*ep))) == NULL) {
		APPLOG_NOMEM();
		goto done;
	}

	memset(ep, 0, sizeof (*ep));
	memcpy(&ep->src, src, sizeof (ep->src));
	ep->ifidx = ifidx;
	INIT_LIST_HEAD(&ep->tgts);
	if (add_advert_tgt(ep, tgt, nonce, nlen) < 0) {
		free(ep);
		goto done;
	}

	htbl_add(advert_cache, ep, &ep->hit);
	r = 0;

done:
	pthread_mutex_unlock(&advert_cache_lock);

	return (r);
}

static struct snd_advert_tgt *
get_advert_nonce(struct in6_addr *src, struct in6_addr *tgt, int ifidx)
{
	struct snd_advert_ent *ep, k[1];
	struct snd_advert_tgt *tp;

	memcpy(&k->src, src, sizeof (k->src));
	k->ifidx = ifidx;

	pthread_mutex_lock(&advert_cache_lock);

	if ((ep = htbl_find(advert_cache, k)) != NULL) {
		if ((tp = find_advert_tgt(ep, tgt)) != NULL) {
			list_del(&tp->list);
			if (list_empty(&ep->tgts)) {
				htbl_rem_hit(advert_cache, &ep->hit);
				free_advert_ent(ep);
			}
			goto done;
		}
	}
	tp = NULL;

done:
	pthread_mutex_unlock(&advert_cache_lock);
	return (tp);
}

int
snd_proto_add_solicit_nonce(struct sbuff *b, struct in6_addr *tgt, int ifidx)
{
	uint8_t nonce[SND_NONCE_LEN];

	os_specific_get_rand_bytes(nonce, sizeof (nonce));
	if (get_solicit_nonce(tgt, ifidx, nonce, 1) < 0) {
		return (-1);
	}
	DBG(&dbg, "tgt: %s",
	    tgt ? inet_ntop(AF_INET6, tgt, abuf, sizeof (abuf)) : "<null>");
	DBG_HEXDUMP(&dbg, "nonce", nonce, SND_NONCE_LEN);

	return (snd_add_nonce_opt(b, nonce, SND_NONCE_LEN));
}

int
snd_proto_check_solicit_nonce(struct in6_addr *tgt, int ifidx, uint8_t *opt)
{
	uint8_t *nonce, sent_nonce[SND_NONCE_LEN];
	int olen;

	olen = opt[1] << 3;
	nonce = opt + 2;

	DBG(&dbg, "tgt: %s",
	    tgt ? inet_ntop(AF_INET6, tgt, abuf, sizeof (abuf)) : "<null>");
	DBG_HEXDUMP(&dbg, "nonce", nonce, olen - 2);

	if ((olen - 2) != SND_NONCE_LEN) {
		DBG(&dbg_snd, "option nonce length is wrong (%d / %d)",
		    olen - 2, SND_NONCE_LEN);
		return (-1);
	}

	if (get_solicit_nonce(tgt, ifidx, sent_nonce, 0) < 0) {
		DBG(&dbg_snd, "Can't find original nonce");
		return (-1);
	}
	if (memcmp(sent_nonce, nonce, SND_NONCE_LEN) != 0) {
		DBG(&dbg_snd, "nonces do not match");
		DBG_HEXDUMP(&dbg_snd, "original nonce", sent_nonce,
			    SND_NONCE_LEN);
		return (-1);
	}

	DBG(&dbg, "verify nonce: ok");
	return (0);
}

int
snd_proto_cache_nonce(struct in6_addr *src, struct in6_addr *tgt, int ifidx,
    uint8_t *opt)
{
	uint8_t *nonce;
	int olen;

	olen = opt[1] << 3;
	nonce = opt + 2;

	DBG(&dbg, "src: %s (%d)",
	    inet_ntop(AF_INET6, src, abuf, sizeof (abuf)), ifidx);
	DBG(&dbg, "tgt: %s",
	    tgt ? inet_ntop(AF_INET6, tgt, abuf, sizeof (abuf)) : "<null>");
	DBG_HEXDUMP(&dbg, "nonce", nonce, olen - 2);
	return (snd_add_advert_nonce(src, tgt, ifidx, nonce, olen - 2));
}

int
snd_proto_add_advert_nonce(struct sbuff *b, struct in6_addr *src,
    struct in6_addr *tgt, int ifidx)
{
	struct snd_advert_tgt *tp;
	int r;

	DBG(&dbg, "src: %s (%d)",
	    inet_ntop(AF_INET6, src, abuf, sizeof (abuf)), ifidx);
	DBG(&dbg, "tgt: %s",
	    tgt ? inet_ntop(AF_INET6, tgt, abuf, sizeof (abuf)) : "<null>");

	if ((tp = get_advert_nonce(src, tgt, ifidx)) == NULL) {
		DBG(&dbg_snd, "no cached nonce found");
		/* try to send anyway */
		return (0);
	}

	DBG_HEXDUMP(&dbg, "nonce", tp->nonce, tp->nlen);
	r = snd_add_nonce_opt(b, tp->nonce, tp->nlen);
	free(tp);
	return (r);
}

#ifdef	USE_CONSOLE
static void
solicit_dump_walker(void *p, void *c)
{
	struct snd_solicit_ent *sp = p;
	char nbuf[256];

	printf("\t%s (ifidx %d)\n",
	       inet_ntop(AF_INET6, &sp->tgt, abuf, sizeof (abuf)),
	       sp->ifidx);
	printf("\t\tnonce: %s\n", mac2str_r(sp->nonce, SND_NONCE_LEN, nbuf));
}

static void
advert_dump_walker(void *p, void *c)
{
	struct snd_advert_ent *ep;
	struct snd_advert_tgt *tp;
	char nbuf[256];

	ep = (struct snd_advert_ent *)p;
	printf("\t%s (ifidx %d)\n",
	       inet_ntop(AF_INET6, &ep->src, abuf, sizeof (abuf)),
	       ep->ifidx);
	list_for_each_entry(tp, &ep->tgts, list) {
		printf("\t    %s\n",
		       inet_ntop(AF_INET6, &tp->tgt, abuf, sizeof (*abuf)));
		printf("\t\tnonce: %s\n",
		       mac2str_r(tp->nonce, sizeof (nbuf) / 4, nbuf));
	}
}

void
dump_solicit_cache(void)
{
	pthread_mutex_lock(&solicit_cache_lock);
	htbl_walk(solicit_cache, solicit_dump_walker, NULL);
	pthread_mutex_unlock(&solicit_cache_lock);
}

void
dump_advert_cache(void)
{
	pthread_mutex_lock(&advert_cache_lock);
	htbl_walk(advert_cache, advert_dump_walker, NULL);
	pthread_mutex_unlock(&advert_cache_lock);
}
#endif	/* USE_CONSOLE */

int
snd_proto_nonce_init(void)
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

	if ((solicit_cache = htbl_create(SND_HASH_SZ, hash_ent, match_ent))
	    == NULL) {
		applog(LOG_ERR, "%s: htbl_create() failed", __FUNCTION__);
		return (-1);
	}
	if ((advert_cache = htbl_create(SND_HASH_SZ, hash_ent, match_ent))
	    == NULL) {
		applog(LOG_ERR, "%s: htbl_create() failed", __FUNCTION__);
		return (-1);
	}

	return (0);
}

void
snd_proto_nonce_fini(void)
{
	DBG(&dbg, "");
	timer_clear(&gc_timer_item);
	if (solicit_cache) htbl_destroy(solicit_cache, free);
	if (advert_cache) htbl_destroy(advert_cache, free_advert_ent);
}
