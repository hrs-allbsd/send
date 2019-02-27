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
 * Timestamp checking, and timestamp cache management.
 *
 * I have grave reservations about the use of a timestamp cache,
 * since coming up with a scheme that is robust at both preventing
 * replay attacks and is itself resistent to attack is tricky. The
 * problem is that the timestamp cache needs to keep state, and is
 * thus subject to (at least) resource draining attacks. Hardening
 * the cache against these attacks will likely entail a fancy,
 * complex scheme which then by virtue of its complexity makes it
 * more likely to have bugs or hidden soft spots. All this is so
 * that hosts without well-synchronized clocks can communicate. IMHO
 * it would be better to simply require hosts using SEND to keep
 * their clocks in sync (i.e. run NTP or something).
 *
 * However, RFC3971 pretty much requires a timestamp cache, so we
 * implement one here. Our approach is to classify cache entries
 * according to the sec value in the CGA, cap the number of possible
 * cache entries, and toss out those with the lowest sec value when
 * the cache becomes full. The rational behind this approach is that 
 * one easy, effective way to attack the cache is to generate lots
 * of CGAs and fill up a victim's cache, thus purging it of legitimate
 * entries and / or draining the victim's memory resources. This
 * scheme in this implementation should make this sort of attack more
 * difficult and time-consuming. However, this scheme could be no doubt
 * be greatly improved.
 *
 * This cache also mirrors the kernel's neighbor cache. If sendd is
 * running in mixed mode (i.e. it accepts unsecured ND messages), before
 * passing them to the kernel it checks this cache to ensure that the
 * unsecured ND will not overwrite a secured ND. This is how we implement
 * the "secure" neighbor cache flag without modifying the kernel's
 * neighbor cache implementation. Note: this works because only secured,
 * verified ND messages are ever put in this cache.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "config.h"
#include <applog.h>
#include <hashtbl.h>
#include <timer.h>
#include <cga.h>

#include "sendd_local.h"
#include "snd_proto.h"
#include "snd_config.h"
#include "os/os_defines.h"
#include "dbg.h"

#ifdef	DEBUG
static char abuf[INET6_ADDRSTRLEN];

static struct dlog_desc dbg = {
	.desc = "timestamp_cache",
	.ctx = SENDD_NAME
};
#endif

#define	TS_SECS(__ts)	(__ts >> 16)
#define	TS_FRAC(__ts)	(__ts & 0xffff)
#define	TS_PRINT(__ts)	TS_SECS(__ts), TS_FRAC(__ts)

struct snd_timestamp_ent {
	struct in6_addr		addr;
	uint64_t		rdlast;
	uint64_t		tslast;
	htbl_item_t		hit;
	struct list_head	dlist;
	time_t			exp;
	int			ifidx;
};

static struct list_head drop_lists[CGA_MAX_SEC];
static htbl_t *timestamp_cache;
static pthread_mutex_t cachelock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t cache_cnt;

/* garbage collection state */
static timer_item_t gc_timer_item;
static void set_gc_timer(void);

static uint32_t
hash_ent(void *a, int sz)
{
	struct snd_timestamp_ent *p = a;
	return (hash_in6_addr(&p->addr, sz));
}

static int
match_ent(void *a, void *b)
{
	struct snd_timestamp_ent *x = a;
	struct snd_timestamp_ent *y = b;

	if (x->ifidx != y->ifidx) {
		return (x->ifidx - y->ifidx);
	}
	return (memcmp(&x->addr, &y->addr, sizeof (x->addr)));
}

static void
gc_timestamp_walker(void *a, void *c)
{
	struct snd_timestamp_ent *tp = a;
	struct timeval *now = c;

	DBG(&dbg, "%s (ifidx %d)",
	    inet_ntop(AF_INET6, &tp->addr, abuf, sizeof (abuf)), tp->ifidx);

	if (tp->exp < now->tv_sec) {
		list_del(&tp->dlist);
		htbl_rem_hit(timestamp_cache, &tp->hit);
		free(tp);
		cache_cnt--;
		DBG(&dbg, "expired");
	}
}

static void
timestamp_gc_timer(void *a)
{
	struct timeval now[1];

	DBG(&dbg, "");

	gettimeofday(now, NULL);

	pthread_mutex_lock(&cachelock);
	htbl_walk(timestamp_cache, gc_timestamp_walker, now);
	pthread_mutex_unlock(&cachelock);

	if (cache_cnt > 0) {
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

	tv->tv_sec = snd_conf_get_int(snd_timestamp_cache_gc_intvl);
	tv->tv_usec = 0;
	timer_set(tv, timestamp_gc_timer, NULL, &gc_timer_item);
	DBG(&dbg, "next gc in %d seconds",
	    snd_conf_get_int(snd_timestamp_cache_gc_intvl));
}

/*
 * When the cache is full, remove a lower-sec entry and reuse its
 * memory rather then free-ing and allocating a new entry.
 * Caller must hold cachelock.
 *
 * Returns a uninitialized entry on success, NULL if no suitable
 * entries can be found to remove.
 */
static struct snd_timestamp_ent *
reuse_lower_sec_ent(int sec)
{
	int i;
	struct snd_timestamp_ent *tp, *n;

	for (i = 0; i < sec && i < CGA_MAX_SEC; i++) {
		list_for_each_entry_safe(tp, n, drop_lists + i, dlist) {
			/* grab the first available entry */
			list_del(&tp->dlist);
			htbl_rem_hit(timestamp_cache, &tp->hit);
			cache_cnt--;
			return (tp);
		}
	}

	return (NULL);
}

/*
 * secure = 0: Only prevent overriding a secure neighbor cache entry
 * secure = 1: Check timestamp
 * secure = 2: Only parse timestamp; don't check it.
 */
int
snd_check_timestamp(struct in6_addr *src, int ifidx, uint8_t *opt,
    uint64_t *tsp, uint64_t *nowp, int secure)
{
	struct snd_opt_timestamp *to = (struct snd_opt_timestamp *)opt;
	struct timeval tv[1];
	uint64_t ts = 0;
	uint64_t now = 0;
	int64_t fuzz, diff, delta = snd_timestamp_get_delta();
	uint16_t fr;
	struct snd_timestamp_ent *tp, k[1];
	int drift, r = -1;

	DBG(&dbg, "%s (%d)", inet_ntop(AF_INET6, src, abuf, sizeof (abuf)),
	    ifidx);

	if (secure) {
		gettimeofday(tv, NULL);

		/*
		 * Convert to send timestamp format for comparison.
		 * first 48 bits are integer number of seconds since
		 * epoch time
		 */
		now = tv->tv_sec;
		now <<= 16;
		/* Last 16 bits are fractions of a second */
		fr = tv->tv_usec >> 4;
		now += fr;

		ts = ntoh64(to->ts);
		*tsp = ts;
		*nowp = now;

		if (secure == 2) {
			return (0);
		}
	}

	/* Look up entry in cache */
	memcpy(&k->addr, src, sizeof (k->addr));
	k->ifidx = ifidx;

	pthread_mutex_lock(&cachelock);

	tp = htbl_find(timestamp_cache, k);

	/*
	 * Ensure unsecured ND won't override secured ND. If we find
	 * an entry for this and this is an unsecured ND, that means
	 * that there is already a secured ND entry in the cache -
	 * so drop the unsecured ND. Otherwise, it is OK to let it
	 * pass.
	 */
	if (!secure) {
		DBG(&dbg_snd, "unsecured ND: %s", tp ? "fail" : "pass");
		if (tp == NULL) {
			r = 0;
		}
		goto done;
	}

	if (tp == NULL) {
		diff = ts - now;

		DBG(&dbg, "now: %llu.%.5llu ts: %llu.%.5llu "
		    "diff: %lld.%.5lld, delta: %d.%.5d",
		    TS_PRINT(now), TS_PRINT(ts), TS_PRINT(diff),
		    TS_PRINT(delta));

		if (diff > delta || diff < -delta) {
			DBG(&dbg_snd, "timestamp out of allowed delta");
			/*
			 * RFC 3971 says this SHOULD be passed, but an
			 * a neighbor cache entry MUST NOT be created.
			 * However, since we don't have control over
			 * whether or not a neighbor cache will be created
			 * as a result of passing this packet, we instead
			 * choose to err on the side of paranoia and just
			 * reject the packet.
			 */
		} else {
			DBG(&dbg, "timestamp: ok");
			r = 0;
		}
	} else {
		drift = snd_conf_get_int(snd_timestamp_drift);
		fuzz = snd_timestamp_get_fuzz();
		ts += fuzz;
		diff = tp->tslast +
			(now - tp->rdlast) * (100 - drift) / 100;
		diff -= fuzz;

		DBG(&dbg, "%llu.%.5llu > %llu.%.5llu ?", TS_PRINT(ts),
		    TS_PRINT(diff));

		if (ts > diff) {
			DBG(&dbg, "timestamp: ok");
			r = 0;
		} else {
			DBG(&dbg_snd, "timestamp check failed");
		}
	}

done:
	pthread_mutex_unlock(&cachelock);
	return (r);
}

int
snd_timestamp_cache_upd(struct in6_addr *addr, int ifidx, uint64_t rdlast,
    uint64_t tslast)
{
	struct snd_timestamp_ent *tp, k[1];
	struct timeval now[1];
	int sec, r = -1;

	DBG(&dbg, "");

	memcpy(&k->addr, addr, sizeof (k->addr));
	k->ifidx = ifidx;
	sec = cga_get_sec(addr);

	pthread_mutex_lock(&cachelock);

	if ((tp = htbl_find(timestamp_cache, k)) != NULL) {
		tp->rdlast = rdlast;
		tp->tslast = tslast;
		r = 0;
		goto done;
	}

	/* Need to create a new entry */
	if (cache_cnt >= snd_conf_get_int(snd_timestamp_cache_max)) {
		if ((tp = reuse_lower_sec_ent(sec)) == NULL) {
			applog(LOG_WARNING, "%s: cache is full", __FUNCTION__);
			r = -1;
			goto done;
		}
	} else if ((tp = malloc(sizeof (*tp))) == NULL) {
		APPLOG_NOMEM();
		goto done;
	}
	memset(tp, 0, sizeof (*tp));
	memcpy(&tp->addr, addr, sizeof (tp->addr));
	tp->ifidx = ifidx;
	tp->rdlast = rdlast;
	tp->tslast = tslast;

	htbl_add(timestamp_cache, tp, &tp->hit);
	list_add_tail(&tp->dlist, drop_lists + sec);
	cache_cnt++;
	r = 0;

done:
	pthread_mutex_unlock(&cachelock);
	if (r == 0) {
		gettimeofday(now, NULL);
		tp->exp = now->tv_sec +
			snd_conf_get_int(snd_timestamp_cache_life);
		set_gc_timer();
	}
	return (r);
}

uint64_t
snd_timestamp_get_delta(void)
{
	uint64_t d = snd_conf_get_int(snd_timestamp_delta);
	return (d << 16);
}

uint64_t
snd_timestamp_get_fuzz(void)
{
	uint64_t d = snd_conf_get_int(snd_timestamp_fuzz);
	return (d << 16);
}

#ifdef	USE_CONSOLE
static void
dump_cache_ent(struct snd_timestamp_ent *tp)
{
	char abuf[INET6_ADDRSTRLEN];

	printf("\t    %s (ifidx %d)\n\t\trdlast %llu.%.5llu\n"
	       "\t\ttslast %llu.%.5llu\n",
	       inet_ntop(AF_INET6, &tp->addr, abuf, sizeof (abuf)),
	       tp->ifidx, TS_PRINT(tp->rdlast), TS_PRINT(tp->tslast));
}

void
dump_timestamp_cache(void)
{
	int i;
	struct snd_timestamp_ent *tp;

	if (cache_cnt) {
		printf("\t%d entr%s\n", cache_cnt,
		       cache_cnt > 1 ? "ies" : "y");
	}
	pthread_mutex_lock(&cachelock);
	for (i = 0; i < CGA_MAX_SEC; i++) {
		if (!list_empty(drop_lists + i)) {
			printf("\tsec %d\n", i);
		}
		list_for_each_entry(tp, drop_lists + i, dlist) {
			dump_cache_ent(tp);
		}
	}
	pthread_mutex_unlock(&cachelock);
}
#endif	/* USE_CONSOLE */

int
snd_proto_timestamp_init(void)
{
	int i;
#ifdef	DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg,
		NULL
	};

	if (snd_applog_register(dbgs) < 0) {
		return (-1);
	}
#endif

	for (i = 0; i < CGA_MAX_SEC; i++) {
		INIT_LIST_HEAD(drop_lists + i);
	}
	if ((timestamp_cache = htbl_create(SND_HASH_SZ, hash_ent, match_ent))
	    == NULL) {
		applog(LOG_ERR, "%s: htbl_create() failed", __FUNCTION__);
		return (-1);
	}

	return (0);
}

void
snd_proto_timestamp_fini(void)
{
	DBG(&dbg, "");

	if (timestamp_cache) htbl_destroy(timestamp_cache, free);
}
