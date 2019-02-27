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
#include <stdlib.h>
#include <sys/socket.h>
#include <net/if.h>

#include "config.h"
#include <libconfig.h>
#include <applog.h>

#include "sendd_local.h"
#include "snd_proto.h"
#include "snd_config.h"
#include "dbg.h"

/*
 * User-tunable configuration values are managed here. The values
 * are kept in an array of struct snd_conf; the ordering of the
 * values MUST match enum snd_conf_syms in snd_config.h. Upon
 * startup, snd_read_config() will do a sanity check on this and
 * return a fatal error if there is a problem.
 *
 * There is were default protocol values and other settings are
 * parsed and assigned. Of special note: The lifetime
 * of a timestamp cache entry (snd_timestamp_cache_life) should be no
 * less than the timestamp delta. Otherwise, an attacker could wait
 * for the timestamp cache entry to time out and be garbage collected,
 * and then replay a message. The replayed message would only be subject
 * to the stateless timestamp check, and hence would be accepted.
 */

/* String */
#define	SND_CFS(_sym, _val,_m)			\
	{ #_sym, .tu.v_str = _val, NULL, SND_CONF_P_STR, _m, _sym }

/* Integer value, parse as integer */
#define	SND_CFII(_sym, _val, _un, _m)				\
	{ #_sym, .tu.v_int = _val, _un, SND_CONF_P_INT, _m, _sym }

/* Integer value, parse as boolean */
#define	SND_CFIB(_sym, _val, _m)	\
	{ #_sym, .tu.v_int = _val, NULL, SND_CONF_P_BOOL, _m, _sym }

struct snd_conf snd_confs[] = {
	SND_CFIB(snd_accept_unconstrained_ra, 0, 0),
	SND_CFIB(snd_addr_autoconf, 1, 0),
	SND_CFII(snd_adv_nonce_cache_life, 2, "seconds", 0),
	SND_CFII(snd_cga_minsec, 0, NULL, 0),
	SND_CFS(snd_cga_params, NULL, 1),
	SND_CFIB(snd_full_secure, 1, 0),
	SND_CFII(snd_min_key_bits, 1024, "bits", 0),
	SND_CFII(snd_nonce_cache_gc_intvl, 2, "seconds", 0),
	SND_CFII(snd_pfx_cache_gc_intvl, 40, "seconds", 0),
	SND_CFS(snd_pkixip_conf, NULL, 0),
	SND_CFIB(snd_replace_linklocals, 1, 0),
	SND_CFII(snd_sol_nonce_cache_life, 10, "seconds", 0),
	SND_CFII(snd_timestamp_cache_gc_intvl, 40, "seconds", 0),
	SND_CFII(snd_timestamp_cache_life, SND_TIMESTAMP_DELTA, "seconds", 0),
	SND_CFII(snd_timestamp_cache_max, 1024, "entries", 0),
	SND_CFII(snd_timestamp_delta, SND_TIMESTAMP_DELTA, "seconds", 0),
	SND_CFII(snd_timestamp_drift, 1, "percent", 0),
	SND_CFII(snd_timestamp_fuzz, 1, "seconds", 0),
#ifndef	NOTHREADS
	SND_CFII(snd_thrpool_max, 2, "threads", 0),
#endif
#ifdef	DEBUG
	SND_CFS(snd_debugs, NULL, 0),
#endif
	{ NULL }
};

struct snd_iface {
	const char	*name;
	int		ifidx;
	struct list_head list;
};
static DEFINE_LIST_HEAD(ifaces);

int
snd_iface_ok(int ifidx)
{
	struct snd_iface *p;

	if (list_empty(&ifaces)) {
		/* All interfaces active */
		return (1);
	}

	list_for_each_entry(p, &ifaces, list) {
		if (p->ifidx == ifidx) {
			return (1);
		}
	}
	return (0);
}

void
snd_dump_ifaces(void)
{
	struct snd_iface *p;

	if (list_empty(&ifaces)) {
		printf("\t\t<all>\n");
		return;
	}

	list_for_each_entry(p, &ifaces, list) {
		printf("\t\t%s (%d)\n", p->name, p->ifidx);
	}
}

int
snd_add_iface(const char *name)
{
	struct snd_iface *p;
	int ifidx;

	if ((ifidx = if_nametoindex(name)) == 0) {
		applog(LOG_ERR, "invalid interface: %s", name);
		return (-1);
	}
	if (!list_empty(&ifaces) && snd_iface_ok(ifidx)) {
		/* dup */
		return (0);
	}

	if ((p = malloc(sizeof (*p))) == NULL) {
		APPLOG_NOMEM();
		return (-1);
	}
	p->name = name;
	p->ifidx = ifidx;
	list_add_tail(&p->list, &ifaces);

	return (0);
}

int
snd_read_config(char *p)
{
	const char *v;
	int i, rv = 0;

	if ((rv = config_init(p)) != 0) {
		applog(LOG_ERR, "%s: config_init failed reading '%s': %s",
		       __FUNCTION__, p, strerror(errno));
		return (-1);
	}

	for (i = 0; snd_confs[i].sym != NULL; i++) {
		/*
		 * Sanity check - if the programmer has not kept 
		 * enum snd_conf_syms and snd_confs in sync, this
		 * will catch it.
		 */
		if (i != snd_confs[i].type) {
			applog(LOG_CRIT, "%s: programmer error: snd_conf_syms"
			       " and snd_confs not in sync! '%s' doesn't "
			       "match up", __FUNCTION__, snd_confs[i].sym);
			return (-1);
		}

		v = config_get(snd_confs[i].sym, NULL);
		if (v != NULL) {
			switch (snd_confs[i].parse) {
			case SND_CONF_P_INT:
				snd_conf_get_int(i) = atoi(v);
				break;
			case SND_CONF_P_STR:
				snd_conf_get_str(i) = v;
				break;
			case SND_CONF_P_BOOL:
				if (strncasecmp("no", v, 2) == 0) {
					snd_conf_get_int(i) = 0;
				} else {
					snd_conf_get_int(i) = 1;
				}
				break;
			default:
				applog(LOG_CRIT, "%s: internal error: "
				       "unhandled config type %d",
				       __FUNCTION__, snd_confs[i].parse);
				return (-1);
			}
		} else if (snd_confs[i].mandatory) {
			applog(LOG_ERR, "%s: missing mandatory config: '%s'",
			       __FUNCTION__, snd_confs[i].sym);
			rv = -1;
		}
	}

	return (rv);
}

void
snd_config_fini(void)
{
	config_fini();
}
