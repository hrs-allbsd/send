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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "config.h"
#include <applog.h>

#ifndef	SND_OS_linux
#include <dnet.h>
#endif

#include "sendd_local.h"
#include "snd_config.h"
#include "os_specific.h"
#include "os/os_defines.h"
#include "dbg.h"

#ifdef	DEBUG
#include <arpa/inet.h>
static char abuf[INET6_ADDRSTRLEN];

static struct dlog_desc dbg = {
	.desc = "addrtbl",
	.ctx = SENDD_NAME
};
#endif

static DEFINE_LIST_HEAD(snd_non_cga_linklocals);

struct snd_ll_addr {
	struct in6_addr	addr;
	int		ifidx;
	struct list_head list;
};

static int
do_replace_linklocal(struct in6_addr *old, struct in6_addr *new, int ifidx)
{
	DBG(&dbg, "replacing %s",
	    inet_ntop(AF_INET6, old, abuf, sizeof (abuf)));

	if (os_specific_del_addr(old, ifidx, 64) < 0 ||
	    os_specific_add_addr(new, ifidx, 64, SND_LIFE_INF, SND_LIFE_INF)
	    < 0) {
		return (-1);
	}

	return (0);
}

static int
gen_linklocal_cga(struct in6_addr *addr, int ifidx)
{
	struct snd_cga_params *p;

	if ((p = snd_find_params_byifidx(ifidx)) == NULL) {
		return (-1);
	}

	/* set link local prefix */
	memset(addr, 0, sizeof (*addr));
	addr->s6_addr32[0] = htonl(0xfe800000);

	/* Generate same link-local for all interfaces */
	if (snd_cga_gen(addr, p) < 0) {
		DBG(&dbg, "snd_cga_gen() failed");
		return (-1);
	}
	DBG(&dbg, "generated address: %s",
	    inet_ntop(AF_INET6, addr, abuf, sizeof (abuf)));

	return (0);
}

/*
 * Since this is a user-space only implementation, we can't modify
 * now the kernel forms link-locals when it initializes the IPv6
 * stack. Instead, when this daemon starts up, we replace all non-CGA
 * link-locals with a CGA link-local. We re-use the same one so that
 * we won't need to find a new modifier for each address (this is the
 * same as for address autoconfiguration).
 */
static int
replace_linklocals(void)
{
	struct snd_ll_addr *ap, *n;
	struct in6_addr addr[1];

	list_for_each_entry_safe(ap, n, &snd_non_cga_linklocals, list) {
		if (gen_linklocal_cga(addr, ap->ifidx) < 0) {
			return (-1);
		}
		do_replace_linklocal(&ap->addr, addr, ap->ifidx);
		list_del(&ap->list);
		free(ap);
	}

	return (0);
}

static void
add_ll_addr(struct in6_addr *a, int ifidx)
{
	struct snd_ll_addr *ap;

	if ((ap = malloc(sizeof (*ap))) == NULL) {
		APPLOG_NOMEM();
		return;
	}
	memcpy(&ap->addr, a, sizeof (ap->addr));
	ap->ifidx = ifidx;
	list_add(&ap->list, &snd_non_cga_linklocals);
}

int
snd_replace_this_non_cga_linklocal(struct in6_addr *a, int ifidx)
{
	struct in6_addr addr[1];

	if (!snd_conf_get_int(snd_replace_linklocals)) {
		return (0);
	}
	if (gen_linklocal_cga(addr, ifidx) < 0 ||
	    do_replace_linklocal(a, addr, ifidx) < 0) {
		return (-1);
	}

	return (0);
}

int
snd_replace_non_cga_linklocals(void)
{
	if (snd_conf_get_int(snd_replace_linklocals) &&
	    !list_empty(&snd_non_cga_linklocals)) {
		return (replace_linklocals());
	}
	return (0);
}

static void
snd_cfg_addr(struct in6_addr *a, int plen, int ifidx)
{
	DBG(&dbg, "%s/%d (%d)",
	    inet_ntop(AF_INET6, a, abuf, sizeof (abuf)), plen, ifidx);

	if (IN6_IS_ADDR_LOOPBACK(a)) {
		DBG(&dbg, "skipping loopback");
		return;
	}

	if (plen != 64) {
		DBG(&dbg, "prefix length != 64 bits; skipping");
		return;
	}

	if (!snd_is_lcl_cga(a, ifidx)) {
		DBG(&dbg, "not CGA");
		if (snd_conf_get_int(snd_replace_linklocals) &&
		    IN6_IS_ADDR_LINKLOCAL(a)) {
			add_ll_addr(a, ifidx);
		}
		return;
	}
}

/*
 * libdnet (1.11) is currently broken on Linux - intf_loop fails on SUSE 10.0.
 * Until it is fixed, we use this workaround instead.
 */
#ifdef SND_OS_linux

static int
get_addrs(void)
{
	FILE *fp;
	struct in6_addr a;
	uint32_t ifidx, plen, scope, flags;
	char buf[128], ifname[32];
	int i, off, digit;

	if ((fp = fopen("/proc/net/if_inet6", "r")) == NULL) {
		applog(LOG_ERR, "%s: fopen(/proc/net/if_inet6): %s",
		       __FUNCTION__, strerror(errno));
		return (-1);
	}

	while (fgets(buf, sizeof (buf), fp) != NULL) {
		for (i = off = 0; i < 16; i++, off += 2) {
			sscanf(buf + off, "%02x", &digit);
			a.s6_addr[i] = digit;
		}
		sscanf(buf + off, "%02x %02x %02x %02x %32s\n",
		       &ifidx, &plen, &scope, &flags, ifname);
		snd_cfg_addr(&a, plen, ifidx);
	}

	fclose(fp);
	return (0);
}

#else	/* not SND_OS_linux */

static void
intf_cfg_addr(const struct addr *da, int ifidx)
{
	struct in6_addr *a = (struct in6_addr *)&da->addr_ip6;

	DBG(&dbg, "%s/%d (%d)",
	    inet_ntop(da->addr_type == ADDR_TYPE_IP6 ? AF_INET6 : AF_INET,
		      a, abuf, sizeof (abuf)), da->addr_bits, ifidx);

	if (da->addr_type != ADDR_TYPE_IP6) {
		DBG(&dbg, "skipping non-ipv6 addr");
		return;
	}

	/* XXX: embedded link local addr check */
	if (IN6_IS_ADDR_LINKLOCAL(a)) {
		a->s6_addr[2] = 0;
		a->s6_addr[3] = 0;
	}

	snd_cfg_addr(a, da->addr_bits, ifidx);
}

static int
intf_cb(const struct intf_entry *entry, void *c)
{
	int ifidx, i;

	DBG(&dbg, "%s", entry->intf_name);

	if ((ifidx = if_nametoindex(entry->intf_name)) == 0) {
		DBG(&dbg, "interface not found");
		return (0);
	}
	if (!snd_iface_ok(ifidx)) {
		DBG(&dbg, "SEND not configured on interface");
		return (0);
	}
	if (entry->intf_type != INTF_TYPE_ETH) {
		DBG(&dbg, "skipping non-ether style interface");
		return (0);
	}

	if (os_specific_handle_iface(entry->intf_name, ifidx) < 0) {
		return (-1);
	}

	intf_cfg_addr(&entry->intf_addr, ifidx);

	for (i = 0; i < entry->intf_alias_num; i++) {
		intf_cfg_addr(&entry->intf_alias_addrs[i], ifidx);
	}
	return (0);
}

static int
get_addrs(void)
{
	intf_t *intf;
	int r = -1;

	if ((intf = intf_open()) == NULL) {
		applog(LOG_ERR, "%s: intf_open: %s", __FUNCTION__,
		       strerror(errno));
		goto done;
	}

	if (intf_loop(intf, intf_cb, NULL) < 0) {
		applog(LOG_ERR, "%s: intf_loop: %s", __FUNCTION__,
		       strerror(errno));
		goto done;
	}

	r = 0;
done:
	intf_close(intf);
	return (r);
}
#endif	/* SND_OS_linux */

int
snd_addr_init(void)
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

	return (get_addrs());
}
