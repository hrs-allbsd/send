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
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/bpf.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/userpf.h>

#include "config.h"
#include <applog.h>

#include "../os_specific.h"
#include "../sendd_local.h"
#include "snd_macosx.h"

#ifdef	DEBUG
#include <arpa/inet.h>
static char abuf[INET6_ADDRSTRLEN]; // XXX
static struct dlog_desc dbg = {
	.desc = "userpf",
	.ctx = SENDD_NAME
};
#endif

/* Per-interface info */
struct upf_ifinfo {
	struct list_head list;
	char		name[32];
	int		ifidx;
	int		csock;
};
static DEFINE_LIST_HEAD(ifaces);

#ifndef	ARR_SZ
#define	ARR_SZ(a) (sizeof (a) / sizeof (*a))
#endif

#ifndef offsetof
#define	offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

static struct bpf_insn pf_prog_nd[] = {
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, offsetof(struct ip6_hdr, ip6_nxt)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_ICMPV6, 0, 4),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, sizeof (struct ip6_hdr)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ND_ROUTER_SOLICIT, 4, 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ND_ROUTER_ADVERT, 3, 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ND_NEIGHBOR_SOLICIT, 2, 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ND_NEIGHBOR_ADVERT, 1, 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ND_REDIRECT, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SND_MAX_PKT - sizeof (struct userpf_ipf_hdr)),
	BPF_STMT(BPF_RET+BPF_K, 0),
};

static struct upf_ifinfo *
find_iface_by_ifidx(int ifidx)
{
	struct upf_ifinfo *p;

	list_for_each_entry(p, &ifaces, list) {
		if (p->ifidx == 0 || p->ifidx == ifidx) {
			return (p);
		}
	}

	return (NULL);
}

static int
open_ctl_sock(void)
{
	int sd;
	struct ctl_info ctl;
	struct sockaddr_ctl sc;

	if ((sd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) < 0) {
		applog(LOG_ERR, "%s: socket(PF_SYSTEM, SOCK_DGRAM, "
		       "SYSPROTO_CONTROL): %s", __FUNCTION__, strerror(errno));
		return (-1);
	}

	bzero(&ctl, sizeof (ctl));
	strncpy(ctl.ctl_name, USERPF_ID, sizeof (ctl.ctl_name));
	if (ioctl(sd, CTLIOCGINFO, &ctl) < 0) {
		applog(LOG_ERR, "%s: ioctl(CTLIOCGINFO): %s", __FUNCTION__,
		       strerror(errno));
		if (errno == ENOENT) {
			applog(LOG_ERR, "%s: is the userpf kext loaded?",
			       __FUNCTION__);
		}
		close(sd);
		return (-1);
	}

	bzero(&sc, sizeof (sc));
	sc.sc_len = sizeof (sc);
	sc.sc_family = PF_SYSTEM;
	sc.ss_sysaddr = SYSPROTO_CONTROL;
	sc.sc_id = ctl.ctl_id;
	if (connect(sd, (void *)&sc, sizeof (sc)) < 0) {
		applog(LOG_ERR, "%s: connect(): %s", __FUNCTION__,
		       strerror(errno));
		close(sd);
		return (-1);
	}

	return (sd);
}

static int
open_ctl_socks(void)
{
	struct upf_ifinfo *p;

	list_for_each_entry(p, &ifaces, list) {
		if ((p->csock = open_ctl_sock()) < 0) {
			return (-1);
		}
	}

	return (0);
}

static int
set_filter(int sd, int ifidx)
{
	struct {
		struct userpf_ipf_spec fp;
		uint8_t prog[sizeof (pf_prog_nd)];
	} req;
	
	bzero(&req, sizeof (req));
	req.fp.dir = USERPF_DIR_BOTH;
	req.fp.ifidx = ifidx;
	req.fp.af = AF_INET6;
	req.fp.flags = USERPF_INFER_OUT_IFIDX;
	req.fp.bpf_cnt = ARR_SZ(pf_prog_nd);
	memcpy(req.prog, pf_prog_nd, sizeof (req.prog));
	
	if (setsockopt(sd, SYSPROTO_CONTROL, USERPF_IP_FILT, &req,
		       sizeof (req)) < 0) {
		applog(LOG_ERR, "%s: setsockopt(USERPF_IP_FILT): %s",
		       __FUNCTION__, strerror(errno));
		return (-1);
	}

	return (0);
}

static int
set_filters(void)
{
	struct upf_ifinfo *p;

	list_for_each_entry(p, &ifaces, list) {
		DBG(&dbg, "setting filter for %s (%d)", p->name, p->ifidx);
		if (set_filter(p->csock, p->ifidx) < 0) {
			return (-1);
		}
	}

	return (0);
}

/*
 * Extract the ifidx from the address (KAME-stack mechanism, link-local only),
 * normalize src and dst addrs by removing embedded ifidx, and
 * return the ifidx.
 */
static inline int
extract_ll_ifidx(struct ip6_hdr *ip6)
{
	struct in6_addr *a;
	uint16_t *p;
	int ifidx = 0;
	
	/* src addr */
	a = &ip6->ip6_src;
	if (IN6_IS_ADDR_LINKLOCAL(a)) {
		p = (uint16_t *)(a->s6_addr + 2);
		ifidx = ntohs(*p);
		*p = 0;
	}

	/* dst addr */
	a = &ip6->ip6_dst;
	if (IN6_IS_ADDR_MULTICAST(a) || IN6_IS_ADDR_LINKLOCAL(a)) {
		p = (uint16_t *)(a->s6_addr + 2);
		if (ifidx == 0) {
			ifidx = ntohs(*p);
		}
		*p = 0;
	}

	return (ifidx);
}

static inline void
set_ll_ifidx(struct ip6_hdr *ip6, uint16_t ifidx)
{
	struct in6_addr *a;
	uint16_t *p;

	/* src addr */
	a = &ip6->ip6_src;
	if (IN6_IS_ADDR_LINKLOCAL(a)) {
		p = (uint16_t *)(a->s6_addr + 2);
		*p = htons(ifidx);
	}

	/* dst addr */
	a = &ip6->ip6_dst;
	if (IN6_IS_ADDR_MULTICAST(a) || IN6_IS_ADDR_LINKLOCAL(a)) {
		p = (uint16_t *)(a->s6_addr + 2);
		*p = htons(ifidx);
	}
}

static void
userpf_recv_pkt(int sd)
{
	struct sbuff *b = snd_get_buf();
	struct userpf_ipf_hdr *hdr = sbuff_data(b);
	struct ip6_hdr *ip6;
	int in, ifidx;

	if ((b->len = recv(sd, b->head, b->rem, 0)) < 0) {
		applog(LOG_ERR, "%s: recv: %s", __FUNCTION__,
		       strerror(errno));
		snd_put_buf(b);
		return;
	}

	if ((hdr = sbuff_pull(b, sizeof (*hdr))) == NULL) {
		snd_put_buf(b);
		return;
	}

	/*
	 * Get ifidx - if link-local, we need to extract the
	 * ifidx from the address itself. This handles the case
	 * where different interfaces have the same link-local
	 * address; the kernel ifidx-infering code will not
	 * handle this correctly.
	 */
	ip6 = (struct ip6_hdr *)hdr->pkt;
	DBG(&dbg, "src %s",
	    inet_ntop(AF_INET6, &ip6->ip6_src, abuf, sizeof (abuf)));
	DBG(&dbg, "dst %s",
	    inet_ntop(AF_INET6, &ip6->ip6_dst, abuf, sizeof (abuf)));

	ifidx = extract_ll_ifidx(ip6);
	if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src) ||
	    IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		/* ifidx from address is more reliable */
		hdr->ifidx = ifidx;
	} else {
		/* ifidx is not in addr */
		ifidx = hdr->ifidx;
	}
	DBG(&dbg, "ifidx: %d pkt: %d %d", ifidx, b->len, hdr->pktlen);

	/* set direction */
	in = hdr->dir == USERPF_DIR_IN ? 1 : 0;

	/* hand packet off to SEND */
	snd_recv_pkt(b, ifidx, in, hdr);
}

int
os_specific_handle_iface(const char *ifname, int ifidx)
{
	struct upf_ifinfo *p;

	/* If all interfaces are configured for SEND, don't add specific
	 * filters for each interface - one filter with ifidx == 0 will
	 * handle all with better performance. When this function is
	 * passed ifidx == 0, it is special.
	 */
	if (ifidx != 0 && snd_iface_ok(0)) {
		return (0);
	}

	if ((p = malloc(sizeof (*p))) == NULL) {
		APPLOG_NOMEM();
		return (-1);
	}
	memset(p, 0, sizeof (*p));

	snprintf(p->name, sizeof (p->name), "%s", ifname);
	p->ifidx = ifidx;
	p->csock = -1;
	list_add_tail(&p->list, &ifaces);

	return (0);
}

void
os_specific_deliver_pkt(void *pkt, struct sbuff *b, int drop, int changed)
{
	struct userpf_ipf_hdr *hdr = pkt;
	struct upf_ifinfo *p;

	if (drop) {
		goto done;
	}

	if ((p = find_iface_by_ifidx(hdr->ifidx)) == NULL) {
		DBG(&dbg, "Can't find ifidx %s (%d)", hdr->ifname, hdr->ifidx);
		goto done;
	}

	hdr->changed = changed;

	/* If link-local or mcast, reset the ifidx into the IP6 header addrs */
	set_ll_ifidx(sbuff_data(b), hdr->ifidx);

	/* Rewind buffer to start at userpf_ipf_hdr */
	sbuff_reset_to(b, b->len + sizeof (*hdr));
	DBG(&dbg, "ifidx: %d pkt: %d", hdr->ifidx, b->len);

	/* Return to kernel */
	if (send(p->csock, b->head, b->len, 0) < 0) {
		applog(LOG_ERR, "%s: send: %s", __FUNCTION__,
		       strerror(errno));
	}

done:
	snd_put_buf(b);
}

void
os_specific_dispatch_fds(fd_set *fds)
{
	struct upf_ifinfo *p;

	list_for_each_entry(p, &ifaces, list) {
		if (FD_ISSET(p->csock, fds)) {
			userpf_recv_pkt(p->csock);
		}
	}
}

void
os_specific_add_fds(fd_set *fds, int *maxfd)
{
	struct upf_ifinfo *p;

	list_for_each_entry(p, &ifaces, list) {
		FD_SET(p->csock, fds);
		*maxfd = sendd_max(*maxfd, p->csock);
	}
}

int
macosx_userpf_init(void)
{
#ifdef	DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg,
		NULL
	};

	if (applog_register(dbgs) < 0) {
		return (-1);
	}
#endif

	if (list_empty(&ifaces)) {
		/* Configure filter on all interfaces */
		if (userpf_add_iface("all", 0) < 0) {
			return (-1);
		}
	}

	if (open_ctl_socks() < 0 ||
	    set_filters() < 0) {
		return (-1);
	}
	return (0);
}

void
macosx_userpf_fini(void)
{
	struct upf_ifinfo *p;

	list_for_each_entry(p, &ifaces, list) {
		close(p->csock);
	}
}
