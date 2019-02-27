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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/bpf.h>
#include <netgraph.h>
#include <netgraph/ng_socket.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_bpf.h>

#include "config.h"
#include <applog.h>
#include <list.h>
#include <sbuff.h>

#include "../sendd_local.h"
#include "../os_specific.h"
#include "../dbg.h"
#include "snd_freebsd.h"

#ifdef	DEBUG
static struct dlog_desc dbg = {
	.desc = "netgraph",
	.ctx = SENDD_NAME
};
#endif

/* Per-interface info */
struct ng_ifinfo {
	struct list_head list;
	char		name[32];
	int		ifidx;
	int		csock;
	int		dsock;
};
static DEFINE_LIST_HEAD(ifaces);

/* Data packet meta data */
struct ng_packet_info {
	struct ng_ifinfo *ifinfo;
	int		in;
};

/*
 * BPF allow all
 *
 * Generated with tcpdump
 */
static struct bpf_insn pf_prog_all[] = {
	{ 0x6, 0, 0, 0x00002000 },
};

/*
 * BPF rs / ra / ns / na / redirect
 *
 * Generated with:
 *
 * tcpdump -s 8192 -dd icmp6 and \(ip6[40] == 133 or ip6[40] == 134 \
 *	or ip6[40] == 135 or ip6[40] == 136 or ip6[40] == 137\)
 */
static struct bpf_insn pf_prog_nd[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 9, 0x000086dd },
	{ 0x30, 0, 0, 0x00000014 },
	{ 0x15, 0, 7, 0x0000003a },
	{ 0x30, 0, 0, 0x00000036 },
	{ 0x15, 4, 0, 0x00000085 },
	{ 0x15, 3, 0, 0x00000086 },
	{ 0x15, 2, 0, 0x00000087 },
	{ 0x15, 1, 0, 0x00000088 },
	{ 0x15, 0, 1, 0x00000089 },
	{ 0x6, 0, 0, 0x00002000 },
	{ 0x6, 0, 0, 0x00000000 },
};

/*
 * Read and display the next incoming control message
 */
void
MsgRead(int csock)
{
	struct ng_mesg *m, *m2;
	struct ng_mesg *ascii;
	char path[NG_PATHSIZ];

	/* Get incoming message (in binary form) */
	if (NgAllocRecvMsg(csock, &m, path) < 0) {
		DBG(&dbg, "%s: recv incoming message: %s", __FUNCTION__,
		    strerror(errno));
		return;
	}

	/* Ask originating node to convert message to ASCII */
	if (NgSendMsg(csock, path, NGM_GENERIC_COOKIE,
	      NGM_BINARY2ASCII, m, sizeof(*m) + m->header.arglen) < 0
	    || NgAllocRecvMsg(csock, &m2, NULL) < 0) {
		DBG(&dbg, "Rec'd %s %d from \"%s\":",
		    (m->header.flags & NGF_RESP) != 0 ? "response" : "command",
		    m->header.cmd, path);
		if (m->header.arglen == 0)
			DBG(&dbg, "No arguments");
		else
			DBG_HEXDUMP(&dbg, "", m->data, m->header.arglen);
		free(m);
		return;
	}

	/* Display message in ASCII form */
	free(m);
	ascii = (struct ng_mesg *)m2->data;
	DBG(&dbg, "Rec'd %s \"%s\" (%d) from \"%s\":",
	    (ascii->header.flags & NGF_RESP) != 0 ? "response" : "command",
	    ascii->header.cmdstr, ascii->header.cmd, path);
	if (*ascii->data != '\0')
		DBG(&dbg, "Args:\t%s", ascii->data);
	else
		DBG(&dbg, "No arguments");
	free(m2);
}

static int
create_bpf(const char *ifname, int csock)
{
	struct ngm_mkpeer mkp;
	struct ngm_connect con;
	struct ngm_name name;
	char nbuf[NG_PATHSIZ];

	/* Create BPF */
	snprintf(mkp.type, sizeof (mkp.type), "%s", "bpf");
	snprintf(mkp.ourhook, sizeof (mkp.ourhook), "%s", "lower");
	snprintf(mkp.peerhook, sizeof (mkp.peerhook), "%s", "tolower");

	/* Send message */
	snprintf(nbuf, sizeof (nbuf), "%s:", ifname);
	if (NgSendMsg(csock, nbuf, NGM_GENERIC_COOKIE,
		      NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
		applog(LOG_ERR, "%s: mkpeer %s: %s", __FUNCTION__, ifname,
		       strerror(errno));
		return (-1);
	}

	/* Name this node */
	snprintf(name.name, sizeof (name.name), "%s%s", "nd_bpf_", ifname);
	snprintf(nbuf, sizeof (nbuf), "%s:lower", ifname);
	if (NgSendMsg(csock, nbuf, NGM_GENERIC_COOKIE,
		      NGM_NAME, &name, sizeof(name)) < 0) {
		applog(LOG_ERR, "%s: name nd_bpf_%s: %s", __FUNCTION__,
		       ifname, strerror(errno));
		return (-1);
	}

	/* Connect to upper ether hook */
	snprintf(con.path, sizeof (con.path), "%s:", ifname);
	snprintf(con.ourhook, sizeof (con.ourhook), "%s", "toupper");
	snprintf(con.peerhook, sizeof (con.peerhook), "%s", "upper");

	snprintf(nbuf, sizeof (nbuf), "nd_bpf_%s:", ifname);
	if (NgSendMsg(csock, nbuf, NGM_GENERIC_COOKIE,
	    NGM_CONNECT, &con, sizeof(con)) < 0) {
		applog(LOG_ERR, "%s: send_connect_msg (toupper:%s): %s",
		       __FUNCTION__, ifname, strerror(errno));
		return (-1);
	}
	return (0);
}

static int
attach_snd(const char *ifname, int csock)
{
	struct ngm_connect con;

	/* Attach hook for incoming packets to bpf */
	snprintf(con.path, sizeof (con.path), "%s%s:", "nd_bpf_", ifname);
	snprintf(con.ourhook, sizeof (con.ourhook), "%s", "in");
	snprintf(con.peerhook, sizeof (con.peerhook), "%s", "in");

	if (NgSendMsg(csock, ".", NGM_GENERIC_COOKIE,
	    NGM_CONNECT, &con, sizeof(con)) < 0) {
		applog(LOG_ERR, "%s: send connect msg (lower %s)",
		       __FUNCTION__, ifname);
		return (-1);
	}

	/* Attach hook for outgoing packets to bpf */
	snprintf(con.path, sizeof (con.path), "%s%s:", "nd_bpf_", ifname);
	snprintf(con.ourhook, sizeof (con.ourhook), "%s", "out");
	snprintf(con.peerhook, sizeof (con.peerhook), "%s", "out");

	if (NgSendMsg(csock, ".", NGM_GENERIC_COOKIE,
	    NGM_CONNECT, &con, sizeof(con)) < 0) {
		applog(LOG_ERR, "%s: send connect msg (upper %s)",
		       __FUNCTION__, ifname);
		return (-1);
	}
	return (0);
}

static int
attach_one_bpf(const char *path, const char *this, const char *match,
    const char *notmatch, void *pf_prog, int pcnt, int plen, int csock)
{
	uint8_t *buf;
	struct ng_bpf_hookprog *prog;

	if ((buf = malloc(NG_BPF_HOOKPROG_SIZE(pcnt))) == NULL) {
		APPLOG_NOMEM();
		return (-1);
	}
	prog = (struct ng_bpf_hookprog *)buf;

	snprintf(prog->thisHook, sizeof (prog->thisHook), this);
	snprintf(prog->ifMatch, sizeof (prog->ifMatch), match);
	snprintf(prog->ifNotMatch, sizeof (prog->ifNotMatch), notmatch);
	prog->bpf_prog_len = pcnt;
	memcpy(prog->bpf_prog, pf_prog, plen);

	DBG(&dbg, "path: %s this: %s match: %s notmatch: %s", path, this,
	    match, notmatch);
	DBG(&dbg, "bpf_prog: len %d insts %d", plen, pcnt);

	if (NgSendMsg(csock, path, NGM_BPF_COOKIE, NGM_BPF_SET_PROGRAM,
		      prog,NG_BPF_HOOKPROG_SIZE(pcnt)) < 0) {
		applog(LOG_ERR, "%s: set bpf prog: %s", __FUNCTION__,
		       strerror(errno));
		free(buf);
		return (-1);
	}

	free(buf);
	return (0);
}

static int
attach_bpf(const char *ifname, int csock)
{
	char path[NG_PATHSIZ];

	snprintf(path, sizeof (path), "nd_bpf_%s:", ifname);

	if (attach_one_bpf(path, "tolower", "in", "toupper",
			   pf_prog_nd, ARR_SZ(pf_prog_nd),
			   sizeof (pf_prog_nd), csock) < 0 ||
	    attach_one_bpf(path, "toupper", "out", "tolower",
			   pf_prog_nd, ARR_SZ(pf_prog_nd),
			   sizeof (pf_prog_nd), csock) < 0 ||
	    attach_one_bpf(path, "in", "toupper", "toupper",
			   pf_prog_all, ARR_SZ(pf_prog_all),
			   sizeof (pf_prog_all), csock) < 0 ||
	    attach_one_bpf(path, "out", "tolower", "tolower",
			   pf_prog_all, ARR_SZ(pf_prog_all),
			   sizeof (pf_prog_all), csock) < 0) {
		return (-1);
	}
	return (0);
}

static int
create_snd_nodes(void)
{
	struct ng_ifinfo *p;
	char nbuf[NG_PATHSIZ];

	list_for_each_entry(p, &ifaces, list) {
		snprintf(nbuf, sizeof (nbuf), "snd_%s", p->name);
		if (NgMkSockNode(nbuf, &p->csock, &p->dsock) < 0) {
			applog(LOG_ERR, "%s: create node(%s): %s",
			       __FUNCTION__, p->name, strerror(errno));
			return (-1);
		}

		if (create_bpf(p->name, p->csock) < 0 ||
		    attach_snd(p->name, p->csock) < 0 ||
		    attach_bpf(p->name, p->csock) < 0) {
			return (-1);
		}
	}

	return (0);
}

static int
ng_handle_data(struct ng_ifinfo *p)
{
	int r;
	int dsock = p->dsock;
	struct sbuff *b;
	struct ng_packet_info *pi;
	char hook[NG_HOOKSIZ];

	if ((b = snd_get_buf()) == NULL) {
		return (-1);
	}

	/* XXX align data at 64-bits in a portable manner? */
	pi = sbuff_data(b);
	sbuff_advance(b, sizeof (*pi));

	if ((r = NgRecvData(dsock, b->data, b->rem, hook)) < 0) {
		applog(LOG_ERR, "%s: NgRecvData() hook %s: %s", __FUNCTION__,
		       hook, strerror(errno));
		goto drop;
	}
	b->len = r;

	if (sbuff_pull(b, sizeof (struct ether_header)) == NULL) {
		DBG(&dbg_snd, "invalid pkt (not enough for ether header");
		goto drop;
	}

	DBG(&dbg, "hook: %s if %s (%d)", hook, p->name, p->ifidx);

	pi->ifinfo = p;
	if (strcmp(hook, "in") == 0) {
		pi->in = 1;
	} else if (strcmp(hook, "out") == 0) {
		pi->in = 0;
	} else {
		DBG(&dbg, "data on unknown hook %s", hook);
		goto drop;
	}

	snd_recv_pkt(b, p->ifidx, pi->in, pi);
	return (0);

drop:
	snd_put_buf(b);
	return (-1);
}

void
os_specific_deliver_pkt(void *p, struct sbuff *b, int drop, int changed)
{
	struct ng_packet_info *pi;
	char *hook;

	if (drop) {
		snd_put_buf(b);
		return;
	}
	pi = (struct ng_packet_info *)(b->head);
	hook = pi->in ? "in" : "out";

	/* roll back buffer to include ether header */
	b->data -= sizeof (struct ether_header);
	b->len += sizeof (struct ether_header);

	DBG(&dbg, "%d bytes %s on %s", b->len, hook, pi->ifinfo->name);

	if (NgSendData(pi->ifinfo->dsock, hook, b->data, b->len) < 0) {
		applog(LOG_ERR, "%s: NgSendData: %s", __FUNCTION__,
		       strerror(errno));
	}

	snd_put_buf(b);
}

void
os_specific_add_fds(fd_set *fds, int *maxfd)
{
	struct ng_ifinfo *p;

	list_for_each_entry(p, &ifaces, list) {
		*maxfd = *maxfd > p->csock ? *maxfd : p->csock;
		*maxfd = *maxfd > p->dsock ? *maxfd : p->dsock;
		FD_SET(p->csock, fds);
		FD_SET(p->dsock, fds);
	}
}

void
os_specific_dispatch_fds(fd_set *fds)
{
	struct ng_ifinfo *p;

	list_for_each_entry(p, &ifaces, list) {
		if (FD_ISSET(p->csock, fds)) {
			MsgRead(p->csock);
		}
		if (FD_ISSET(p->dsock, fds)) {
			ng_handle_data(p);
		}
	}
}

int
os_specific_handle_iface(const char *ifname, int ifidx)
{
	struct ng_ifinfo *p;

	if ((p = malloc(sizeof (*p))) == NULL) {
		APPLOG_NOMEM();
		return (-1);
	}
	memset(p, 0, sizeof (*p));

	snprintf(p->name, sizeof (p->name), "%s", ifname);
	p->ifidx = ifidx;
	p->csock = p->dsock = -1;
	list_add_tail(&p->list, &ifaces);

	return (0);
}

int
freebsd_netgraph_init(void)
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
		applog(LOG_ERR, "SEND must be active on at least one iface");
		return (-1);
	}

	if (create_snd_nodes() < 0) {
		freebsd_netgraph_fini();
		return (-1);
	}

	return (0);
}

void
freebsd_netgraph_fini(void)
{
	struct ng_ifinfo *p, *n;
	char nbuf[NG_PATHSIZ];

	DBG(&dbg, "");

	list_for_each_entry_safe(p, n, &ifaces, list) {
		snprintf(nbuf, sizeof (nbuf), "nd_bpf_%s:", p->name);
		if (p->csock != -1 &&
		    NgSendMsg(p->csock, nbuf, NGM_GENERIC_COOKIE, NGM_SHUTDOWN,
			      NULL, 0) < 0) {
			DBG(&dbg, "shutdown %s %s", nbuf, strerror(errno));
			list_del(&p->list);
			free(p);
		}
	}
}
