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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet6/send.h>

#include <errno.h>
#include <unistd.h>

#include "config.h"
#include "snd_freebsd.h"
#include "../dbg.h"
#include "../os_specific.h"
#include "../sendd_local.h"
#include "../snd_proto.h"

#include <applog.h>
#include <list.h>
#include <sbuff.h>

static int sndsock	= -1;

/* Per-interface info */
struct snd_ifinfo {
	struct list_head list;
	char	name[IFNAMSIZ];
	int	ifidx;
	int	snds;
};

static DEFINE_LIST_HEAD(ifaces);

/* Data packet meta data */
struct snd_packet_info {
	struct snd_ifinfo *ifinfo;
	int	in;
	int	ifidx;
};

extern int linux_rand_init(void);
extern void linux_rand_fini(void);

static int
freebsd_snd_init(void)
{

	if (list_empty(&ifaces)) {
		applog(LOG_ERR, "SEND must be active on at least one iface");
		return (-1);
	}

#ifndef IPPROTO_SEND
#define IPPROTO_SEND	259
#endif
	if ((sndsock = socket(PF_INET6, SOCK_RAW, IPPROTO_SEND)) < 0) {	
		applog(LOG_ERR, "[%s:%d]: socket: %s", __func__, __LINE__,
			strerror(errno));
		return (-1);
	} else {
		applog(LOG_ERR, "%s: SEND socket created: fd=%d", __func__, sndsock);
	}

	return (0);
}

int
os_specific_init(void)
{
        if (linux_rand_init() < 0 || freebsd_snd_init() < 0) {
                return (-1);
        }

        return (0);
}

static void
freebsd_snd_fini(void)
{

	close(sndsock);
}

void
os_specific_fini(void)
{

	freebsd_snd_fini();
	linux_rand_fini();
}

int
os_specific_handle_iface(const char *ifname, int ifidx)
{
	struct snd_ifinfo *p;

	if ((p = malloc(sizeof (*p))) == NULL) {
		APPLOG_NOMEM();
		return (-1);
	}
	memset(p, 0, sizeof (*p));

	snprintf(p->name, sizeof (p->name), "%s", ifname);
	DBG(&dbg_snd, "os_specific_handle_iface -> p->name = %s", p->name);
	p->ifidx = ifidx;
	DBG(&dbg_snd, "os_specific_handle_iface -> p->ifidx = %d", ifidx);
	list_add_tail(&p->list, &ifaces);

	return (0);
}

static void
snd_sock_read()
{
	struct sockaddr_send sendsrc;
	struct snd_ifinfo *p, pifinfo;
	socklen_t len;
	struct sbuff *b;
	struct snd_packet_info *pi;
	int n;

	if ((b = snd_get_buf()) == NULL) {
		goto done;
	}

	pi = sbuff_data(b);
	sbuff_advance(b, sizeof (*pi));

	len = sizeof(sendsrc);
	bzero(&sendsrc, sizeof(sendsrc));
	n = recvfrom(sndsock, b->data, b->rem, 0, (struct sockaddr *)&sendsrc, &len);
	if (n < 0) {
		applog(LOG_ERR, "%s: read: %s", __func__, strerror(errno));
		goto done;
	} else
		DBG(&dbg_snd, "%d bytes received on send socket. (%d)", n, b->rem);

	b->len = n;

	/* Check if we are interested in the given interface. */
	list_for_each_entry(p, &ifaces, list) {
		if (p->ifidx == sendsrc.send_ifidx)
			goto found;
	}

	/*
	 * If not found, send the packet straight back to the kernel, as
	 * we are not doing SeND on that interface.
	 */
	DBG(&dbg_snd, "Received packet for non-SeND interface. Sending back to kernel.");
	pifinfo.ifidx = sendsrc.send_ifidx;
	pi->ifinfo = &pifinfo;
	pi->in = (sendsrc.send_direction == SND_IN) ? 1 : 0;
	os_specific_deliver_pkt(NULL, b, 0, 0);

	goto done;

found:
	switch (sendsrc.send_direction) {
	case SND_IN:
		applog(LOG_ERR, "Direction: SND_IN");
		pi->ifinfo = p;
		pi->in = 1;
		snd_recv_pkt(b, p->ifidx, SND_IN, pi);
		break;
	case SND_OUT:
		applog(LOG_ERR, "Direction: SND_OUT");
		pi->ifinfo = p;
		pi->in = 0;
		snd_recv_pkt(b, p->ifidx, SND_OUT, pi);
		break;
	default:
		applog(LOG_ERR, "Unknown SEND pkt header: unknown direction.");
	}

done:
	/* ToDo: Free memory! */
	snd_put_buf(b);
	return;
}

void
os_specific_add_fds(fd_set *fds, int *maxfd)
{

	FD_SET(sndsock, fds);
	*maxfd = sendd_max(*maxfd, sndsock);
}

void
os_specific_dispatch_fds(fd_set *fds)
{

	if (FD_ISSET(sndsock, fds))
		snd_sock_read();
}

void
os_specific_deliver_pkt(void *p, struct sbuff *b, int drop, int changed)
{
	struct snd_packet_info *pi;
	struct sockaddr_send sendsrc;

	if (drop) {
		snd_put_buf(b);
		return;
	}

	pi = (struct snd_packet_info *)(b->head);
	bzero(&sendsrc, sizeof(sendsrc));
	sendsrc.send_len = sizeof(sendsrc);
	sendsrc.send_family = AF_INET6;
	sendsrc.send_direction = pi->in;
	sendsrc.send_ifidx = pi->ifinfo->ifidx;

	DBG(&dbg_snd, "Sending %d bytes for ifidx=%d:\n", b->len, pi->ifinfo->ifidx);
	if (sendto(sndsock, b->data, b->len, 0, (struct sockaddr *)&sendsrc,
	    sizeof(sendsrc)) < 0) {
		DBG(&dbg_snd, "Failed to send SEND message back to kernel.");
		DBG(&dbg_snd, "%d %p %d %p", sndsock, b->data, b->len, &sendsrc);
		DBG(&dbg_snd, "send_len=%d send_family=%d send_direction=%d send_ifidx=%d", sendsrc.send_len, sendsrc.send_family, sendsrc.send_direction, sendsrc.send_ifidx);
		DBG_HEXDUMP(&dbg_snd, "data:", b->data, b->len);
		perror("Failed");
		snd_put_buf(b);
		return;
	}

	snd_put_buf(b);

	return;
}
