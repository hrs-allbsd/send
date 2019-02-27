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

#include <sys/select.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libipq.h>

#include "config.h"
#include <applog.h>

#include "../os_specific.h"
#include "../sendd_local.h"
#include "snd_linux.h"

static struct ipq_handle *qh;

extern unsigned if_nametoindex(const char *);

static inline void
process_pkt(ipq_packet_msg_t *pkt, struct sbuff *b)
{
	int in, ifidx;

	b->data = pkt->payload;
	b->len = pkt->data_len;

	if (*(pkt->indev_name)) {
		in = 1;
		ifidx = if_nametoindex(pkt->indev_name);
	} else if (*(pkt->outdev_name)) {
		in = 0;
		ifidx = if_nametoindex(pkt->outdev_name);
	} else {
		applog(LOG_ERR, "%s: pkt has neither indev nor outdev",
		       __FUNCTION__);
		snd_put_buf(b);
		return;
	}

	snd_recv_pkt(b, ifidx, in, pkt);
}

static void
ipq_recv_pkt(void)
{
	int r;
	struct sbuff *b = snd_get_buf();

	if (b == NULL) {
		return;
	}
	if ((r = ipq_read(qh, b->head, b->rem, -1)) < 0) {
		applog(LOG_ERR, "%s: ipq_read(): %s", __FUNCTION__,
		       ipq_errstr());
		goto fail;
	} else if (r == 0) {
		/* timeout */
		goto fail;
	}

	switch ((r = ipq_message_type(b->head))) {
	case NLMSG_ERROR:
		applog(LOG_ERR, "%s: nlmsg error: %s", __FUNCTION__,
		       strerror(ipq_get_msgerr(b->head)));
		goto fail;
	case IPQM_PACKET:
		process_pkt(ipq_get_packet(b->head), b);
		return;
	default:
		break;
	}

fail:
	snd_put_buf(b);
}

void
linux_ipq_add_fds(fd_set *fds, int *maxfd)
{
	FD_SET(qh->fd, fds);
	*maxfd = sendd_max(*maxfd, qh->fd);
}

void
linux_ipq_dispatch_fds(fd_set *fds)
{
	if (FD_ISSET(qh->fd, fds)) {
		ipq_recv_pkt();
	}
}

void
os_specific_deliver_pkt(void *p, struct sbuff *b, int drop, int changed)
{
	ipq_packet_msg_t *pkt = p;
	void *newpkt = NULL;
	int plen = 0;

	if (changed && !drop) {
		newpkt = sbuff_data(b);
		plen = b->len;
	}

	ipq_set_verdict(qh, pkt->packet_id, drop ? NF_DROP : NF_ACCEPT,
			plen, newpkt);
	snd_put_buf(b);
}

int
linux_ipq_init(void)
{
	if ((qh = ipq_create_handle(0, PF_INET6)) == NULL) {
		applog(LOG_ERR, "%s: ipq_create_handle() failed: %s",
		       __FUNCTION__, ipq_errstr());
		return (-1);
	}
	if (ipq_set_mode(qh, IPQ_COPY_PACKET, SND_MAX_PKT) < 0) {
		applog(LOG_ERR, "%s: ipq_set_mode() failed: %s",
		       __FUNCTION__, ipq_errstr());
		if (errno == ECONNREFUSED) {
			applog(LOG_ERR, "%s: perhaps you need to modprobe "
			       "ip6_queue?", __FUNCTION__);
		}
		return (-1);
	}
	return (0);
}

void
linux_ipq_fini(void)
{
	ipq_destroy_handle(qh);
}
