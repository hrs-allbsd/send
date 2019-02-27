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
#include <sys/socket.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>

#include <netinet6/send.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#include "sendd_local.h"
#include "os_specific.h"
#include "snd_proto.h"
#include "dbg.h"

#include <applog.h>
#include <sbuff.h>

static int icmp6sock 	= -1;

#ifdef	DEBUG
static struct dlog_desc dbg = {
	.desc = "net",
	.ctx = SENDD_NAME
};
static char abuf[INET6_ADDRSTRLEN];
#endif

/* TODO: dynamically size according to MTU */
struct sbuff *
snd_get_buf(void)
{
	struct sbuff *b;

	if ((b = sbuff_alloc(SND_MAX_PKT)) == NULL) {
		APPLOG_NOMEM();
		return (NULL);
	}
	return (b);
}

void
snd_put_buf(struct sbuff *b)
{
	sbuff_free(b);
}

int
snd_send_icmp(struct sbuff *b, struct sockaddr_in6 *sin, int ifidx)
{
	struct iovec iov = { b->head, b->len };
	struct in6_pktinfo *ipi;
	uint8_t cbuf[CMSG_SPACE(sizeof (*ipi))];
	struct cmsghdr *cmsg = (struct cmsghdr *)cbuf;
	struct msghdr msg = {
		.msg_name = sin,
		.msg_namelen = sizeof (*sin),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof (cbuf),
	};

	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof (*ipi));

	ipi = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	memset(ipi, 0, sizeof (*ipi));
	ipi->ipi6_ifindex = ifidx;

	DBG(&dbg, "sending %d bytes to %s (%d)", b->len,
	    inet_ntop(AF_INET6, &sin->sin6_addr, abuf, sizeof (abuf)),
	    ifidx);

	if (sendmsg(icmp6sock, &msg, 0) < 0) {
		DBG(&dbg_snd, "sendmsg: %s", strerror(errno));
		return (-1);
	}
	return (0);
}

/*
 * TODO: Linux is not yet up-to-date with rfc3542, specifically in that
 * it uses the socket option IPV6_PKTINFO instead of IPV6_RECVPKTINFO.
 * So for now we just use the older sin6_scope_id, which still works.
 */
void
snd_icmp_sock_read(void)
{
	struct sockaddr_in6 sin[1];
	struct sbuff *b;
	uint8_t *type;
	socklen_t slen;
	int r;

	if ((b = snd_get_buf()) == NULL) {
		return;
	}

	slen = sizeof (*sin);
	if ((r = recvfrom(icmp6sock, b->head, b->rem, 0, (void *)sin, &slen))
	    < 0) {
		applog(LOG_ERR, "%s: recvfrom: %s", __FUNCTION__,
		       strerror(errno));
		goto done;
	}
	b->len = r;

	DBG(&dbg, "%d bytes from %s on IF %d", r,
	    inet_ntop(AF_INET6, &sin->sin6_addr, abuf, sizeof (abuf)),
	    sin->sin6_scope_id);

	/* Is this OK? */
	if (IN6_IS_ADDR_LOOPBACK(&sin->sin6_addr)) {
		DBG(&dbg, "Dropping request from loopback");
		goto done;
	}

	type = sbuff_data(b);
	switch (*type) {
	case ICMP6_SND_CPS:
		snd_handle_cps(b, sin, sin->sin6_scope_id);
		break;
	case ICMP6_SND_CPA:
		snd_handle_cpa(b, sin);
		break;
	case ND_ROUTER_ADVERT:
		snd_process_ra(sbuff_data(b), r, sin->sin6_scope_id,
			       &sin->sin6_addr);
		break;
	default:
		DBG(&dbg_snd, "Unhandled ICMP6 type %d", *type);
		break;
	}

done:
	snd_put_buf(b);
}

int
snd_net_init(void)
{
	int v;
	struct icmp6_filter filter;
#ifdef	DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg,
		NULL
	};

	if (snd_applog_register(dbgs) < 0) {
		return (-1);
	}
#endif

	if ((icmp6sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		applog(LOG_ERR, "%s: socket: %s", __FUNCTION__,
		       strerror(errno));
		return (-1);
	}
	v = 255;
	if (setsockopt(icmp6sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v,
		       sizeof (v)) < 0) {
		applog(LOG_ERR, "%s: setsockopt(IPV6_UNICAST_HOPS): %s",
		       __FUNCTION__, strerror(errno));
		return (-1);
	}
	v = 255;
	if (setsockopt(icmp6sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &v,
	    sizeof (v)) < 0) {
		applog(LOG_ERR, "%s: setsockopt(IPV6_MULTICAST_HOPS): %s",
		       __FUNCTION__, strerror(errno));
		return (-1);
	}

	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ICMP6_SND_CPS, &filter);
	ICMP6_FILTER_SETPASS(ICMP6_SND_CPA, &filter);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);

	if (setsockopt(icmp6sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
		       sizeof (filter)) < 0) {
		applog(LOG_ERR, "%s: setsockopt(ICMP6_FILTER): %s",
		       __FUNCTION__, strerror(errno));
		return (-1);
	}

	return(icmp6sock);
}
