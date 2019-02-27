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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <arpa/inet.h>

#include "config.h"
#include <applog.h>

#include "../os_specific.h"

static int
addr_common(struct in6_addr *a, int ifidx, int plen, int add, uint32_t vlife,
    uint32_t plife)
{
	struct in6_aliasreq req[1];
	struct in6_addr mask64[1];
	int s;
	int cmd;
	int r = -1;

	cmd = add ? SIOCAIFADDR_IN6 : SIOCDIFADDR_IN6;

	memset(req, 0, sizeof (*req));
	if (if_indextoname(ifidx, req->ifra_name) == NULL) {
		applog(LOG_ERR, "%s: can't get iface name for %d",
		       __FUNCTION__, ifidx);
		return (-1);
	}

	memcpy(&req->ifra_addr.sin6_addr, a, sizeof (*a));
	req->ifra_addr.sin6_family = AF_INET6;
	req->ifra_addr.sin6_len = sizeof (struct sockaddr_in6);

	mask64->__u6_addr.__u6_addr32[0] = 0xffffffff;
	mask64->__u6_addr.__u6_addr32[1] = 0xffffffff;
	memcpy(&req->ifra_prefixmask.sin6_addr, mask64, 8);
	req->ifra_prefixmask.sin6_len = sizeof (struct sockaddr_in6);

	req->ifra_lifetime.ia6t_expire = 0;
	req->ifra_lifetime.ia6t_preferred = 0;
	req->ifra_lifetime.ia6t_vltime = vlife;
	req->ifra_lifetime.ia6t_pltime = plife;

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		applog(LOG_ERR, "%s: socket(): %s", __FUNCTION__,
		       strerror(errno));
		goto done;
	}

	if (ioctl(s, cmd, req) < 0) {
		applog(LOG_ERR, "%s: ioctl(): %s", __FUNCTION__,
		       strerror(errno));
		goto done;
	}
	r = 0;

done:
	close(s);
	return (r);
}

int
os_specific_add_addr(struct in6_addr *a, int ifidx, int plen, uint32_t vlife,
    uint32_t plife)
{
	return (addr_common(a, ifidx, plen, 1, vlife, plife));
}

int
os_specific_del_addr(struct in6_addr *a, int ifidx, int plen)
{
	return (addr_common(a, ifidx, plen, 0, 0, 0));
}
