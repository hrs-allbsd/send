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
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "config.h"
#include <applog.h>
#include <sbuff.h>
#include <senddctl.h>
#include "senddctl_proto.h"

#ifndef	ARR_SZ
#define	ARR_SZ(a) (sizeof (a) / sizeof (*a))
#endif

int
senddctl_open_srv(void)
{
	int sd;
	struct sockaddr_un sun;

	if ((sd = socket(PF_LOCAL, SOCK_DGRAM, 0)) < 0) {
		applog(LOG_ERR, "%s: socket(PF_LOCAL, SOCK_DGRAM): %s",
		       __FUNCTION__, strerror(errno));
		return (-1);
	}

	unlink(SENDD_CTL_PATH);
	memset(&sun, 0, sizeof (sun));
	sun.sun_family = PF_LOCAL;
	strncpy(sun.sun_path, SENDD_CTL_PATH, sizeof (sun.sun_path));

	if (bind(sd, (void *)&sun, sizeof (sun)) < 0) {
		close(sd);
		applog(LOG_ERR, "%s: bind: %s", __FUNCTION__, strerror(errno));
		return (-1);
	}

	return (sd);
}

static int
clt_bind(int sd)
{
	struct sockaddr_un sun;

	/* 
	 * Linux has abstract namespace; use this if available.
	 * Otherwise, create a temporary filesystem handle for the client.
	 */
	memset(&sun, 0, sizeof (sun));
	sun.sun_family = PF_LOCAL;
#ifndef	SND_OS_linux
	/* Can't use mkstemp here since bind will try to create the file. */
	/* XXX should probably do a security audit on the time method */
	{
		struct timeval tv;

		gettimeofday(&tv, NULL);
		snprintf(sun.sun_path, sizeof (sun.sun_path),
			 "/var/run/senddctl.%.6ld", tv.tv_usec);
	}
#endif
	if (bind(sd, (void *)&sun, sizeof (sun)) < 0) {
		applog(LOG_ERR, "%s: bind: %s", __FUNCTION__, strerror(errno));
		return (-1);
	}
	return (0);
}

int
senddctl_open_clt(void)
{
	int sd;

	if ((sd = socket(PF_LOCAL, SOCK_DGRAM, 0)) < 0) {
		applog(LOG_ERR, "%s: socket(PF_LOCAL, SOCK_DGRAM): %s",
		       __FUNCTION__, strerror(errno));
		return (-1);
	}

	if (clt_bind(sd) < 0) {
		close(sd);
		return (-1);
	}

	return (sd);
}

void
senddctl_close(int sd)
{
#ifndef	SND_OS_linux
	struct sockaddr_un sun;
	socklen_t sl = sizeof (sun);

	if (getsockname(sd, (void *)&sun, &sl) < 0) {
		applog(LOG_ERR, "%s: getsockname: %s",
		       __FUNCTION__, strerror(errno));
	} else {
		unlink(sun.sun_path);
	}
#endif
	close(sd);
}

static const char *
next_str(struct sbuff *b)
{
	uint8_t *p = sbuff_data(b);
	int rem, off;

	for (off = 0, rem = b->len; rem > 0; rem--, off++) {
		if (p[off] == 0) {
			sbuff_advance(b, off + 1);
			return ((const char *)p);
		}
	}

	applog(LOG_ERR, "%s: no end of string found (%s)", __FUNCTION__, p);
	return (NULL);
}

static void
handle_add_addr_req(int sd, struct sockaddr_un *from, struct sbuff *b,
    struct senddctl_srv_handlers *cbs)
{
	struct senddctl_add_addr_req *req = sbuff_data(b);
	const char *use, *pfile, *kfile;
	struct in6_addr a;
	int ifidx, sec;
	uint8_t sigmeth;

	if (sbuff_advance(b, sizeof (*req)) < 0) {
		applog(LOG_WARNING, "%s: pkt too small (%d bytes)",
		       __FUNCTION__, b->len);
		senddctl_add_rep(sd, from, SENDDCTL_STATUS_PROTOERR);
		return;
	}

	memcpy(&a, &req->addr, sizeof (a));
	ifidx = req->ifidx;

	if (req->src == SENDDCTL_SRC_USE) {
		if ((use = next_str(b)) == NULL) {
			senddctl_add_rep(sd, from, SENDDCTL_STATUS_PROTOERR);
			return;
		}
		pfile = kfile = NULL;
		sec = 0;
		sigmeth = 0;
	} else {
		if ((pfile = next_str(b)) == NULL ||
		    (kfile = next_str(b)) == NULL) {
			senddctl_add_rep(sd, from, SENDDCTL_STATUS_PROTOERR);
			return;
		}
		use = NULL;
		sec = req->sec;
		sigmeth = req->sigmeth;
	}

	if (cbs->handle_add_addr) {
		cbs->handle_add_addr(sd, from, &a, ifidx, use,
				     pfile, kfile, sec, sigmeth);
	}
}

static void
handle_add_named_req(int sd, struct sockaddr_un *from, struct sbuff *b,
    struct senddctl_srv_handlers *cbs)
{
	struct senddctl_add_named_req *req = sbuff_data(b);
	const char *name, *use, *pfile, *kfile;
	int sec;
	uint8_t sigmeth;

	if (sbuff_advance(b, sizeof (*req)) < 0) {
		applog(LOG_WARNING, "%s: pkt too small (%d bytes)",
		       __FUNCTION__, b->len);
		senddctl_add_rep(sd, from, SENDDCTL_STATUS_PROTOERR);
		return;
	}

	if ((name = next_str(b)) == NULL) {
		senddctl_add_rep(sd, from, SENDDCTL_STATUS_PROTOERR);
		return;
	}

	if (req->src == SENDDCTL_SRC_USE) {
		if ((use = next_str(b)) == NULL) {
			senddctl_add_rep(sd, from, SENDDCTL_STATUS_PROTOERR);
			return;
		}
		pfile = kfile = NULL;
		sec = 0;
		sigmeth = 0;
	} else {
		if ((pfile = next_str(b)) == NULL ||
		    (kfile = next_str(b)) == NULL) {
			senddctl_add_rep(sd, from, SENDDCTL_STATUS_PROTOERR);
			return;
		}
		use = NULL;
		sec = req->sec;
		sigmeth = req->sigmeth;
	}

	if (cbs->handle_add_named) {
		cbs->handle_add_named(sd, from, name, use, pfile, kfile, sec,
			sigmeth);
	}
}

static void
handle_del_addr_req(int sd, struct sockaddr_un *from, struct sbuff *b,
    struct senddctl_srv_handlers *cbs)
{
	struct senddctl_add_addr_req *req = sbuff_data(b);
	struct in6_addr a;
	int ifidx;

	if (sbuff_advance(b, sizeof (*req)) < 0) {
		applog(LOG_WARNING, "%s: pkt too small (%d bytes)",
		       __FUNCTION__, b->len);
		senddctl_add_rep(sd, from, SENDDCTL_STATUS_PROTOERR);
		return;
	}

	memcpy(&a, &req->addr, sizeof (a));
	ifidx = req->ifidx;

	if (cbs->handle_del_addr) {
		cbs->handle_del_addr(sd, from, &a, ifidx);
	}
}

static void
handle_del_named_req(int sd, struct sockaddr_un *from, struct sbuff *b,
    struct senddctl_srv_handlers *cbs)
{
	struct senddctl_add_named_req *req = sbuff_data(b);
	const char *name;

	if (sbuff_advance(b, sizeof (*req)) < 0) {
		applog(LOG_WARNING, "%s: pkt too small (%d bytes)",
		       __FUNCTION__, b->len);
		senddctl_add_rep(sd, from, SENDDCTL_STATUS_PROTOERR);
		return;
	}

	if ((name = next_str(b)) == NULL) {
		senddctl_add_rep(sd, from, SENDDCTL_STATUS_PROTOERR);
		return;
	}

	if (cbs->handle_del_named) {
		cbs->handle_del_named(sd, from, name);
	}
}

void
senddctl_srv_read(int sd, struct senddctl_srv_handlers *cbs)
{
	uint8_t buf[SENDDCTL_BUFSZ];
	struct sbuff b[1];
	struct sockaddr_un sun;
	socklen_t sl;

	sbuff_init(b, sizeof (buf), buf);

	sl = sizeof (sun);
	if ((b->len = recvfrom(sd, buf, sizeof (buf), 0, (void *)&sun, &sl))
	    < 0) {
		applog(LOG_ERR, "%s: recvfrom: %s", __FUNCTION__,
		       strerror(errno));
		return;
	}

	if (b->len < 1) {
		applog(LOG_WARNING, "%s: pkt too small (%d bytes)",
		       __FUNCTION__, b->len);
		senddctl_add_rep(sd, &sun, SENDDCTL_STATUS_PROTOERR);
		return;
	}

	switch (*buf) {
	case SENDDCTL_ADD_ADDR:
		handle_add_addr_req(sd, &sun, b, cbs);
		break;
	case SENDDCTL_ADD_NAMED:
		handle_add_named_req(sd, &sun, b, cbs);
		break;
	case SENDDCTL_DEL_ADDR:
		handle_del_addr_req(sd, &sun, b, cbs);
		break;
	case SENDDCTL_DEL_NAMED:
		handle_del_named_req(sd, &sun, b, cbs);
		break;
	default:
		applog(LOG_WARNING, "%s: unknown type %d", __FUNCTION__,
		       *buf);
		break;
	}
}

void
senddctl_clt_read(int sd, struct senddctl_clt_handlers *cbs, void *cookie)
{
	uint8_t buf[SENDDCTL_BUFSZ];
	struct senddctl_add_rep *rep = (struct senddctl_add_rep *)buf;
	struct sockaddr_un sun;
	socklen_t sl;
	int r;

	sl = sizeof (sun);
	if ((r = recvfrom(sd, buf, sizeof (buf), 0, (void *)&sun, &sl)) < 0) {
		applog(LOG_ERR, "%s: recvfrom: %s", __FUNCTION__,
		       strerror(errno));
		return;
	}

	switch (rep->cmd) {
	case SENDDCTL_ADD_REPLY:
		if (cbs->handle_add) cbs->handle_add(rep->status, cookie);
		break;
	case SENDDCTL_DEL_REPLY:
		if (cbs->handle_del) cbs->handle_del(rep->status, cookie);
		break;
	default:
		applog(LOG_WARNING, "%s: unknown type %d", __FUNCTION__,
		       *buf);
		break;
	}
}

static int
add_str(struct sbuff *b, const char *str)
{
	int slen = strlen(str);
	uint8_t z;

	z = 0;
	if (sbuff_put(b, str, slen) < 0 ||
	    sbuff_put(b, &z, 1) < 0) {
		return (-1);
	}
	return (0);
}

static int
send_req(int sd, struct sbuff *b)
{
	struct sockaddr_un sun;

	memset(&sun, 0, sizeof (sun));
	sun.sun_family = PF_LOCAL;
	strncpy(sun.sun_path, SENDD_CTL_PATH, sizeof (sun.sun_path));

	if (sendto(sd, b->head, b->len, 0, (void *)&sun, sizeof (sun)) < 0) {
		applog(LOG_ERR, "%s: sendto: %s", __FUNCTION__,
		       strerror(errno));
		return (-1);
	}

	return (0);
}

static int
add_req_common(int sd, struct sbuff *b, const char *use, const char *pfile,
    const char *kfile, int sec)
{
	if (use) {
		if (add_str(b, use) < 0) {
			applog(LOG_ERR, "%s: internal buffer too small (use)",
			       __FUNCTION__);
			return (-1);
		}
	} else {
		if (pfile == NULL || kfile == NULL) {
			return (-1);
		}
		if (add_str(b, pfile) < 0 ||
		    add_str(b, kfile) < 0) {
			applog(LOG_ERR, "%s: internal buffer too small (exp)",
			       __FUNCTION__);
			return (-1);
		}
	}

	return (send_req(sd, b));
}

int
senddctl_add_addr_req(int sd, struct in6_addr *a, int ifidx, const char *use,
    const char *pfile, const char *kfile, int sec, uint8_t sigmeth)
{
	uint8_t buf[SENDDCTL_BUFSZ];
	struct sbuff b[1];
	struct senddctl_add_addr_req *req;

	if (a == NULL) {
		return (-1);
	}
	sbuff_init(b, sizeof (buf), buf);

	req = sbuff_data(b);
	sbuff_advance(b, sizeof (*req));
	memset(req, 0, sizeof (*req));
	req->cmd = SENDDCTL_ADD_ADDR;
	if (use) {
		req->src = SENDDCTL_SRC_USE;
	} else {
		req->src = SENDDCTL_SRC_EXP;
		req->sec = sec;
		req->sigmeth = sigmeth;
	}
	req->ifidx = ifidx;
	memcpy(&req->addr, a, sizeof (req->addr));

	return (add_req_common(sd, b, use, pfile, kfile, sec));
}

int
senddctl_add_named_req(int sd, const char *name, const char *use,
    const char *pfile, const char *kfile, int sec, uint8_t sigmeth)
{
	uint8_t buf[SENDDCTL_BUFSZ];
	struct sbuff b[1];
	struct senddctl_add_named_req *req;

	if (name == NULL) {
		return (-1);
	}
	sbuff_init(b, sizeof (buf), buf);

	req = sbuff_data(b);
	sbuff_advance(b, sizeof (*req));
	memset(req, 0, sizeof (*req));
	req->cmd = SENDDCTL_ADD_NAMED;
	if (use) {
		req->src = SENDDCTL_SRC_USE;
	} else {
		req->src = SENDDCTL_SRC_EXP;
		req->sec = sec;
		req->sigmeth = sigmeth;
	}
	if (add_str(b, name) < 0) {
		return (-1);
	}

	return (add_req_common(sd, b, use, pfile, kfile, sec));
}

int
senddctl_del_addr_req(int sd, struct in6_addr *a, int ifidx)
{
	uint8_t buf[SENDDCTL_BUFSZ];
	struct sbuff b[1];
	struct senddctl_add_addr_req *req;

	if (a == NULL) {
		return (-1);
	}
	sbuff_init(b, sizeof (buf), buf);

	req = sbuff_data(b);
	sbuff_advance(b, sizeof (*req));
	memset(req, 0, sizeof (*req));
	req->cmd = SENDDCTL_DEL_ADDR;
	req->ifidx = ifidx;
	memcpy(&req->addr, a, sizeof (req->addr));

	return (send_req(sd, b));
}

int
senddctl_del_named_req(int sd, const char *name)
{
	uint8_t buf[SENDDCTL_BUFSZ];
	struct sbuff b[1];
	struct senddctl_add_named_req *req;

	if (name == NULL) {
		return (-1);
	}
	sbuff_init(b, sizeof (buf), buf);

	req = sbuff_data(b);
	sbuff_advance(b, sizeof (*req));
	memset(req, 0, sizeof (*req));
	req->cmd = SENDDCTL_DEL_NAMED;
	if (add_str(b, name) < 0) {
		return (-1);
	}

	return (send_req(sd, b));
}

int
senddctl_add_rep(int sd, void *clt, enum senddctl_status status)
{
	uint8_t buf[SENDDCTL_BUFSZ];
	struct senddctl_add_rep *rep = (struct senddctl_add_rep *)buf;
	struct sockaddr_un *to = clt;

	rep->cmd = SENDDCTL_ADD_REPLY;
	rep->status = status;

	if (sendto(sd, rep, sizeof (*rep), 0, clt, sizeof (*to)) < 0) {
		applog(LOG_ERR, "%s: sendto: %s", __FUNCTION__,
		       strerror(errno));
		return (-1);
	}

	return (0);
}

int
senddctl_del_rep(int sd, void *clt, enum senddctl_status status)
{
	uint8_t buf[SENDDCTL_BUFSZ];
	struct senddctl_add_rep *rep = (struct senddctl_add_rep *)buf;
	struct sockaddr_un *to = clt;

	rep->cmd = SENDDCTL_DEL_REPLY;
	rep->status = status;

	if (sendto(sd, rep, sizeof (*rep), 0, clt, sizeof (*to)) < 0) {
		applog(LOG_ERR, "%s: sendto: %s", __FUNCTION__,
		       strerror(errno));
		return (-1);
	}

	return (0);
}

static const char *status_strings[] = {
	"OK",
	"Protocol Error",
	"Invalid argument",
	"No memory",
	"Not found",
	"In use",
	"Internal system error",
	"Invalid signature method",
};

const char *
senddctl_status2str(enum senddctl_status status)
{
	if (status < 0 || status >= ARR_SZ(status_strings)) {
		return ("Invalid status code");
	}
	return (status_strings[status]);
}
