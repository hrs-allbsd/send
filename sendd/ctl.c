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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "config.h"
#include <applog.h>
#include <senddctl.h>

#include "sendd_local.h"
#include "dbg.h"

#ifdef	DEBUG
#include <arpa/inet.h>
static char abuf[INET6_ADDRSTRLEN];

static struct dlog_desc dbg = {
	.desc = "ctl",
	.ctx = SENDD_NAME
};
#endif

static void
handle_add_addr(int sd, void *clt, struct in6_addr *a, int ifidx,
    const char *use, const char *pfile, const char *kfile, int sec,
    uint8_t sigmeth)
{
	enum senddctl_status status;
	struct snd_sig_method *m;

	DBG(&dbg, "%s (ifidx %d) use: %s sec: %d sigmeth: %d",
	    inet_ntop(AF_INET6, a, abuf, sizeof (abuf)), ifidx, use, sec,
	    sigmeth);
	DBG(&dbg, "params: %s", pfile);
	DBG(&dbg, "keyfile: %s", kfile);

	if ((m = snd_find_sig_method_bytype(sigmeth)) == NULL) {
		status = SENDDCTL_STATUS_BADMETH;
		goto done;
	}

	if (use) {
		status = snd_add_addr_params_use(a, ifidx, use);
	} else {
		status = snd_add_addr_params(a, ifidx, pfile, kfile, sec, m);
	}

done:
	senddctl_add_rep(sd, clt, status);
}

static void
handle_add_named(int sd, void *clt, const char *name, const char *use,
    const char *pfile, const char *kfile, int sec, uint8_t sigmeth)
{
	enum senddctl_status status;
	struct snd_sig_method *m;

	DBG(&dbg, "name: %s use: %s sec: %d sigmeth: %d",
	    name, use, sec, sigmeth);
	DBG(&dbg, "params: %s", pfile);
	DBG(&dbg, "keyfile: %s", kfile);

	if ((m = snd_find_sig_method_bytype(sigmeth)) == NULL) {
		status = SENDDCTL_STATUS_BADMETH;
		goto done;
	}

	if (use) {
		status = snd_add_named_params_use(name, use);
	} else {
		status = snd_add_named_params(name, pfile, kfile, sec, m);
	}

done:
	senddctl_add_rep(sd, clt, status);
}

static void
handle_del_addr(int sd, void *clt, struct in6_addr *a, int ifidx)
{
	enum senddctl_status status;

	DBG(&dbg, "%s (ifidx %d)",
	    inet_ntop(AF_INET6, a, abuf, sizeof (abuf)), ifidx);

	status = snd_del_addr_params(a, ifidx);
	senddctl_del_rep(sd, clt, status);
}

static void
handle_del_named(int sd, void *clt, const char *name)
{
	enum senddctl_status status;

	DBG(&dbg, "%s", name);

	status = snd_del_named_params(name);
	senddctl_del_rep(sd, clt, status);
}

static struct senddctl_srv_handlers ctl_handlers = {
	.handle_add_addr = handle_add_addr,
	.handle_add_named = handle_add_named,
	.handle_del_addr = handle_del_addr,
	.handle_del_named = handle_del_named,
};

void
snd_ctl_read(int sd)
{
	DBG(&dbg, "");
	senddctl_srv_read(sd, &ctl_handlers);
}

int
snd_ctl_init(void)
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

	return (senddctl_open_srv());
}
