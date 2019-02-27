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
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

#include "config.h"
#include <applog.h>
#include "pkixip_ext.h"
#include "pkixip_local.h"

struct dlog_desc dbg_parse = {
	.desc = "pkix_ipext_parse",
	.ctx = PKIXIP_EXT_CTX
};

extern int pkixip_parse(void);
extern FILE *pkixip_in;

IPAddrBlocks *parse_ipb;
struct pkixip_config *configs;

int
pkixip_read_config(const char *f, struct pkixip_config *cf, IPAddrBlocks **ipb)
{
	int r = -1;

	if ((pkixip_in = fopen(f, "r")) == NULL) {
		DBG(&dbg_parse, "fopen: %s", strerror(errno));
		return (-1);
	}

	if (!(parse_ipb = IPAddrBlocks_new())) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		fclose(pkixip_in);
		return (-1);
	}
	configs = cf;

	if (pkixip_parse() != 0) {
		IPAddrBlocks_free(parse_ipb);
		parse_ipb = NULL;
		goto done;
	}

	r = 0;
	if (ipb) {
		*ipb = parse_ipb;
	}
done:
	fclose(pkixip_in);
	return (r);
}

int
pkixip_config_init(void)
{
	struct dlog_desc *dbgs[] = {
		&dbg_parse,
		NULL
	};

	if (applog_register(dbgs) < 0) {
		return (-1);
	}

	return (0);
}
