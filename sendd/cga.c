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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/sha.h>

#include "config.h"
#include <applog.h>
#include <cga.h>

#include "sendd_local.h"
#include "snd_config.h"
#include "dbg.h"

uint8_t *
snd_readder(const char *fname, int *dlen)
{
	struct stat sb[1];
	FILE *fp;
	uint8_t *der;

	if (stat(fname, sb) < 0) {
		applog(LOG_ERR, "%s: Could not stat file '%s': %s",
		       __FUNCTION__, fname, strerror(errno));
		return (NULL);
	}

	if ((fp = fopen(fname, "r")) == NULL) {
		applog(LOG_ERR, "%s: Could not open file '%s': %s",
		       __FUNCTION__, fname, strerror(errno));
		return (NULL);
	}

	if ((der = malloc(sb->st_size)) == NULL) {
		APPLOG_NOMEM();
		fclose(fp);
		return (NULL);
	}

	fread(der, 1, sb->st_size, fp);
	fclose(fp);
	*dlen = sb->st_size;

	return (der);
}

struct snd_cga_params *
snd_cga_get_params(struct in6_addr *addr, int ifidx)
{
	struct cga_parsed_params ws[1];
	struct snd_cga_params *p = snd_find_params_byaddr(addr, ifidx);

	ws->buf = p->der;
	ws->dlen = p->dlen;
	cga_parse_params(ws);

	/* Change prefix to addr's */
	memcpy(ws->pfx, addr->s6_addr, 8);

	return (p);
}

int
snd_cga_gen(struct in6_addr *pfx, struct snd_cga_params *p)
{
	cga_ctx_t ctx[1];

	cga_init_ctx(ctx);
	cga_set_der(ctx, p->der, p->dlen);
	cga_set_sec(ctx, p->sec);
	cga_set_prefix(ctx, pfx);

	if (cga_generate(ctx) != 0) {
		applog(LOG_ERR, "%s: cga_generate() failed", __FUNCTION__);
		return (-1);
	}
	memcpy(pfx, &ctx->addr, sizeof (*pfx));
	return (0);
}

int
snd_cga_verify(struct in6_addr *a, uint8_t *der, int dlen,
    uint8_t **key, int *klen)
{
	cga_ctx_t cga[1];
	cga_parsed_params_t ws[1];
	int r, sec, minsec;

	sec = cga_get_sec(a);
	minsec = snd_conf_get_int(snd_cga_minsec);
	if (sec < minsec) {
		DBG(&dbg_snd, "Peer's CGA sec is too small: %d (configured "
		    "minumum: %d)", sec, minsec);
		return (-1);
	}

	cga_init_ctx(cga);
	cga_set_der(cga, der, dlen);
	cga_set_addr(cga, a);

	if ((r = cga_verify(cga)) == 0) {
		ws->buf = der;
		ws->dlen = dlen;
		cga_parse_params(ws);
		*key = ws->key;
		/*
		 * Don't use ws->klen, since this only refers to the length
		 * of the first key. Instead, set klen to the length of the
		 * first key plus any extensions; this then covers the
		 * multikey case.
		 */
		*klen = dlen - CGA_PARAM_LEN;
	}
	cga_cleanup_ctx(cga);

	return (r);
}

int
snd_is_lcl_cga(struct in6_addr *a, int ifidx)
{
	cga_ctx_t ctx[1];
	struct snd_cga_params *p = snd_find_params_byaddr(a, ifidx);
	struct cga_parsed_params ws[1];

	cga_init_ctx(ctx);
	cga_set_der(ctx, p->der, p->dlen);
	cga_set_sec(ctx, p->sec);
	cga_set_addr(ctx, a);

	ws->buf = p->der;
	ws->dlen = p->dlen;
	cga_parse_params(ws);

	/* Change prefix to addr's */
	memcpy(ws->pfx, a->s6_addr, 8);

	if (cga_verify(ctx) == 0) {
		return (1);
	}
	return (0);
}

void
snd_cga_set_keyhash(struct snd_cga_params *p)
{
	struct cga_parsed_params ws[1];

	ws->buf = p->der;
	ws->dlen = p->dlen;
	cga_parse_params(ws);

	SHA1(ws->key, p->dlen - CGA_PARAM_LEN, p->keyhash);
}

int
snd_cga_init(void)
{
	if (cga_init() < 0) {
		return (-1);
	}
	return (0);
}

void
snd_cga_fini(void)
{
}
