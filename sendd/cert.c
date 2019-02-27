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
#include <openssl/x509.h>

#include "config.h"
#include <applog.h>
#include <pkixip_ext.h>
#include <cga_keyutils.h>

#include "sendd_local.h"
#include "snd_proto.h"
#include "snd_config.h"
#include "os/os_defines.h"
#include "dbg.h"

#ifdef	DEBUG
static struct dlog_desc dbg = {
	.desc = "cert",
	.ctx = SENDD_NAME
};
static char nbuf[1024];
#endif

static int store_bykhash_handle = -1;

#ifdef	LOG_TIMESTAMP
static struct timeval deferred_ts[1];
#endif

STACK_OF(X509) *snd_trustanchors;

struct khash_wrapper {
	X509	*x;
	uint8_t	khash[SHA_DIGEST_LENGTH];
};

static int
get_pubkeyhash(X509 *x, uint8_t *buf)
{
	uint8_t *der;
	EVP_PKEY *k;
	int dlen;

	k = X509_PUBKEY_get(x->cert_info->key);
	if ((der = cga_key2der(k, &dlen)) == NULL) {
		return (-1);
	}

	SHA1(der, dlen, buf);
	return (0);
}

static int
cmp_khash(X509_OBJECT **a, X509_OBJECT **b)
{
	struct khash_wrapper *w1, *w2;

	w1 = (struct khash_wrapper *)*a;
	w2 = (struct khash_wrapper *)*b;

	return (memcmp(w1->khash, w2->khash, SND_KEYHASH_LEN));
}

static void *
wrap_cert(X509 *x)
{
	struct khash_wrapper *w;

	DBG(&dbg, "");

	if ((w = malloc(sizeof (*w))) == NULL) {
		APPLOG_NOMEM();
		return (NULL);
	}

	w->x = x;
	if (get_pubkeyhash(x, w->khash) < 0) {
		free(w);
		return (NULL);
	}

	return (w);
}

static void
set_trustanchor(X509 *x)
{
	if (snd_trustanchors ||
	    (snd_trustanchors = sk_new_null()) != NULL) {
		sk_X509_push(snd_trustanchors, x);
		DBG(&dbg, "added %s", snd_x509_name(x, nbuf, sizeof (nbuf)));
	}
}

static X509 *
find_cert_by_keyhash(uint8_t *khash)
{
	struct khash_wrapper w[1], *r;

	w->x = NULL;
	memcpy(w->khash, khash, sizeof (w->khash));

	r = pkixip_find_cert(w, store_bykhash_handle);

	return (r ? r->x : NULL);
}

int
snd_can_verify_now(uint8_t *khash, void **x)
{
	if ((*x = find_cert_by_keyhash(khash)) == NULL) {
		DBG(&dbg, "Need to retrieve key");
		return (0);
	}
	if (!snd_have_chain(*x)) {
		DBG(&dbg, "Don't have full chain");
		return (0);
	}

	return (1);
}

/*
 * Returns 1 if it is done with the CP and it should be deleted, 0
 * otherwise.
 *
 * ipb is of type IPAddrBlocks.
 */
int
snd_cert_rcvd(uint8_t *khash, void *ipb, void *pi, int empty)
{
	int ok = 1;
	void *x = NULL; /* X509 */

	if (empty) {
		/* router could not provide chain */
		ok = 0;
		goto finish;
	}
	if (!snd_can_verify_now(khash, (void **)&x)) {
		DBG(&dbg, "Can't verify yet");
		return (0);
	}
	DBG(&dbg, "Ready to verify");

	if (snd_conf_get_int(snd_accept_unconstrained_ra) &&
	    !pkixip_has_ext(x)) {
		DBG(&dbg, "Unconstrained certificate");
		ipb = NULL;
	}

	if (pkixip_verify_cert(x, ipb) < 0) {
		DBG(&dbg_snd, "certificate chain verification failed");
		ok = 0;
	}
finish:
	TIMESTAMP_END_GLOBAL(deferred_ts, "Deferred verification complete");
	snd_finish_racheck(pi, ok);

	return (1);
}

#ifdef	USE_CONSOLE
void
dump_trustanchors(void)
{
	extern STACK_OF(X509) *snd_trustanchors;
	X509 *x;
	int i;
	char buf[1024];

	if (sk_num(snd_trustanchors) == 0) {
		printf("<not set>\n");
		return;
	}
	for (i = 0; i < sk_num(snd_trustanchors); i++) {
		x = sk_X509_value(snd_trustanchors, i);
		printf("%s\n", snd_x509_name(x, buf, sizeof (buf)));
	}

}
#endif

int
snd_init_cert(void)
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

	if (pkixip_add_store(&store_bykhash_handle, cmp_khash) < 0) {
		return (-1);
	}
	pkixip_set_wrapper(wrap_cert);
	pkixip_set_trustanchor_cb(set_trustanchor);

	return (0);
}
