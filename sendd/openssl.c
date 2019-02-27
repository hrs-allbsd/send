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
#include <pthread.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include "config.h"
#include <pkixip_ext.h>
#include <applog.h>

#include "sendd_local.h"
#include "snd_config.h"
#include "dbg.h"

#ifdef	DEBUG
static struct dlog_desc dbg = {
	.desc =	"crypto",
	.ctx =	SENDD_NAME
};
struct dlog_desc dbg_cryptox = {
	.desc =	"crypto_extra",
	.ctx =	SENDD_NAME
};
#endif

static char nbuf[1024]; /* for displaying X509_NAMEs */

static pthread_mutex_t *lock_cs;
static int numlocks;
static X509 *host_cert;

static void
ssl_locking_callback(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(lock_cs + n);
	} else {
		pthread_mutex_unlock(lock_cs + n);
	}
}

static int
ssl_thread_init(void)
{
	int i;

	numlocks = CRYPTO_num_locks();
	if ((lock_cs = malloc(numlocks * sizeof (*lock_cs))) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (-1);
	}

	for (i = 0; i < numlocks; i++) {
		pthread_mutex_init(lock_cs + i, NULL);
	}

	CRYPTO_set_locking_callback(ssl_locking_callback);

	return (0);
}

#if 0
/* not used for now */
static void
ssl_thread_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);

	for (i = 0; i < numlocks; i++) {
		pthread_mutex_destroy(lock_cs + i);
	}

	free(lock_cs);
}
#endif

/**
 * Converts the most recent SSL error message(s) into normal log
 * format.
 *
 * func: the name of the calling function
 * context: a message providing context for the error
 */
void
snd_ssl_err(const char *func, const char *context) {
#ifdef	DEBUG
	char buf[512];
	unsigned int err;

	err = ERR_get_error();
	ERR_error_string_n(err, buf, sizeof (buf));
	DBGF(&dbg, (char *)func, "%s: %s", context, buf);
	     
#endif
}

void
snd_print_cert(void)
{
	if (host_cert == NULL) {
		printf("Certificate not set\n");
		return;
	}

	X509_print_fp(stdout, host_cert);
}

static int
store_walker(X509 *x, void *cookie)
{
	X509_NAME_oneline(X509_get_subject_name(x), nbuf, sizeof (nbuf));
	printf("%s\n", nbuf);

	return (1);
}

void
snd_pkixip_walk_store(void)
{
	pkixip_walk_store(store_walker, NULL, PKIXIP_STORE_BYSUBJ);
}

int
snd_pkixip_config(void)
{
	struct pkixip_config cf[1];
	const char *f = snd_conf_get_str(snd_pkixip_conf);

	if (f == NULL) {
		DBG(&dbg, "PKIX IP Config file not set (OK if we are not "
		    "participating in router discovery");
		return (0);
	}

	memset(cf, 0, sizeof (*cf));
	if (pkixip_read_config(f, cf, NULL) < 0) {
		DBG(&dbg, "pkixip_read_config() failed for %s", f);
		return (-1);
	}
	if (cf->certfile == NULL) {
		/* Not necessary unless we are a router */
		DBG(&dbg, "no host cert (OK if we are not a router)");
		return (0);
	}

	/* Set up local cert chain */
	if ((host_cert = pkixip_load_cert(cf->certfile)) == NULL) {
		return (-1);
	}
	if (pkixip_my_chain_init(host_cert) < 0) {
		applog(LOG_ERR, "%s: Could not initialize local cert chain",
		       __FUNCTION__);
		return (-1);
	}

	return (0);
}

char *
snd_x509_name(void *p, char *buf, int blen)
{
	X509 *x = p;
	X509_NAME *dn;

	dn = X509_get_subject_name(x);
	X509_NAME_oneline(dn, buf, blen);

	return (buf);
}

static inline int
selfsigned(X509_NAME *sub, X509_NAME *iss)
{
	return (X509_NAME_cmp(sub, iss) == 0);
}

int
snd_have_chain(void *a)
{
	X509_STORE_CTX *ctx = pkixip_get_store_ctx();
	X509 *tx = a;
	X509_NAME *subj, *iss;
	X509_OBJECT obj[1];

	if (ctx == NULL) {
		DBG(&dbg_snd, "pkixip_get_store() failed");
		return (0);
	}

	for (;;) {
		subj = X509_get_subject_name(tx);
		iss = X509_get_issuer_name(tx);
		if (selfsigned(subj, iss)) {
			return (1);
		}
		if (!X509_STORE_get_by_subject(ctx, X509_LU_X509, iss, obj)) {
			DBG(&dbg_snd, "Missing link in cert chain: %s",
			    X509_NAME_oneline(iss, nbuf, sizeof (nbuf)));
			return (0);
		}
		tx = obj->data.x509;
	}

	return (1);
}

int
snd_ssl_init(void)
{
#ifdef	DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg,
		NULL
	};
	struct dlog_desc *dbgsx[] = {
		&dbg_cryptox,
		NULL
	};

	if (snd_applog_register(dbgs) < 0 ||
	    applog_register(dbgsx) < 0) {
		return (-1);
	}
#endif

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	if (ssl_thread_init() < 0) {
		return (-1);
	}
	return (0);
}

void
snd_ssl_fini(void)
{
	DBG(&dbg, "");
	free(lock_cs);
}
