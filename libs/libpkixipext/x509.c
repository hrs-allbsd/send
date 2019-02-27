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
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/pem.h>

#include "config.h"
#include <applog.h>
#include "pkixip_ext.h"
#include "pkixip_ext_asn.h"
#include "pkixip_local.h"

#ifdef	DEBUG
static struct dlog_desc dbg_x509 = {
	.desc = "pkix_ipext_x509",
	.ctx = PKIXIP_EXT_CTX
};
static char nbuf[1024];
#endif
extern int pkixip_verify_cb(int, X509_STORE_CTX *);

X509V3_EXT_METHOD pkix_ip_ext_method = {
	ext_flags : X509V3_EXT_MULTILINE,
	it : ASN1_ITEM_ref(IPAddrBlocks),
	i2v : (X509V3_EXT_I2V)i2v_IPAddrBlocks,
};

static STACK *stores[PKIXIP_MAX_STORES];
static X509_STORE_CTX *ctx_bysubj;
static int next_store = 1;
static void *(*wrap_store_cert)(X509 *x);
static void (*trustanchor_cb)(X509 *x);
pthread_mutex_t stores_lock = PTHREAD_MUTEX_INITIALIZER;

static STACK *mychain;

/* Lifted from openssl x509_lu.c */
static int
x509_object_cmp(X509_OBJECT **a, X509_OBJECT **b)
{
 	int ret;

 	ret=((*a)->type - (*b)->type);
 	if (ret) return ret;
 	switch ((*a)->type) {
 	case X509_LU_X509:
 		ret=X509_subject_name_cmp((*a)->data.x509,(*b)->data.x509);
 		break;
 	case X509_LU_CRL:
 		ret=X509_CRL_cmp((*a)->data.crl,(*b)->data.crl);
 		break;
	default:
		/* abort(); */
		return 0;
	}
	return ret;
}

static int
x509_bysubj_cmp(const char * const *a, const char * const *b)
{
	X509 *n1, *n2;

	n1 = (X509 *)*a;
	n2 = (X509 *)*b;
	return X509_NAME_cmp(X509_get_subject_name(n1),
			     X509_get_subject_name(n2));
}

void
pkixip_ssl_err(const char *func, const char *context) {
	int err, i;
#ifdef	DEBUG
	char buf[120];
#endif	
	/*
	 * We do this stuff with i here since we don't really
	 * trust the SSL error stack stuff.
	 */
	for (i = 10; (err = ERR_get_error()) != 0 && i > 0; i--) {
		DBG(&dbg_x509, "%s: %s: %s", func, context,
		     ERR_error_string(err, buf));
	}
}

X509 *
pkixip_load_cert(const char *f)
{
	FILE *fp;
	X509 *x = NULL;

	if ((fp = fopen(f, "r")) == NULL) {
		applog(LOG_ERR, "%s: fopen(%s) failed: %s", __FUNCTION__,
		       f, strerror(errno));
		return (NULL);
	}

	x = PEM_read_X509(fp, NULL, NULL, NULL);
	if (x == NULL) {
		pkixip_ssl_err(__FUNCTION__, "PEM_read_x509 failed");
	}
	fclose(fp);

	return (x);
}
int
pkixip_sign(X509 *x, X509 *cax, EVP_PKEY *pkey)
{
	if (!X509_set_issuer_name(x, X509_get_subject_name(cax))) {
		pkixip_ssl_err(__FUNCTION__, "Setting issuer name");
		return (-1);
	}

	if (X509_gmtime_adj(X509_get_notBefore(x), 0) == NULL) {
		pkixip_ssl_err(__FUNCTION__, "Setting notBefore");
		return (-1);
	}

	if (X509_gmtime_adj(X509_get_notAfter(x), 60*60*24*365) == NULL) {
		pkixip_ssl_err(__FUNCTION__, "Setting notAfter");
		return (-1);
	}

	if (!X509_sign(x, pkey, EVP_md5())) {
		pkixip_ssl_err(__FUNCTION__, "X509_sign");
		return (-1);
	}

	return (0);
}

int
pkixip_write_ext(X509 *x, const char *f, IPAddrBlocks *ipb, X509 *cax,
    EVP_PKEY *pkey)
{
	FILE *fp;
	X509_EXTENSION *ex;
	int pos, rv;

	pos = X509_get_ext_by_NID(x, pkix_ip_ext_method.ext_nid, -1);
	if (pos != -1) {
		DBG(&dbg_x509, "removing old extension");
		ex = X509_delete_ext(x, pos);
		if (ex == NULL) {
			DBG(&dbg_x509, "could not remove old extension");
			return (-1);
		}
		X509_EXTENSION_free(ex);
	}

	ex = X509V3_EXT_i2d(pkix_ip_ext_method.ext_nid, 0, ipb);
	if (ex == NULL) {
		pkixip_ssl_err(__FUNCTION__, "X509V3_EXT_i2d() failed");
		return (-1);
	}
	if (X509_EXTENSION_set_critical(ex, 1) == 0) {
		pkixip_ssl_err(__FUNCTION__, "X509_EXTENSION_set_critical() "
			       "failed");
		return (-1);
	}
	X509_add_ext(x, ex, -1);
	X509_EXTENSION_free(ex);

	if ((cax && !pkey) || (!cax && pkey)) {
		DBG(&dbg_x509, "Must set both CA cert and CA privkey to "
		    "re-sign");
		return (-1);
	}

	if (cax && pkey && pkixip_sign(x, cax, pkey) < 0) {
		return (-1);
	}

	if ((fp = fopen(f, "w")) == NULL) {
		DBG(&dbg_x509, "fopen failed: %s", strerror(errno));
		return (-1);
	}

	if (PEM_write_X509(fp, x) == 1) {
		rv = 0;
	} else {
		pkixip_ssl_err(__FUNCTION__, "PEM_write_x509 failed");
		rv = -1;
	}
	fclose(fp);

	return (rv);
}

EVP_PKEY *
pkixip_load_pkey(const char *f)
{
	EVP_PKEY *pkey;
	FILE *fp;

	if ((fp = fopen(f, "r")) == NULL) {
		DBG(&dbg_x509, "fopen failed: %s", strerror(errno));
		return (NULL);
	}

	if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
		pkixip_ssl_err(__FUNCTION__, "PEM_read_PrivateKey failed");
	}

	fclose(fp);
	return (pkey);
}

static STACK *
pkixip_get_store(int handle)
{
	if (handle >= PKIXIP_MAX_STORES || handle < 0) {
		DBG(&dbg_x509, "Handle out of range (%d)", handle);
		return (NULL);
	}

	return (stores[handle]);
}

void
pkixip_walk_store(int (*cb)(X509 *, void *), void *cookie, int handle)
{
	STACK *objs;
	int i;
	X509_OBJECT *xo;

	pthread_mutex_lock(&stores_lock);
	if ((objs = pkixip_get_store(handle)) == NULL) {
		goto done;
	}

	for (i = 0; i < sk_num(objs); i++) {
		xo = sk_X509_OBJECT_value(objs, i);
		if (xo->type != X509_LU_X509) {
			continue;
		}
		if (!cb(xo->data.x509, cookie)) {
			break;
		}
	}
done:
	pthread_mutex_unlock(&stores_lock);
}

void *
pkixip_find_cert(void *k, int handle)
{
	STACK *store;
	int i;
	void *r = NULL;

	pthread_mutex_lock(&stores_lock);
	if ((store = pkixip_get_store(handle)) == NULL) {
		goto done;
	}

	if ((i = sk_find(store, k)) < 0) {
		goto done;
	}

	r = sk_value(store, i);

done:
	pthread_mutex_unlock(&stores_lock);
	return (r);
}

/* Caller must hold stores_lock */
static int
pkixip_do_add_store(int handle, int (*cmp)(X509_OBJECT **, X509_OBJECT **),
    STACK *objs)
{
	if (objs == NULL && (objs = sk_X509_OBJECT_new(cmp)) == NULL) {
		applog(LOG_CRIT, "no memory");
		return (-1);
	}

	stores[handle] = objs;
	return (0);
}

int
pkixip_add_store(int *handle, int (*cmp)(X509_OBJECT **, X509_OBJECT **))
{
	int r = 0;

	pthread_mutex_lock(&stores_lock);

	if (next_store == PKIXIP_MAX_STORES) {
		DBG(&dbg_x509, "Stores table full");
		r = -1;
		goto done;
	}

	if (pkixip_do_add_store(next_store, cmp, NULL) < 0) {
		r = -1;
		goto done;
	}

	*handle = next_store++;

done:
	pthread_mutex_unlock(&stores_lock);
	return (r);
}

X509_STORE_CTX *
pkixip_get_store_ctx(void)
{
	X509_STORE *st;

	if (ctx_bysubj != NULL) {
		return (ctx_bysubj);
	}

	if ((st = X509_STORE_new()) == NULL) {
		applog(LOG_CRIT, "no memory");
		return (NULL);
	}

	if ((ctx_bysubj = X509_STORE_CTX_new()) == NULL) {
		applog(LOG_CRIT, "no memory");
		return (NULL);
	}

	if (X509_STORE_CTX_init(ctx_bysubj, st, NULL, NULL) != 1) {
		pkixip_ssl_err(__FUNCTION__, "X509_STORE_CTX_init failed");
		X509_STORE_free(st);
		X509_STORE_CTX_free(ctx_bysubj);
		ctx_bysubj = NULL;
		return (NULL);
	}

	pthread_mutex_lock(&stores_lock);
	if (pkixip_do_add_store(PKIXIP_STORE_BYSUBJ, x509_object_cmp, st->objs)
	    < 0) {
		X509_STORE_free(st);
		X509_STORE_CTX_free(ctx_bysubj);
		ctx_bysubj = NULL;
		pthread_mutex_unlock(&stores_lock);
		return (NULL);
	}
	pthread_mutex_unlock(&stores_lock);

	return (ctx_bysubj);
}

static void noop_free(void *x) {}

/*
 * Does a light cleanup on a CTX so it can be reused for future verifications:
 * Flushes the CTX chain without free'ing the certs (since they are still
 * in the backing store) -- is this right? The code for X509_STORE_CTX_cleanup
 * seems to free the certs in the chain, which should cause problems if
 * we wish to continue using the store. Need to double check.
 */
void
pkixip_store_ctx_light_cleanup(X509_STORE_CTX *ctx)
{
//	X509_STORE_CTX_cleanup(ctx);

	if (ctx->chain != NULL) {
		sk_X509_pop_free(ctx->chain, noop_free);
		ctx->chain=NULL;
	}
	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509_STORE_CTX, ctx,
			    &(ctx->ex_data));
	memset(&ctx->ex_data,0,sizeof(CRYPTO_EX_DATA));

#if 0
	while (sk_num(ctx->chain) > 0) {
		sk_pop(ctx->chain);
	}
#endif
}

int
pkixip_add2stores_file(const char *f)
{
	X509 *x;
	FILE *fp;
	int rv = 0;

	if ((fp = fopen(f, "r")) == NULL) {
		DBG(&dbg_x509, "%s: fopen failed: %s", __FUNCTION__,
		     strerror(errno));
		return (-1);
	}

	while ((x = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
		if (pkixip_add2stores_cert(x) < 0) {
			rv = -1;
			goto done;
		}
		if (trustanchor_cb) {
			trustanchor_cb(x);
		}
	}

done:
	fclose(fp);
	return (rv);
}

int
pkixip_add2stores_cert(X509 *x)
{
	int i, r = 0;
	X509_STORE_CTX *ctx;
	void *wrapper;
	X509_OBJECT o[1];

	if ((ctx = pkixip_get_store_ctx()) == NULL) {
		return (-1);
	}

	pthread_mutex_lock(&stores_lock);

	if (X509_STORE_get_by_subject(ctx, X509_LU_X509,
	    X509_get_subject_name(x), o) != 0) {
		DBG(&dbg_x509, "Cert already in stores");
		goto done;
	}

	if (X509_STORE_add_cert(ctx->ctx, x) != 1) {
		pkixip_ssl_err(__FUNCTION__, "X509_STORE_add_cert() failed");
		r = -1;
		goto done;
	}

	if (wrap_store_cert) {
		if ((wrapper = wrap_store_cert(x)) == NULL) {
			return (-1);
		}
	} else {
		wrapper = x;
	}

	for (i = 1; i < PKIXIP_MAX_STORES; i++) {
		if (stores[i]) {
			sk_push(stores[i], wrapper);
		}
	}

	DBG(&dbg_x509, "Added %s",
	    X509_NAME_oneline(X509_get_subject_name(x), nbuf, sizeof (nbuf)));

done:
	pthread_mutex_unlock(&stores_lock);
	return (r);
}

void
pkixip_set_wrapper(void *(*w)(X509 *))
{
	wrap_store_cert = w;
}

void
pkixip_set_trustanchor_cb(void (*cb)(X509 *))
{
	trustanchor_cb = cb;
}

int
pkixip_my_chain_init(X509 *mycert)
{
	X509_STORE_CTX *ctx;
	int r = 0;

	DBG(&dbg_x509, "%s",
	    X509_NAME_oneline(X509_get_subject_name(mycert), nbuf,
			      sizeof (nbuf)));

	if ((ctx = pkixip_get_store_ctx()) == NULL) {
		return (-1);
	}

	X509_STORE_CTX_set_cert(ctx, mycert);
	X509_STORE_CTX_set_verify_cb(ctx, pkixip_verify_cb);

	if (X509_verify_cert(ctx) == 0) {
		pkixip_ssl_err(__FUNCTION__, "X509_verify_cert failed");
		r = -1;
		goto done;
	}

	if (mychain != NULL) {
		sk_free(mychain);
	}
	if ((mychain = sk_dup(ctx->chain)) == NULL) {
		APPLOG_NOMEM();
		r = -1;
		goto done;
	}
	sk_set_cmp_func(mychain, x509_bysubj_cmp);
	DBG(&dbg_x509, "mychain verified and set");

done:
	pkixip_store_ctx_light_cleanup(ctx);
	return (r);
}

STACK *
pkixip_get_mychain(void)
{
	return (mychain);
}

int
pkixip_has_ext(X509 *x)
{
	if (X509_get_ext_by_NID(x, pkix_ip_ext_method.ext_nid, -1) != -1) {
		return (1);
	}
	return (0);
}

int
pkixip_x509_init(void)
{
#ifdef	DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg_x509,
		NULL
	};

	if (applog_register(dbgs) < 0) {
		return (1);
	}
#endif

	pkix_ip_ext_method.ext_nid = OBJ_create("1.3.6.1.5.5.7.1.7",
						"PKIX_IP_EXT",
						"PKIX IP Addr Extension");
	if (pkix_ip_ext_method.ext_nid == 0) {
		pkixip_ssl_err(__FUNCTION__, "OBJ_create failed");
		return (-1);
	}

	DBG(&dbg_x509, "Got NID %d", pkix_ip_ext_method.ext_nid);
	if (X509V3_EXT_add(&pkix_ip_ext_method) != 1) {
		pkixip_ssl_err(__FUNCTION__, "X509V3_EXT_add() failed");
		return (-1);
	}

	return (0);
}
