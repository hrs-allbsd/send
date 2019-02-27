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

#ifndef	_PKIXIP_EXT_H
#define	_PKIXIP_EXT_H

#include <stdint.h>
#include <openssl/x509.h>
#include "pkixip_ext_asn.h"

#define	PKIXIP_STORE_BYSUBJ	0

struct pkixip_config {
	char *trustedcert;
	char *outfile;
	char *cacert;
	char *capriv;
	char *certfile;
};

extern int pkixip_aor_cmp(const char * const *, const char * const *);
extern int pkixip_ipf_cmp(const char * const *, const char * const *);

extern int pkixip_add2stores_cert(X509 *);
extern int pkixip_add2stores_file(const char *);
extern int pkixip_add_store(int *, int (*cmp)(X509_OBJECT **, X509_OBJECT **));
extern void *pkixip_find_cert(void *, int);
extern STACK *pkixip_get_mychain(void);
extern X509_STORE_CTX *pkixip_get_store_ctx(void);
extern int pkixip_has_ext(X509 *x);
extern X509 *pkixip_load_cert(const char *);
extern int pkixip_my_chain_init(X509 *);
extern void pkixip_set_trustanchor_cb(void (*)(X509 *));
extern void pkixip_set_wrapper(void *(*)(X509 *));
extern int pkixip_sign(X509 *, X509 *, EVP_PKEY *);
extern int pkixip_write_ext(X509 *, const char *, IPAddrBlocks *, X509 *,
    EVP_PKEY *);
extern EVP_PKEY *pkixip_load_pkey(const char *);
extern int pkixip_verify_cert(X509 *, IPAddrBlocks *);
extern int pkixip_read_config(const char *f, struct pkixip_config *,
    IPAddrBlocks **);
extern void pkixip_store_ctx_light_cleanup(X509_STORE_CTX *);
extern void pkixip_walk_store(int (*)(X509 *, void *), void *, int);

extern int pkixip_init(void);
extern const char *pkixip_version;

#endif	/* _PKIXIP_EXT_H */
