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
#include <sys/socket.h>
#include <netinet/in.h>

#include "config.h"
#include <applog.h>
#include "pkixip_ext.h"
#include "pkixip_local.h"

#ifdef	DEBUG
static struct dlog_desc dbg_ver = {
	.desc = "pkix_ipext_ver",
	.ctx = PKIXIP_EXT_CTX
};
static char nbuf[1024];
#endif

/*
 * Returns 1 if pfx1 is within pfx2, 0 if not.
 */
static int
in_pfx(ASN1_BIT_STRING *pfx1, ASN1_BIT_STRING *pfx2)
{
	int bytes1, bits1, bytes2, bits2;
	uint8_t mask, x1, x2;

	bytes1 = pfx1->length;
	bits1 = pfx1->flags & 0x7;
	if (bits1) {
		bytes1--;
		bits1 = 8 - bits1;
	}
	bytes2 = pfx2->length;
	bits2 = pfx2->flags & 0x7;
	if (bits2) {
		bytes2--;
		bits2 = 8 - bits2;
	}

	if (bytes1 < bytes2) {
		return (0);
	}
	if (bytes1 == bytes2 && bits1 < bits2) {
		return (0);
	}

	if (memcmp(pfx1->data, pfx2->data, bytes2) != 0) {
		return (0);
	}
	if (!bits2) {
		return (1);
	}

	mask = 0xff;
	mask <<= (8 - bits2);
	x1 = pfx1->data[bytes2];
	x2 = pfx2->data[bytes2];

	if ((x1 & mask) <= (x2 & mask)) {
		return (1);
	}

	return (0);
}

static int
in_range(ASN1_BIT_STRING *min1, ASN1_BIT_STRING *max1, ASN1_BIT_STRING *min2,
    ASN1_BIT_STRING *max2, int af)
{
	BIGNUM bpmin[1], bpmax[1], bmin[1], bmax[1];
	int alen, len, bits;
	uint8_t mask, buf[sizeof (struct in6_addr)];

	BN_init(bpmin); BN_init(bpmax); BN_init(bmin); BN_init(bmax);
	switch (af) {
	case AF_INET:
		alen = sizeof (struct in_addr);
		break;
	case AF_INET6:
		alen = sizeof (struct in6_addr);
		break;
	default:
		DBG(&dbg_ver, "Unsupported AF");
		return (0);
	}

	len = min1->length < alen ? min1->length : alen;
	memset(buf, 0, sizeof (buf));
	memcpy(buf, min1->data, len);
	if (!BN_bin2bn(buf, alen, bpmin)) {
		return (0);
	}

	len = max1->length < alen ? max1->length : alen;
	memset(buf, 0xff, sizeof (buf));
	memcpy(buf, max1->data, len);
	bits = max1->flags & 0x7;
	if (bits) {
		mask = 0xff;
		mask >>= bits;
		buf[len - 1] |= mask;
	}
	if (!BN_bin2bn(buf, alen, bpmax)) {
		return (0);
	}

	len = min2->length < alen ? min2->length : alen;
	memset(buf, 0, sizeof (buf));
	memcpy(buf, min2->data, len);
	if (!BN_bin2bn(buf, alen, bmin)) {
		return (0);
	}

	len = max2->length < alen ? max2->length : alen;
	memset(buf, 0xff, sizeof (buf));
	memcpy(buf, max2->data, len);
	bits = max2->flags & 0x7;
	if (bits) {
		mask = 0xff;
		mask >>= bits;
		buf[len - 1] |= mask;
	}
	if (!BN_bin2bn(buf, alen, bmax)) {
		return (0);
	}

	/* bmin <= bpmin <= bpmax <= bmax. We already know bpmin <= bpmax */
	if (BN_cmp(bmin, bpmin) == 1) {
		return (0);
	}
	if (BN_cmp(bpmax, bmax) == 1) {
		return (0);
	}

	return (1);
}

static int
aor_match(IPAddressOrRange *aor1, IPAddressOrRange *aor2, int af)
{
	ASN1_BIT_STRING *min1, *max1, *min2, *max2;
#ifdef	DEBUG
	extern void dump_aor(IPAddressOrRange *, int, struct dlog_desc *);

	DBG(&dbg_ver, "AOR1");
	dump_aor(aor1, af, &dbg_ver);
	DBG(&dbg_ver, "AOR2");
	dump_aor(aor2, af, &dbg_ver);
#endif

	if (aor1->type == IP_AOR_RANGE) {
		/* We don't allow ranges in input (for now...) */
		DBG(&dbg_ver, "Ranges not allowed in input");
		return (-1);
	}

	/* Fast case first */
	if (aor1->type == IP_AOR_PREFIX && aor2->type == IP_AOR_PREFIX &&
	    in_pfx(aor1->u.addressPrefix, aor2->u.addressPrefix)) {
		return (0);
	}

	/* Now handle ranges */
	if (aor1->type == IP_AOR_RANGE) {
		min1 = aor1->u.addressRange->min;
		max1 = aor1->u.addressRange->max;
	} else if (aor1->type == IP_AOR_PREFIX) {
		min1 = aor1->u.addressPrefix;
		max1 = aor1->u.addressPrefix;
	} else {
		DBG(&dbg_ver, "Bad AOR type %d", aor1->type);
		return (-1);
	}
	if (aor2->type == IP_AOR_RANGE) {
		min2 = aor2->u.addressRange->min;
		max2 = aor2->u.addressRange->max;
	} else if (aor2->type == IP_AOR_PREFIX) {
		min2 = aor2->u.addressPrefix;
		max2 = aor2->u.addressPrefix;
	} else {
		DBG(&dbg_ver, "Bad AOR type %d", aor2->type);
		return (-1);
	}

	return (in_range(min1, max1, min2, max2, af) ? 0 : -1);
}

static int
af_cmp(IPAddressFamily *ipf1, IPAddressFamily *ipf2)
{
	IPAddressChoice *ipc1, *ipc2;
	IPAddressOrRange *aor1, *aor2;
	int i, j, af = 0;
	uint16_t fam;

	ipc1 = ipf1->ipAddressChoice;
	ipc2 = ipf2->ipAddressChoice;
	if (ipc1->type == IPA_CHOICE_INHERIT ||
	    ipc2->type == IPA_CHOICE_INHERIT) {
		DBG(&dbg_ver, "Inherit choice not allowed in input");
		return (-1);
	}

	memcpy(&fam, ipf1->addressFamily->data, 2);
	fam = ntohs(fam);
	switch (fam) {
	case IANA_AF_IPV4:
		af = AF_INET;
		break;
	case IANA_AF_IPV6:
		af = AF_INET6;
		break;
	}

	DBG(&dbg_ver, "Pre-cmp ipc AOR count: %d",
	    sk_num(ipc1->u.addressesOrRanges));

	for (i = 0; i < sk_num(ipc1->u.addressesOrRanges); i++) {
		aor1 =
		    (IPAddressOrRange *)sk_value(ipc1->u.addressesOrRanges, i);
		for (j = 0; j < sk_num(ipc2->u.addressesOrRanges); j++) {
			aor2 = (IPAddressOrRange *)
			    sk_value(ipc2->u.addressesOrRanges, j);
			if (aor_match(aor1, aor2, af) == 0) {
				sk_delete(ipc1->u.addressesOrRanges, i--);
				IPAddressOrRange_free(aor1);
				break;
			}
		}
	}

	DBG(&dbg_ver, "Post-cmp ipc AOR count: %d",
	    sk_num(ipc1->u.addressesOrRanges));

	if (sk_num(ipc1->u.addressesOrRanges) == 0) {
		return (0);
	}

	DBG(&dbg_ver, "Match failed");
	return (-1);
}

int
af_match(IPAddressFamily *ipf1, IPAddressFamily *ipf2)
{
	int safi1 = IANA_SAFI_UNICAST;
	int safi2 = IANA_SAFI_UNICAST;

	if (memcmp(ipf1->addressFamily->data, ipf2->addressFamily->data, 2)) {
		return (0);
	}

	if (ipf1->addressFamily->length >= 3) {
		safi1 = ipf1->addressFamily->data[2];
	}
	if (ipf2->addressFamily->length >= 3) {
		safi2 = ipf2->addressFamily->data[2];
	}

	return (safi1 == safi2);
}

static inline
int is_inherit(IPAddressFamily *ipf)
{
	return (ipf->ipAddressChoice->type == IPA_CHOICE_INHERIT);
}

static int
verify_ipext_cert(X509_STORE_CTX *ctx, int idx, X509 *x, IPAddrBlocks *vipb)
{
	IPAddrBlocks *ipb;
	IPAddressFamily *ipf1, *ipf2;
	int i, j, inherit = 0;

	DBG(&dbg_ver, "vipb stack cnt: %d idx: %d", sk_num(vipb), idx);

	ipb = X509_get_ext_d2i(x, pkix_ip_ext_method.ext_nid, NULL, NULL);
	if (!ipb) {
		DBG(&dbg_ver, "Missing PKIX IP Extension");
		return (-1);
	}

	for (i = 0; i < sk_num(vipb); i++) {
		ipf1 = (IPAddressFamily *)sk_value(vipb, i);

		/* Ignore inherits in vipb */
		if (is_inherit(ipf1)) {
			sk_delete(vipb, i--);
			IPAddressFamily_free(ipf1);
			continue;
		}

		for (j = 0; j < sk_num(ipb); j++) {
			ipf2 = (IPAddressFamily *)sk_value(ipb, j);
			if (af_match(ipf1, ipf2)) {
				/*
				 * Inherits in ipb need to be checked
				 * recursively.
				 */
				if (is_inherit(ipf2)) {
					inherit = 1;
					break;
				}

				if (af_cmp(ipf1, ipf2) == 0) {
					sk_delete(vipb, i--);
					IPAddressFamily_free(ipf1);
					break;
				}
			}
		}
	}

	if (!inherit || (++idx) == sk_num(ctx->chain)) {
		/* end of the line */
		goto done;
	}
	x = (X509 *)sk_value(ctx->chain, idx);
	verify_ipext_cert(ctx, idx, x, vipb);

done:
	IPAddrBlocks_free(ipb);

	/* If the vipb stack is now empty all ipf's matched */
	if (sk_num(vipb) != 0) {
		return (-1);
	}

	return (0);
}

static int
verify_ipext(X509_STORE_CTX *ctx, IPAddrBlocks *vipb)
{
	int i;
	X509 *x;

#ifdef	DEBUG
	DBG(&dbg_ver, "Verifying against IPAddrBlock:");
	X509V3_EXT_val_prn(BIO_new_fp(stdout, BIO_NOCLOSE),
			   i2v_IPAddrBlocks(NULL, vipb, NULL), 8, 1);
#endif

	if (sk_num(vipb) == 0) {
		DBG(&dbg_ver, "IPAddrBlock empty; rejecting");
		return (-1);
	}

	for (i = 0; i < sk_num(ctx->chain); i++) {
		x = (X509 *)sk_value(ctx->chain, i);

		DBG(&dbg_ver, "%s",
		    X509_NAME_oneline(X509_get_subject_name(x), nbuf,
				      sizeof (nbuf)));

		if (verify_ipext_cert(ctx, i, x, vipb) < 0) {
			return (-1);
		}
		if (sk_num(vipb) == 0) {
			break;
		}
	}

	return (0);
}

static int
verify_ipext_chain(X509_STORE_CTX *ctx)
{
	int i;
	X509 *x, *vx;
	IPAddrBlocks *ipb;

	DBG(&dbg_ver, "Verifying IP Exts in the certificate chain");

	for (i = 1; i < sk_num(ctx->chain); i++) {
		vx = (X509 *)sk_value(ctx->chain, i - 1);
		x = (X509 *)sk_value(ctx->chain, i);

		DBG(&dbg_ver, "%s",
		    X509_NAME_oneline(X509_get_subject_name(vx), nbuf,
				      sizeof (nbuf)));

		ipb = X509_get_ext_d2i(vx, pkix_ip_ext_method.ext_nid, NULL,
		    NULL);
		if (!ipb) {
			DBG(&dbg_ver, "Missing PKIX IP Extension");
			return (-1);
		}

		X509V3_EXT_val_prn(BIO_new_fp(stdout, BIO_NOCLOSE),
				   i2v_IPAddrBlocks(NULL, ipb, NULL), 8, 1);

		if (verify_ipext_cert(ctx, i, x, ipb) < 0) {
			DBG(&dbg_ver, "verification failure");
			IPAddrBlocks_free(ipb);
			return (-1);
		}
		IPAddrBlocks_free(ipb);
	}

	return (0);
}

int
pkixip_verify_cb(int ok, X509_STORE_CTX *ctx)
{
#ifdef	DEBUG
	X509 *x = X509_STORE_CTX_get_current_cert(ctx);

	X509_NAME_oneline(X509_get_subject_name(x), nbuf, sizeof (nbuf));
#endif
	if (!ok) {
		if (ctx->error == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) {
			/*
			 * OpenSSL doesn't explicitly support PKIX IP Ext,
			 * so it throws this error when it encounters the
			 * extension in the verification process. We
			 * ignore it so the verification can proceed.
			 */
			ok = 1;
			DBG(&dbg_ver, "OK at %s", nbuf);
		} else {
			DBG(&dbg_ver, "Not OK at %s", nbuf);
			DBG(&dbg_ver, "%s",
			    X509_verify_cert_error_string(ctx->error));
		}
	} else {
		DBG(&dbg_ver, "OK at %s", nbuf);
	}

	return (ok);
}

int
pkixip_verify_cert(X509 *x, IPAddrBlocks *ipb)
{
	int r = 0;
	X509_STORE_CTX *ctx;
	DEFINE_TIMESTAMP_VARS();

	if ((ctx = pkixip_get_store_ctx()) == NULL) {
		return (-1);
	}

	DBG(&dbg_ver, "Certificate to be verified: %s",
	    X509_NAME_oneline(X509_get_subject_name(x), nbuf, sizeof (nbuf)));

	X509_STORE_CTX_set_cert(ctx, x);
	X509_STORE_CTX_set_verify_cb(ctx, pkixip_verify_cb);

	TIMESTAMP_START();
	if (X509_verify_cert(ctx) == 0) {
		TIMESTAMP_END("X509 chain verification (fail)");
		pkixip_ssl_err(__FUNCTION__, "X509_verify_cert failed");
		r = -1;
		goto done;
	}
	TIMESTAMP_END("X509 chain verification");

	if (ipb == NULL) {
		goto done;
	}

	if (verify_ipext_chain(ctx) < 0) {
		r = -1;
		goto done;
	}

	/* Finally verify the given ipb against the IP exts in the chain */
	DBG(&dbg_ver, "Verifying ipb against chain IP exts");
	TIMESTAMP_START();
	r = verify_ipext(ctx, ipb);
	TIMESTAMP_END("PKIX IP extension chain verification");

done:
	pkixip_store_ctx_light_cleanup(ctx);
	return (r);
}

int
pkixip_verify_init(void)
{
#ifdef	DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg_ver,
		NULL
	};

	if (applog_register(dbgs) < 0) {
		return (1);
	}
#endif

	return (0);
}
