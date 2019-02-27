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
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "config.h"
#include "pkixip_ext_asn.h"

ASN1_SEQUENCE(IPAddressRange) = {
	ASN1_SIMPLE(IPAddressRange, min, ASN1_BIT_STRING),
	ASN1_SIMPLE(IPAddressRange, max, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(IPAddressRange)

ASN1_CHOICE(IPAddressOrRange) = {
	ASN1_SIMPLE(IPAddressOrRange, u.addressPrefix, ASN1_BIT_STRING),
	ASN1_SIMPLE(IPAddressOrRange, u.addressRange, IPAddressRange)
} ASN1_CHOICE_END(IPAddressOrRange)

ASN1_CHOICE(IPAddressChoice) = {
	ASN1_SIMPLE(IPAddressChoice, u.inherit, ASN1_NULL),
	ASN1_SEQUENCE_OF(IPAddressChoice, u.addressesOrRanges, IPAddressOrRange)
} ASN1_CHOICE_END(IPAddressChoice)

ASN1_SEQUENCE(IPAddressFamily) = {
	ASN1_SIMPLE(IPAddressFamily, addressFamily, ASN1_OCTET_STRING),
	ASN1_SIMPLE(IPAddressFamily, ipAddressChoice, IPAddressChoice)
} ASN1_SEQUENCE_END(IPAddressFamily)

ASN1_ITEM_TEMPLATE(IPAddrBlocks) =
	ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, ipAddressFamily, IPAddressFamily)
ASN1_ITEM_TEMPLATE_END(IPAddrBlocks)

IMPLEMENT_ASN1_FUNCTIONS(IPAddressRange)
IMPLEMENT_ASN1_FUNCTIONS(IPAddressOrRange)
IMPLEMENT_ASN1_FUNCTIONS(IPAddressChoice)
IMPLEMENT_ASN1_FUNCTIONS(IPAddressFamily)
IMPLEMENT_ASN1_FUNCTIONS(IPAddrBlocks)

static void
i2v_ipaddr(uint8_t *data, int dlen, char *abuf, int ablen, int af)
{
	char *p;
	int len;

	switch (af) {
	case AF_INET:
	case AF_INET6:
		if (inet_ntop(af, data, abuf, ablen) != NULL) {
			break;
		}
	default:
		p = hex_to_string(data, dlen);
		len = strlen(p);
		len = len < ablen ? len : ablen;
		memcpy(abuf, p, len);
		OPENSSL_free(p);
	}
}

static void
i2v_prefix(ASN1_BIT_STRING *pfx, STACK_OF(CONF_VALUE) *extlist,
    const char *name, int af)
{
	int bytes, bits, plen;
	char abuf[INET6_ADDRSTRLEN + 8], pbuf[8];
	uint8_t ipbuf[16];
	int len;

	bytes = pfx->length;
	bits = pfx->flags & 0x7;
	if (bits) {
		bytes--;
		bits = 8 - bits;
	}

	plen = bytes * 8 + bits;

	memset(ipbuf, 0, sizeof (ipbuf));
	len = pfx->length < sizeof (ipbuf) ? pfx->length : sizeof (ipbuf);
	memcpy(ipbuf, pfx->data, len);
	i2v_ipaddr(ipbuf, len, abuf, sizeof (abuf) - 8, af);

	snprintf(pbuf, sizeof (pbuf), "/%d", plen);
	strncat(abuf, pbuf, sizeof (abuf) - strlen(abuf));
	X509V3_add_value(name, abuf, &extlist);
}

static STACK_OF(CONF_VALUE) *
i2v_IPAddressRange(X509V3_EXT_METHOD *method, IPAddressRange *ipr,
    STACK_OF(CONF_VALUE) *extlist, int af)
{
	char abuf[INET6_ADDRSTRLEN];
	uint8_t ipbuf[16];
	int len, bits;
	uint8_t mask;

	len = ipr->min->length < sizeof (ipbuf) ? ipr->min->length :
		sizeof (ipbuf);
	memset(ipbuf, 0, sizeof (ipbuf));
	memcpy(ipbuf, ipr->min->data, len);
	i2v_ipaddr(ipbuf, len, abuf, sizeof (abuf), af);
	X509V3_add_value("            Range Min", abuf, &extlist);

	len = ipr->max->length < sizeof (ipbuf) ? ipr->max->length :
		sizeof (ipbuf);
	memset(ipbuf, 0xff, sizeof (ipbuf));
	memcpy(ipbuf, ipr->max->data, len);
	bits = ipr->max->flags & 0x7;
	if (bits) {
		mask = 0xff;
		mask >>= bits;
		ipbuf[len - 1] |= mask;
	}
	i2v_ipaddr(ipbuf, len, abuf, sizeof (abuf), af);
	X509V3_add_value("            Range Max", abuf, &extlist);

	return (extlist);
}

static STACK_OF(CONF_VALUE) *
i2v_IPAddressOrRange(X509V3_EXT_METHOD *method, IPAddressOrRange *aor,
    STACK_OF(CONF_VALUE) *extlist, int af)
{
	switch (aor->type) {
	case IP_AOR_PREFIX:
		i2v_prefix(aor->u.addressPrefix, extlist,
			   "            Prefix", af);
		break;
	case IP_AOR_RANGE:
		return (i2v_IPAddressRange(method, aor->u.addressRange,
					   extlist, af));
	default:
		X509V3_add_value("            Unknown IPAddressOrRange",
				 NULL, &extlist);
		break;
	}

	return (extlist);
}

static STACK_OF(CONF_VALUE) *
i2v_IPAddressChoice(X509V3_EXT_METHOD *method, IPAddressChoice *ipc,
    STACK_OF(CONF_VALUE) *extlist, int af)
{
	int i;
	IPAddressOrRange *aor;

	switch (ipc->type) {
	case IPA_CHOICE_INHERIT:
		X509V3_add_value("        Inherit", NULL, &extlist);
		break;
	case IPA_CHOICE_AOR:
		X509V3_add_value("        Prefix or Range", NULL, &extlist);
		for (i = 0; i < sk_num(ipc->u.addressesOrRanges); i++) {
			aor = (IPAddressOrRange *)
				sk_value(ipc->u.addressesOrRanges, i);
			i2v_IPAddressOrRange(method, aor, extlist, af);
		}
		break;
	}

	return (extlist);
}

static STACK_OF(CONF_VALUE) *
i2v_IPAddressFamily(X509V3_EXT_METHOD *method, IPAddressFamily *ipf,
    STACK_OF(CONF_VALUE) *extlist)
{
	uint16_t fam;
	char buf[128], *p;
	int rem, n, af = 0; /* default to unknown */

	memcpy(&fam, ipf->addressFamily->data, sizeof (fam));
	fam = ntohs(fam);

	p = buf;
	rem = sizeof (buf);
	switch (fam) {
	case IANA_AF_IPV4:
		n = snprintf(p, rem, "    IPv4");
		rem -= n; p += n;
		af = AF_INET;
		break;
	case IANA_AF_IPV6:
		n = snprintf(p, rem, "    IPv6");
		rem -= n; p += n;
		af = AF_INET6;
		break;
	default:
		n = snprintf(p, rem, "Unknown Fddress Family");
		rem -= n; p += n;
		break;
	}

	if (ipf->addressFamily->length > 2) {
		switch (ipf->addressFamily->data[2]) {
		case IANA_SAFI_UNICAST:
			snprintf(p, rem, " (Unicast)");
			break;
		case IANA_SAFI_MULTICAST:
			snprintf(p, rem, " (Multicast)");
			break;
		case IANA_SAFI_BOTH:
			snprintf(p, rem, " (Unicast and Multicast)");
			break;
		case IANA_SAFI_MPLS:
			snprintf(p, rem, " (MPLS)");
			break;
		default:
			snprintf(buf, rem, " (Unknown SAFI %d)",
				 (int)ipf->addressFamily->data[2]);
			break;
		}
	}

	X509V3_add_value(buf, NULL, &extlist);

	return (i2v_IPAddressChoice(method, ipf->ipAddressChoice, extlist, af));
}

STACK_OF(CONF_VALUE) *
i2v_IPAddrBlocks(X509V3_EXT_METHOD *method, IPAddrBlocks *ipb,
    STACK_OF(CONF_VALUE) *extlist)
{
	int i;
	IPAddressFamily *ipf;

	if (!extlist && !(extlist = sk_CONF_VALUE_new_null())) {
		return (NULL);
	}

	for (i = 0; i < sk_num(ipb); i++) {
		ipf = (IPAddressFamily *)sk_value(ipb, i);
		i2v_IPAddressFamily(method, ipf, extlist);
	}

	return (extlist);
}

#ifdef	DEBUG
#include <applog.h>

void
dump_aor(IPAddressOrRange *aor, int af, struct dlog_desc *dbg)
{
	STACK_OF(CONF_VALUE) *extlist;
	CONF_VALUE *nval;
	int i;

	if (!(extlist = sk_CONF_VALUE_new_null())) {
		return;
	}

	i2v_IPAddressOrRange(NULL, aor, extlist, af);
	for(i = 0; i < sk_CONF_VALUE_num(extlist); i++) {
		nval = sk_CONF_VALUE_value(extlist, i);
		if (!nval->name) {
			DBG(dbg, nval->value);
		} else if (!nval->value) {
			DBG(dbg, nval->name);
		} else {
			DBG(dbg, "%s: %s", nval->name, nval->value);
		}
	}

	sk_CONF_VALUE_pop_free(extlist, X509V3_conf_free);
}
#endif
