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

#ifndef	_PKIXIP_EXT_ASN_H
#define	_PKIXIP_EXT_ASN_H

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#define	IANA_AF_IPV4		1
#define	IANA_AF_IPV6		2

#define	IANA_SAFI_UNICAST	1
#define	IANA_SAFI_MULTICAST	2
#define	IANA_SAFI_BOTH		3
#define	IANA_SAFI_MPLS		4

/*
typedef struct IPAddressRange_st {
	ASN1_BIT_STRING		*min;
	ASN1_BIT_STRING		*max;
} IPAddressRange;

typedef struct IPAddressOrRange_st {

#define	IP_AOR_PREFIX		0
#define	IP_AOR_RANGE		1

	int 			type;
	union {
		ASN1_BIT_STRING	*addressPrefix;
		IPAddressRange	*addressRange;
	} u;
} IPAddressOrRange;

typedef struct IPAddressChoice_st {

#define	IPA_CHOICE_INHERIT	0
#define	IPA_CHOICE_AOR		1

	int 			type;
	union {
		ASN1_NULL	*inherit;
		STACK_OF(IPAddressOrRange) *addressesOrRanges;
	} u;
} IPAddressChoice;

typedef struct IPAddressFamily_st {
	ASN1_OCTET_STRING	*addressFamily;
	IPAddressChoice		*ipAddressChoice;
} IPAddressFamily;
*/

#define IP_AOR_PREFIX		0
#define IP_AOR_RANGE		1
#define IPA_CHOICE_INHERIT	0
#define IPA_CHOICE_AOR		1

typedef STACK_OF(IPAddressFamily) IPAddrBlocks;

DECLARE_ASN1_FUNCTIONS(IPAddressRange)
DECLARE_ASN1_FUNCTIONS(IPAddressOrRange)
DECLARE_ASN1_FUNCTIONS(IPAddressChoice)
DECLARE_ASN1_FUNCTIONS(IPAddressFamily)
DECLARE_ASN1_FUNCTIONS(IPAddrBlocks)

extern STACK_OF(CONF_VALUE) *i2v_IPAddrBlocks(X509V3_EXT_METHOD *,
    IPAddrBlocks *, STACK_OF(CONF_VALUE) *);

#endif	/* _PKIXIP_EXT_ASN_H */
