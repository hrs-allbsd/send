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

#include "config.h"
#include "pkixip_ext_asn.h"

int
pkixip_aor_cmp(const char * const *a1, const char * const *a2)
{
	int by1, by2, bi1, bi2, bytes, bits;
	uint8_t *d1, *d2, x1, x2, mask;
	int r;
	IPAddressOrRange *aor1, *aor2;

	aor1 = (IPAddressOrRange *)*a1;
	aor2 = (IPAddressOrRange *)*a2;

	if (aor1 == NULL) {
		if (aor2 == NULL) {
			return (0);
		}
		return (-1);
	} else if (aor2 == NULL) {
		return (1);
	}

	if (aor1->type == IP_AOR_PREFIX) {
		d1 = aor1->u.addressPrefix->data;
		by1 = aor1->u.addressPrefix->length;
		bi1 = aor1->u.addressPrefix->flags & 0x7;
	} else if (aor1->type == IP_AOR_RANGE) {
		d1 = aor1->u.addressRange->min->data;
		by1 = aor1->u.addressRange->min->length;
		bi1 = aor1->u.addressRange->min->flags & 0x7;
	} else {
		return (-1);
	}

	if (aor2->type == IP_AOR_PREFIX) {
		d2 = aor2->u.addressPrefix->data;
		by2 = aor2->u.addressPrefix->length;
		bi2 = aor2->u.addressPrefix->flags & 0x7;
	} else if (aor2->type == IP_AOR_RANGE) {
		d2 = aor2->u.addressRange->min->data;
		by2 = aor2->u.addressRange->min->length;
		bi2 = aor2->u.addressRange->min->flags & 0x7;
	} else {
		return (-1);
	}

	bytes = by1;
	if (by1 > by2) {
		bytes = by2;
		bits = bi2;
	} else if (by1 < by2) {
		bytes = by1;
		bits = bi1;
	} else {
		bits = bi1 > bi2 ? bi2 : bi1;
	}
	if (bits) {
		bytes--;
	}

	r = memcmp(d1, d2, bytes);
	if (r < 0) {
		return (-1);
	} else if (r > 0) {
		return (1);
	}
	if (!bits) {
		return (0);
	}

	mask = 0xff;
	mask <<= (8 - bits);
	x1 = d1[bytes];
	x2 = d2[bytes];

	if ((x1 & mask) > (x2 & mask)) {
		return (1);
	} else if ((x1 & mask) < (x2 & mask)) {
		return (-1);
	}

	return (0);
}

int
pkixip_ipf_cmp(const char * const *a1, const char * const *a2)
{
	IPAddressFamily *ipf1 = (IPAddressFamily *)*a1;
	IPAddressFamily *ipf2 = (IPAddressFamily *)*a2;
	int cnt, r;

	if (ipf1 == NULL) {
		if (ipf2 == NULL) {
			return (0);
		}
		return (-1);
	} else if (ipf2 == NULL) {
		return (1);
	}

	if (ipf1->addressFamily->length > ipf2->addressFamily->length) {
		cnt = ipf2->addressFamily->length;
	} else {
		cnt = ipf1->addressFamily->length;
	}

	r = memcmp(ipf1->addressFamily->data, ipf2->addressFamily->data, cnt);
	if (r < 0) {
		return (-1);
	} else if (r > 0) {
		return (1);
	}

	return (0);
}
