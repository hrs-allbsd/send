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

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>

#include "config.h"
#include <applog.h>
#include "pkixip_ext.h"
#include "pkixip_local.h"

int linecnt;

extern char *pkixip_text;
extern int pkixip_lex(void);

extern IPAddrBlocks *parse_ipb;
static IPAddressFamily *ipf;
static IPAddressOrRange *aor;
static uint8_t afbuf[3];
static int af;

extern struct pkixip_config *configs;

extern struct dlog_desc dbg_parse;

static void explain(void);
static void cleanup(void);
static int af_already_exists(void);
static int add_inherit(void);
static int add_pfx(void *, int);
static int add_range(void *, void *, int, int, int);
static void yyerror(char *);

#define ABORT	do { explain(); cleanup(); YYABORT; } while (0)

%}

%token T_ADDRESSES T_IPV4 T_IPV6 T_SAFI T_INHERIT T_PREFIX T_RANGE
%token T_IPV4_ADDR T_IPV6_ADDR T_UNICAST T_MULTICAST T_BOTH T_MPLS
%token T_FILES T_TRUSTEDCERT T_CERTFILE T_OUTFILE T_CACERT T_CAPRIV T_STRING
%token T_NUMBER T_BAD_TOKEN

%union {
	char		*string;
	int		num;
	struct in_addr	addr4;
	struct in6_addr addr6;
}

%token <string> T_STRING
%token <addr4> T_IPV4_ADDR
%token <addr6> T_IPV6_ADDR
%token <num> T_NUMBER
%type <num> safi_value

%%

grammar			: grammar sections
			| sections
			;

sections		: files_head
			| addrs_head
			;

files_head		: T_FILES '{' files_section '}'
			;

files_section		: files_section conf_files
			| conf_files
			;

conf_files		: T_OUTFILE T_STRING ';'
			{
				if (configs->outfile) {
					fprintf(stderr, "outfile already "
						"set\n");
					ABORT;
				}
				configs->outfile = $2;
			}
			|
			T_CACERT T_STRING ';'
			{
				if (configs->cacert) {
					fprintf(stderr, "cacert already "
						"set\n");
					ABORT;
				}
				configs->cacert = $2;
			}
			|
			T_CAPRIV T_STRING ';'
			{
				if (configs->capriv) {
					fprintf(stderr, "capriv already "
						"set\n");
					ABORT;
				}
				configs->capriv = $2;
			}
			|
			T_CERTFILE T_STRING ';'
			{
				if (configs->certfile) {
					fprintf(stderr, "certfile already "
						"set\n");
					ABORT;
				}
				configs->certfile = $2;
			}
			| T_TRUSTEDCERT T_STRING ';'
			{
				if (pkixip_add2stores_file($2) < 0) ABORT;
			}
			;

addrs_head		: T_ADDRESSES '{' addrs_sections '}'
			{
				/* Sort by AFs */
				sk_set_cmp_func(parse_ipb, pkixip_ipf_cmp);
				sk_find(parse_ipb, NULL);
			}
			;

addrs_sections		: addrs_sections addrs_section
			| addrs_section
			;

addrs_section	 	: ipv4_section
			| ipv6_section
			;

ipv4_section		: ipv4_head '{' address_section '}'
			;

ipv6_section		: ipv6_head '{' address_section '}'
			;

ipv4_head		: T_IPV4
			{
				af = IANA_AF_IPV4;
			}
			;

ipv6_head		: T_IPV6
			{
				af = IANA_AF_IPV6;
			}
			;

address_section		: safi address_spec
			;

safi			: T_SAFI safi_value ';'
			{
				int naf = htons(af);

				if (!(ipf = IPAddressFamily_new())) {
					applog(LOG_CRIT, "no memory");
					ABORT;
				}
				memcpy(afbuf, &naf, sizeof (naf));
				afbuf[2] = (uint8_t)$2;

				ASN1_OCTET_STRING_set(ipf->addressFamily,
				    afbuf, sizeof (afbuf));

				if(af_already_exists()) {
					fprintf(stderr, "already have a AF /"
						" SAFI of this type\n");
					IPAddressFamily_free(ipf);
					ABORT;
				}

				if (sk_push(parse_ipb, (char *)ipf) == 0) {
					applog(LOG_CRIT, "sk_push() failed");
					ABORT;
				}
			}
			;

safi_value		: T_UNICAST
			{
				$$ = IANA_SAFI_UNICAST;
			}
			| T_MULTICAST
			{
				$$ = IANA_SAFI_MULTICAST;
			}
			| T_BOTH
			{
				$$ = IANA_SAFI_BOTH;
			}
			| T_MPLS
			{
				$$ = IANA_SAFI_MPLS;
			}
			;

address_spec		: T_INHERIT ';'
			{
				add_inherit();
			}
			| prefix_or_ranges
			{
				/* Force a sort of IPAddressOrRanges stack */
				IPAddressChoice *ipc = ipf->ipAddressChoice;
				sk_find(ipc->u.addressesOrRanges, NULL);
			}
			;

prefix_or_ranges	: prefix_or_ranges prefix_or_range
			| prefix_or_range
			;

prefix_or_range		: prefix
			| range
			;

prefix			: prefix4
			| prefix6
			;

range			: range4
			| range6
			;

prefix4			: T_PREFIX T_IPV4_ADDR '/' T_NUMBER ';'
			{
				if (af != IANA_AF_IPV4) {
					fprintf(stderr, "No IPv4 addresses "
						"allowed in this section\n");
					ABORT;
				}
				if (add_pfx(&$2, $4) < 0) ABORT;
			}
			;

prefix6			: T_PREFIX T_IPV6_ADDR '/' T_NUMBER ';'
			{
				if (af != IANA_AF_IPV6) {
					fprintf(stderr, "No IPv6 addresses "
						"allowed in this section\n");
					ABORT;
				}
				if (add_pfx(&$2, $4) < 0) ABORT;
			}
			;

range4			: T_RANGE T_IPV4_ADDR '/' T_NUMBER T_IPV4_ADDR '/' T_NUMBER ';'
			{
				if (af != IANA_AF_IPV4) {
					fprintf(stderr, "No IPv4 addresses "
						"allowed in this section\n");
					ABORT;
				}
				if (add_range(&$2, &$5, $4, $7, IANA_AF_IPV4)
				    < 0) ABORT;
			}
			;

range6			: T_RANGE T_IPV6_ADDR '/' T_NUMBER T_IPV6_ADDR '/' T_NUMBER ';'
			{
				if (af != IANA_AF_IPV6) {
					fprintf(stderr, "No IPv6 addresses "
						"allowed in this section\n");
					ABORT;
				}
				if (add_range(&$2, &$5, $4, $7, IANA_AF_IPV6)
				    < 0) ABORT;
			}
			;

%%

int
pkixip_wrap(void)
{
	return (1);
}

static void
yyerror(char *msg)
{
	fprintf(stderr, "error: %s, line %d: %s\n", msg, linecnt, pkixip_text);
	IPAddrBlocks_free(parse_ipb);
	parse_ipb = NULL;
}

static void
cleanup(void)
{
	IPAddrBlocks_free(parse_ipb);
	parse_ipb = NULL;
}

static void
explain(void)
{
	fprintf(stderr, "aborting at line %d: %s\n", linecnt, pkixip_text);
}

static void
set_bits(ASN1_BIT_STRING *abs, uint8_t *data, int bytes, int bits)
{
	ASN1_BIT_STRING_set(abs, data, bytes);
	abs->flags |= ASN1_STRING_FLAG_BITS_LEFT;
	abs->flags |= bits;
}

static int
new_aor(void)
{
	IPAddressChoice *ipc = ipf->ipAddressChoice;

	if (!ipc->u.addressesOrRanges &&
	    !(ipc->u.addressesOrRanges =
	      sk_new(pkixip_aor_cmp))) {
		applog(LOG_CRIT, "no memory");
		return (-1);
	}

	ipc->type = IPA_CHOICE_AOR;

	if (!(aor = IPAddressOrRange_new())) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (-1);
	}
	if (!sk_push(ipc->u.addressesOrRanges, (char *)aor)) {
		applog(LOG_CRIT, "sk_push() failed");
		return (-1);
	}

	return (0);
}

static int
add_pfx(void *a, int plen)
{
	int bytes, bits;
	uint8_t *data = a;

	if (new_aor() < 0) {
		return (-1);
	}

	if ((aor->u.addressPrefix = ASN1_BIT_STRING_new()) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (-1);
	}

	bytes = plen / 8;
	bits = plen % 8;
	if (bits) {
		bits = 8 - bits;
		bytes++;
	}

	aor->type = IP_AOR_PREFIX;
	set_bits(aor->u.addressPrefix, data, bytes, bits);

	return (0);
}

static int
add_range(void *a1, void *a2, int min_bits, int max_bits, int paf)
{
	IPAddressRange *iar;
	int minbytes, minbits, maxbytes, maxbits;

	if (new_aor() < 0) {
		return (-1);
	}

	if ((aor->u.addressRange = IPAddressRange_new()) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (-1);
	}
	iar = aor->u.addressRange;

	minbytes = min_bits / 8;
	minbits = min_bits % 8;
	if (minbits) minbytes++;

	maxbytes = max_bits / 8;
	maxbits = max_bits % 8;
	if (maxbits) maxbytes++;

	aor->type = IP_AOR_RANGE;
	switch (paf) {
	case IANA_AF_IPV4:
		set_bits(iar->min, a1, minbytes, minbits);
		set_bits(iar->max, a2, maxbytes, maxbits);
		break;
	case IANA_AF_IPV6:
		set_bits(iar->min, a1, minbytes, minbits);
		set_bits(iar->max, a2, maxbytes, maxbits);
		break;
	default:
		DBG(&dbg_parse, "Invalid AF (%d)", af); // XXX
		return (-1);
	}

	return (0);
}

static int
add_inherit(void)
{
	IPAddressChoice *ipc = ipf->ipAddressChoice;

	if (!(ipc->u.inherit = ASN1_NULL_new())) {
		applog(LOG_CRIT, "no memory");
		return (-1);
	}
	ipc->type = IPA_CHOICE_INHERIT;

	return (0);
}

static int
af_already_exists(void)
{
	int i;
	IPAddressFamily *e_ipf;

	for (i = 0; i < sk_num(parse_ipb); i++) {
		e_ipf = (IPAddressFamily *)sk_value(parse_ipb, i);
		if (af_match(ipf, e_ipf)) {
			return (1);
		}
	}

	return (0);
}
