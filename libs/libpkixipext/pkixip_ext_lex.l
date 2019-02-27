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
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "config.h"
#include <applog.h>

#include "y.tab.h"

int linecnt = 1;
extern struct dlog_desc *dbg_parse;
%}

/* flex option to keep -Wall quiet */
%option nounput

digit		[0-9]
number		({digit})+
ip4addr		{digit}{1,3}"."{digit}{1,3}"."{digit}{1,3}"."{digit}{1,3}

hexdigit	([a-f]|[A-F]|[0-9])
addr1		{hexdigit}{1,4}":"({hexdigit}{1,4}":")*(":"{hexdigit}{1,4})+
addr2		{hexdigit}{1,4}(":"{hexdigit}{1,4})*"::"
addr3		({hexdigit}{1,4}":"){7}{hexdigit}{1,4}
ip6addr		({addr1}|{addr2}|{addr3}|"::")

%s STRING

%%

<STRING>[^ \t\n;]+ {
	pkixip_lval.string = strdup(yytext);
	BEGIN 0;
	return T_STRING;
}

[Aa]ddresses		{ return T_ADDRESSES; }
[Ii][Pp][Vv]4		{ return T_IPV4; }
[Ii][Pp][Vv]6		{ return T_IPV6; }
SAFI			{ return T_SAFI; }
inherit			{ return T_INHERIT; }
prefix			{ return T_PREFIX; }
range			{ return T_RANGE; }
unicast			{ return T_UNICAST; }
multicast		{ return T_MULTICAST; }
both			{ return T_BOTH; }
mpls			{ return T_MPLS; }
files			{ return T_FILES; }
trustedcert		{ BEGIN STRING; return T_TRUSTEDCERT; }
certfile		{ BEGIN STRING; return T_CERTFILE; }
outfile			{ BEGIN STRING; return T_OUTFILE; }
cacert			{ BEGIN STRING; return T_CACERT; }
capriv			{ BEGIN STRING; return T_CAPRIV; }

[\t ]+			{ }
"{"|"}"|";"|"/"		{ return *yytext; }
#.*$			{ }
\n			{ linecnt++;}

{ip4addr} {
	struct in_addr addr;
	int i;

	i = inet_pton(AF_INET, yytext, &addr);
	if (i < 0) {
		DBG(dbg_parse, "Error parsing address %s (line %d): %s",
		    yytext, linecnt, strerror(errno));
		return T_BAD_TOKEN;
	}

	pkixip_lval.addr4 = addr;
	return T_IPV4_ADDR;
}

{ip6addr} {
	struct in6_addr addr;
	int i;

	i = inet_pton(AF_INET6, yytext, &addr);
	if (i < 0) {
		DBG(dbg_parse, "Error parsing address %s (line %d): %s",
		    yytext, linecnt, strerror(errno));
		return T_BAD_TOKEN;
	}

	pkixip_lval.addr6 = addr;
	return T_IPV6_ADDR;
}

{number} {
	pkixip_lval.num = atoi(yytext);
	return T_NUMBER;
}

%%
