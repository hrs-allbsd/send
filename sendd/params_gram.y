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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#include "config.h"
#include <applog.h>

#include "sendd_local.h"

static void explain(void);
static void yyerror(char *);

#define ABORT	do { explain(); YYABORT; } while (0)

#define	RESET_TMPS derfile = keyfile = use = NULL; sec = ifidx = -1; \
	sigm = NULL

#define	CHECK_TMP_PARAMS					\
	do {							\
	if (derfile == NULL) {					\
		applog(LOG_ERR, "missing snd_cga_params");	\
		ABORT;						\
	}							\
	if (keyfile == NULL) {					\
		applog(LOG_ERR, "missing snd_cga_priv");	\
		ABORT;						\
	}							\
	if (sec == -1) {					\
		applog(LOG_ERR, "missing snd_cga_sec");		\
		ABORT;						\
	}							\
	} while (0)

#define	CHECK_TMP_IFACE					\
	do {						\
	if (ifidx == -1) {				\
		applog(LOG_ERR, "missing interface");	\
		ABORT;					\
	}						\
	} while (0)

extern char *params_text;
extern int params_lex(void);

int params_linecnt;

static const char *derfile;
static const char *keyfile;
static const char *use;
static int sec = -1;
static int ifidx = -1;
static struct snd_sig_method *sigm;

%}

%token T_STRING T_IPV6_ADDR T_NAMED T_ADDR T_USE T_SIGMETH
%token T_DERFILE T_KEYFILE T_SEC T_INTERFACE T_BAD_TOKEN T_NUMBER

%union {
	char		*string;
	int		num;
	struct in6_addr addr6;
}

%token <string> T_STRING
%token <addr6> T_IPV6_ADDR
%token <num> T_NUMBER

%%

grammar			: named_defs addr_defs | named_defs | addr_defs | ;

named_defs		: named_defs named_def | named_def;

addr_defs		: addr_defs addr_def | addr_def;

named_def		: T_NAMED T_STRING '{' named_params_def '}'
			{
				/* make named param */
				if (use != NULL) {
					if (snd_add_named_params_use($2, use)
					    != 0) {
						ABORT;
					}
				} else {
					CHECK_TMP_PARAMS;
					if (snd_add_named_params($2,
								 derfile,
								 keyfile,
								 sec,
								 sigm) != 0) {
						ABORT;
					}
				}
				RESET_TMPS;
			}
			;

addr_def		: T_ADDR T_IPV6_ADDR '{' addr_params_def '}'
			{
				/* make named param */
				if (use != NULL) {
					CHECK_TMP_IFACE;
					if (snd_add_addr_params_use(&$2,
								    ifidx,
								    use)
					    != 0) {
						ABORT;
					}
				} else {
					CHECK_TMP_IFACE;
					CHECK_TMP_PARAMS;
					if (snd_add_addr_params(&$2,
								ifidx,
								derfile,
								keyfile,
								sec,
								sigm) != 0) {
						ABORT;
					}
				}
				RESET_TMPS;
			}
			;

named_params_def	: params_files | use;

addr_params_def		: addr_params
			| use interface | interface use
			;

params_files		: params_files params_file | params_file;

params_file		: derfile | keyfile | sec | sigmeth;

addr_params		: addr_params addr_param | addr_param;

addr_param		: derfile | keyfile | sec | sigmeth | interface;

derfile			: T_DERFILE T_STRING ';' { derfile = $2; };

keyfile			: T_KEYFILE T_STRING ';' { keyfile = $2; };

use			: T_USE T_STRING ';' { use = $2; };

sec			: T_SEC T_NUMBER ';' { sec = $2; };

interface		: T_INTERFACE T_STRING ';'
			{
				// XXX would be nice to handle dynamic ifaces
				ifidx = if_nametoindex($2);
				if (ifidx == 0) {
					applog(LOG_ERR, "Invalid interface %s",
					       $2);
					ABORT;
				}
			}
			;

sigmeth			: T_SIGMETH T_STRING ';'
			{
				sigm = snd_find_sig_method_byname($2);
				if (sigm == NULL) {
					applog(LOG_ERR, "Invalid signature "
					       "method %s", $2);
					ABORT;
				}
			}
			;

%%

int
params_wrap(void)
{
	return (1);
}

static void
yyerror(char *msg)
{
	fprintf(stderr, "error: %s, line %d: %s\n", msg, params_linecnt,
		params_text);
}

static void
explain(void)
{
	fprintf(stderr, "aborting at line %d: %s\n", params_linecnt,
		params_text);
}
