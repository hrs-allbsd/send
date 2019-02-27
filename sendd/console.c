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
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "config.h"
#include <appconsole.h>
#include <applog.h>

#include "sendd_local.h"
#include "snd_proto.h"
#include "snd_config.h"

static void
exitcb(void)
{
	snd_cleanup();
	exit(0);
}

static void
do_cache(char *b)
{
	printf("============ Solicit Cache ============\n");
	dump_solicit_cache();
	printf("============ Advert Cache ============\n");
	dump_advert_cache();
	printf("============ Timestamp Cache ============\n");
	dump_timestamp_cache();
	printf("============ Prefix Cache ============\n");
	dump_pfx_cache();
}

static void
do_show(char *b)
{
	snd_print_cert();
}

static void
show_config(char *b)
{
	int i;

	for (i = 0; snd_confs[i].sym != NULL; i++) {
		printf("\t%-30s", snd_confs[i].sym);
		switch (snd_confs[i].parse) {
		case SND_CONF_P_INT:
			printf("%-20d%s\n", snd_conf_get_int(i),
			       snd_confs[i].units ? snd_confs[i].units : "");
			break;
		case SND_CONF_P_STR: {
			const char *v = snd_conf_get_str(i);
			printf("%s\n", v ? v : "<unset>");
			break;
		}
		case SND_CONF_P_BOOL:
			printf("%s\n", snd_conf_get_int(i) ? "yes" : "no");
			break;
		default:
			printf("<unknown %d>%p\n", snd_confs[i].parse,
			       snd_conf_get_str(i));
			break;
		}
	}
	printf("\tActive Interfaces:\n");
	snd_dump_ifaces();
}

static void
show_params(char *b)
{
	snd_dump_params();
}

static void
pkixip_walk(char *b)
{
	snd_pkixip_walk_store();
}

static void
show_sigmeth(char *b)
{
	snd_dump_sig_methods();
}

static void
do_troot(char *b)
{
	dump_trustanchors();
}

#ifdef	DEBUG
static void
do_debug_on(char *b)
{
	char *ctx, *lvl;

	APPCONSOLE_FIRST_ARG(b, ctx, "parse error: missing context\n");

	if (strncasecmp(ctx, "all", 3) == 0) {
		applog_addlevel(log_all_on);
		return;
	}

	APPCONSOLE_NEXT_ARG(ctx, lvl, "parse error: missing level\n");

	applog_enable_level(ctx, lvl);
}

static void
do_debug_off(char *b)
{
	char *ctx, *lvl;

	APPCONSOLE_FIRST_ARG(b, ctx, "parse error: missing context\n");

	if (strncasecmp(ctx, "all", 3) == 0) {
		applog_clearlevel(log_all_on);
		return;
	}

	APPCONSOLE_NEXT_ARG(ctx, lvl, "parse error: missing level\n");

	applog_disable_level(ctx, lvl);
}

static void
do_which_levels(char *b)
{
	applog_printlevels();
}

#endif /* DEBUG */

static cons_info_t cmds[] = {
	{ "cache", "\t\tDump caches", 3, do_cache },
	{ "show", "\t\tShow information", 2, do_show },
	{ "config", "\t\tShow config", 3, show_config },
	{ "params", "\t\tShow CGA parameters", 3, show_params },
	{ "pkixip_walk", "\tWalk the certificate store", 9, pkixip_walk },
	{ "sigmeth", "\t\tShow available signature methods", 3, show_sigmeth },
	{ "troot", "\t\tShow trusted root", 3, do_troot },
#ifdef	DEBUG
	{ "debug_on", "\tEnable / disable debug", 8, do_debug_on },
	{ "debug_off", "\tEnable / disable debug", 8, do_debug_off },
	{ "debug_levels", "\tShow possible debug levels", 8, do_which_levels },
#endif
};

int
snd_console_init(void)
{
	if (console_init(0, 1, cmds, sizeof (cmds) / sizeof (*cmds), exitcb,
			 "sendd> ") < 0) {
		return (-1);
	}

	return (0);
}

void
snd_console_exit(void)
{
	console_exit();
}
