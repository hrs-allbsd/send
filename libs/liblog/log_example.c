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
#include <unistd.h>
#include <stdlib.h>

#include <applog.h>

#define	EX_CTX	"example"

#ifdef	DEBUG
static struct dlog_desc dbg_foo = {
	.desc = "foo",
	.ctx = EX_CTX
};
static struct dlog_desc dbg_bar = {
	.desc = "bar",
	.ctx = EX_CTX
};
#endif

static void
foo(void)
{
	DBG(&dbg_foo, "foo is at %p", foo);
	DBG_HEXDUMP(&dbg_foo, "first 40 bytes of foo", (uint8_t *)foo, 40);
}

static void
bar(void)
{
	DEFINE_TIMESTAMP_VARS();

	DBG(&dbg_bar, "about to take a nap");
	TIMESTAMP_START();
	sleep(2);
	TIMESTAMP_END("sleep 2");
}

static void
usage(const char *this)
{
	const char **methods;

	fprintf(stderr, "usage: %s [-q] -l <log method>\n", this);
	fprintf(stderr, "\t-q\tquiet\n");
	fprintf(stderr, "\t-l\tlog method, one of\n");

	methods = applog_get_methods();
	do {
		fprintf(stderr, "\t\t\t%s\n", *methods++);
	} while (*methods);
}

int
main(int argc, char **argv)
{
	int c;
	int quiet = 0;
	char *log_method = NULL;
#ifdef	DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg_foo,
		&dbg_bar,
		NULL
	};
#endif

	while ((c = getopt(argc, argv, "l:q")) != -1) {
		switch (c) {
		case 'l':
			log_method = optarg;
			break;
		case 'q':
			quiet = 1;
			break;
		default:
			usage(*argv);
			exit(1);
		}
	}

	if (applog_open(applog_str2method(log_method), EX_CTX) < 0) {
		exit(1);
	}

#ifdef	DEBUG
	applog_register(dbgs);
	if (!quiet) {
		applog_addlevel(log_all_on);
	}
#endif

	foo();
	bar();

	exit(0);
}
