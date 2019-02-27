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
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "appconsole.h"

static void cntcb(char *);

static void
showcb(char *buf)
{
	printf("%s", buf);
	printf("\n");
}

static void
exitcb(void)
{
	exit(0);
}

static cons_info_t cmds[] = {
	{ "show", "Shows test info", 3, showcb },
	{ "count", "Shows command count", 2, cntcb },
	{ "shell", "Same as show", 3, showcb }
};

static void
cntcb(char *buf)
{
	printf("%d\n", sizeof (cmds) / sizeof (*cmds));
}

int
main(int argc, char **argv)
{
#ifdef	NOTHREADS
	fd_set fds;
	int rv;
#endif

	if (console_init(0, 1, cmds, sizeof (cmds) / sizeof (*cmds), exitcb,
	    "test> ") < 0) {
		fprintf(stderr, "console_init failed\n");
		exit(1);
	}

#ifdef	NOTHREADS
	FD_ZERO(&fds);
	FD_SET(0, &fds);
	while ((rv = select(1, &fds, NULL, NULL, NULL)) >= 0) {
		if (FD_ISSET(0, &fds)) {
#ifdef	USE_READLINE
			console_read_char();
#else
			console_read();
#endif	/* USE_READLINE */
		}
		else {
			printf("fd other than stdin ready\n");
		}
	}
#else
	for (;;) {
		sleep(20);
	}
#endif

	exit(0);
}
