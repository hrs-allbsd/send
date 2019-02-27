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

#include "config.h"
#include "libconfig.h"

static struct {
	const char *k, *v;
} tests[] = {
	{ "one", "two" },
	{ "three", "four" },
	{ "five", "six" },
	{ "seven", "eight" },
	{ "nine", "ten" },
	{ "eleven", "twelve" },
	{ "multiple", "equals = another" },
	{ "novalue", "" },
	{ "novalue_space", "" },
	{ "no", "return" }
};

int
main(int argc, char **argv)
{
	const char *v;
	int rv;
	int i;

	if ((rv = config_init("test.conf")) < 0) {
		fprintf(stderr, "config_init failed: %s\n", strerror(-rv));
		return (rv);
	}

	if (argc >= 2) {
		v = config_get(argv[1], "<null>");
		printf("%s\n", v);

		return (0);
	}

	/* if no args, run automated test */
#define	FAIL(ti, val) printf("FAILED for key %s: got %s, should be %s\n", \
		(ti).k, (val), (ti).v); rv = -1

	rv = 0;
	for (i = 0; i < (sizeof (tests) / sizeof (*tests)); i++) {
		if ((v = config_get(tests[i].k, NULL)) == NULL) {
			FAIL(tests[i], "<not found>");
		}
		if (strcmp(v, tests[i].v) != 0) {
			FAIL(tests[i], v);
		}
	}

	if (rv == 0) {
		printf("PASSED\n");
	}
	return (rv);
}

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
