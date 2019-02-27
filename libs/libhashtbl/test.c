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
#include <string.h>

#include "config.h"
#include "hashtbl.h"

#define	REPS	1000

struct intitem {
	int i;
	htbl_item_t hitm;
};

static uint32_t
hashint(void *a, int s)
{
	struct intitem *p = a;

	return (p->i % s);
}

static int
matchint(void *a, void *b)
{
	struct intitem *x = a;
	struct intitem *y = b;

	return (x->i - y->i);
}

static void
walker(void *v, void *c)
{
	struct intitem *p = v;

	printf("%d ", p->i);
}

int
main(int argc, char **argv)
{
	int i;
	struct intitem *p, pk[1];
	htbl_t *tbl;

	if ((tbl = htbl_create(7, hashint, matchint)) == NULL) {
		fprintf(stderr, "no memory\n");
		exit(1);
	}

	for (i = 0; i < REPS; i++) {
		if ((p = malloc(sizeof (*p))) == NULL) {
			fprintf(stderr, "no memory\n");
			exit(1);
		}
		memset(p, 0, sizeof (*p));
		p->i = i;
		htbl_add(tbl, p, &p->hitm);
	}

	for (i = 0; i < REPS; i++) {
		memset(pk, 0, sizeof (*pk));
		pk->i = i;
		if ((p = htbl_find(tbl, pk)) == NULL) {
			printf("Could not find %d\n", i);
			exit(1);
		}
	}

	for (i = 0; i < REPS; i++) {
		memset(pk, 0, sizeof (*pk));
		pk->i = i;
		if ((p = htbl_rem(tbl, pk)) == NULL) {
			printf("Could not del %d\n", i);
			exit(1);
		}
		/* now put it back... */
		htbl_add(tbl, p, &p->hitm);
	}

	htbl_walk(tbl, walker, NULL);
	printf("\n");
	htbl_destroy(tbl, free);

	printf("*** PASSED ***\n");
	exit(0);
}
