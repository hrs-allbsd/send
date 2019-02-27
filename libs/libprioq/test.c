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

#include "config.h"
#include "prioq.h"

#define ASIZE 40

struct intitem {
	int i;
	pq_item_t pqi;
};

static int
matchint(void *a, void *b) {
	struct intitem *i1 = a;
	struct intitem *i2 = b;

	return (i1->i - i2->i);
}

static void
walker(void *v, void *a)
{
	struct intitem *i = v;

	printf("%d ", i->i);
}

static void
dotest(pq_t *pq, struct intitem *a)
{
	int i;
	struct intitem *x;

	for (i = ASIZE - 1; i >= 0; i--) {
		if (a[i].i == -1) {
			continue;
		}
		x = pq_getmax(pq);
		if (x->i != i) {
			printf("\ngetmax should be %d, not %d\n", i,
			       x->i);
			exit(1);
		}
		x = pq_delmax(pq);
		printf("%d ", x->i);
		if (x->i != i) {
			printf("\ndelmax should be %d, not %d\n", i,
			       x->i);
			exit(1);
		}
	}
	if (pq_size(pq) != 0) {
		printf("\nnot empty!\n");
		exit(1);
	}
}

int
main(int argc, char **argv) {
	pq_t *pq;
	struct intitem a[ASIZE];
	int i, j;

	if ((pq = pq_create(matchint)) == NULL) {
		exit(1);
	}

	printf("in order\n");
	for (i = 0; i < ASIZE; i++) {
		a[i].i = i;
		pq_insert(pq, a + i, &a[i].pqi);
	}

	pq_walk(pq, walker, NULL);
	printf("\n");

	dotest(pq, a);

	printf("\nreverse order\n");
	for (i = ASIZE - 1; i >= 0; i--) {
		pq_insert(pq, a + i, &a[i].pqi);
	}

	pq_walk(pq, walker, NULL);
	printf("\n");

	dotest(pq, a);

	printf("\n");

	printf("staggered order\n");
	for (i = 0; i < (ASIZE / 2); i++) {
		struct intitem *ti;

		pq_insert(pq, a + i, &a[i].pqi);
		ti = a + ((ASIZE - 1) - i);
		pq_insert(pq, ti, &ti->pqi);
	}
	pq_walk(pq, walker, NULL);
	printf("\n");

	dotest(pq, a);

	printf("\n");

	printf("reprio\n");
	for (i = ASIZE - 1; i >= 0; i--) {
		pq_insert(pq, a + i, &a[i].pqi);
	}

	pq_walk(pq, walker, NULL);
	printf("\n");

	j = a[0].i;
	a[0].i = a[ASIZE - 1].i;
	pq_reprio(pq, &a[0].pqi);

	a[ASIZE - 1].i = j;
	pq_reprio(pq, &a[ASIZE - 1].pqi);

	i = ASIZE / 4;
	j = a[i].i;
	a[i].i = a[i * 3].i;
	pq_reprio(pq, &a[i].pqi);

	a[i * 3].i = j;
	pq_reprio(pq, &a[i * 3].pqi);

	dotest(pq, a);

	printf("\n");

	printf("delete\n");

	/* reset array */
	for (i = 0; i < ASIZE; i++) {
		a[i].i = i;
	}

	for (i = ASIZE - 1; i >= 0; i--) {
		pq_insert(pq, a + i, &a[i].pqi);
	}

	pq_walk(pq, walker, NULL);
	printf("\n");

	i = ASIZE / 4;
	pq_del(pq, &a[i].pqi);
	pq_del(pq, &a[i * 2].pqi);
	pq_del(pq, &a[i * 3].pqi);
	pq_del(pq, &a[ASIZE - 1].pqi);

	a[i].i = a[i * 2].i = a[i * 3].i = a[ASIZE - 1].i = -1;

	dotest(pq, a);

	printf("\n");

	printf("delete all\n");
	/* reset array */
	for (i = 0; i < ASIZE; i++) {
		a[i].i = i;
	}

	for (i = ASIZE - 1; i >= 0; i--) {
		pq_insert(pq, a + i, &a[i].pqi);
	}

	for (i = ASIZE - 1; i >= 0; i--) {
		if (pq_size(pq) != i + 1) {
			printf("\nwrong size; is %d should be %d\n",
			       pq_size(pq), i);
			exit(1);
		}
		pq_del(pq, &a[i].pqi);
		printf("%d: ", i);
		pq_walk(pq, walker, NULL);
		printf("\n");
		fflush(stdout);
	}

	pq_destroy(pq, NULL);

	printf("*** PASSED ***\n");

	exit(0);
}
