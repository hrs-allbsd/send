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
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#include "config.h"
#include "thrpool.h"
#include "list.h"

static DEFINE_LIST_HEAD(list);
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

struct ptest {
	struct list_head list;
	thrpool_id_t id;
	int n;
};

static void
task(void *a)
{
	struct ptest *p = a;

	pthread_mutex_lock(&lock);
	fprintf(stderr, "task: %d: %lu, %p\n", p->n, p->id.pthread_id,
		p->id.pqi);
	list_add_tail(&p->list, &list);
	pthread_mutex_unlock(&lock);
}

static void
sleep_task(void *a)
{
	fprintf(stderr, "sleeping...");
	sleep(1);
	fprintf(stderr, "done\n");
}

int
main(int argc, char **argv)
{
	struct list_head *pos;
	struct ptest *p, ps[4], doomed[1];
	int i, j, r = 0;

	for (i = 0; i < 4; i++) {
		ps[i].n = i;
		memset(&ps[i].id, 0, sizeof (ps[i].id));
	}
	memset(doomed, 0, sizeof (*doomed));
	doomed->n = 100;

	thrpool_set_max(1);
	thrpool_set_q_size(4);

	thrpool_req(sleep_task, NULL, NULL, 0);

	/* insert them in reserve order, using priorities to order them */
	for (i = 3, j = 1; i >= 0; i--, j++) {
		thrpool_req(task, ps + i, &ps[i].id, j);
	}

	/* insert one in the middle, then remove it */
	thrpool_req(task, doomed, &doomed->id, 2);

	thr_interrupt(&doomed->id);

	/* all items should be q'd now */
	for (i = 0; i < 4; i++) {
		fprintf(stderr, "%d: %lu, %p\n", i,
			ps[i].id.pthread_id, ps[i].id.pqi);
	}

	sleep(2);

	i = 0;
	list_for_each(pos, &list) {
		p = list_entry(pos, struct ptest, list);
		printf("%d\n", p->n);
		if (i++ != p->n) {
			r = 1;
		}
	}
	if (i == 0) {
		fprintf(stderr, "list empty\n");
		r = 1;
	}

	if (r != 0) {
		fprintf(stderr, "*** FAIL ***\n");
	} else {
		fprintf(stderr, "*** PASSED ***\n");
	}
	return (r);
}
