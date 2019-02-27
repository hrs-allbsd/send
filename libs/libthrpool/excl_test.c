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
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>

#include "config.h"
#include <applog.h>
#include "thrpool.h"

static int cb_cnt, finished, target;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

static void
signal_finished(void)
{
	pthread_mutex_lock(&lock);
	finished = 1;
	pthread_cond_signal(&cv);
	pthread_mutex_unlock(&lock);
}

static int
wait_for_finish(int wait)
{
	struct timespec ts[1];
	struct timeval tv[1];
	int r = -1;

	gettimeofday(tv, NULL);
	ts->tv_sec = tv->tv_sec + wait;
	ts->tv_nsec = tv->tv_usec * 1000;

	pthread_mutex_lock(&lock);
	while (!finished) {
		if (pthread_cond_timedwait(&cv, &lock, ts) == ETIMEDOUT) {
			printf("timed out\n");
			goto done;
		}
	}
	r = 0;

done:
	finished = 0;
	pthread_mutex_unlock(&lock);

	return (r);
}

static void
cnt_cb(void *a)
{
	int *c = a;

	(*c)++;
	if (*c == target) {
		signal_finished();
	}
}

static void
excl_cb(void *a)
{
	int c = cb_cnt;
	fprintf(stderr, "before sleeping: %d\n", cb_cnt);
	sleep(1);
	fprintf(stderr, "after sleeping: %d\n", cb_cnt);
	if (cb_cnt != c) {
		fprintf(stderr, "!=\n");
		exit(1);
	}
}

static void
excl(int cnt, int tgt, int wait)
{
	int i;

	fprintf(stderr, "%d excl\n", cnt);
	target = tgt;
	for (i = 0; i < cnt; i++) {
		thrpool_req_excl(cnt_cb, &cb_cnt, NULL);
	}

	if (!wait) {
		return;
	}
	if (wait_for_finish(wait) < 0) {
		exit(1);
	}
	if (cb_cnt != target) {
		printf("cnt is %d, should be %d\n", cb_cnt, target);
		exit(1);
	}
}

static void
norm(int cnt, int tgt, int wait)
{
	int i;

	fprintf(stderr, "%d norm\n", cnt);
	target = tgt;
	for (i = 0; i < cnt; i++) {
		thrpool_req(cnt_cb, &cb_cnt, NULL, 0);
	}

	if (!wait) {
		return;
	}
	if (wait_for_finish(wait) < 0) {
		exit(1);
	}
	if (cb_cnt != target) {
		printf("cnt is %d, should be %d\n", cb_cnt, target);
		exit(1);
	}
}

int
main()
{
	if (applog_open(L_STDERR, "test") < 0) {
		exit(1);
	}
	applog_addlevel(log_all_on);

	excl(1, 1, 1);
	cb_cnt = 0;
	excl(5, 5, 1);
	cb_cnt = 0;

	excl(1, 1, 1);
	cb_cnt = 0;
	sleep(1);
	excl(5, 5, 1);
	cb_cnt = 0;
	sleep(1);

	/* add a bunch of other threads and try again */
	excl(1, 1, 1);
	norm(10, 10, 1);
	cb_cnt = 0;
	excl(1, 1, 1);
	cb_cnt = 0;
	norm(10, 10, 1);
	cb_cnt = 0;

	/* have normal thrs executing while making a excl req */
	norm(5, 5, 0);
	excl(1, 6, 0);
	norm(5, 11, 1);
	sleep(1);
	cb_cnt = 0;

	/* ensure excl is indeed exclusive */
	fprintf(stderr, "excl is excl test\n");
	norm(3, 3, 0);
	fprintf(stderr, "adding excl task 1\n");
	thrpool_req_excl(excl_cb, NULL, NULL);
	norm(3, 6, 2);
	sleep(1);
	fprintf(stderr, "adding excl task 2\n");
	thrpool_req_excl(excl_cb, NULL, NULL);
	norm(3, 9, 2);

	printf("*** PASSED ***\n");
	exit(0);
}
