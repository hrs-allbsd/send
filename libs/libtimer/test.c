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
#include <string.h>

#include "config.h"
#include "timer.h"
#include "list.h"
#include "applog.h"

#define THRESH_TEST 20
#define RESCHED_REPS 4

#ifndef	timercmp
# define timercmp(a, b, CMP)                                                  \
  (((a)->tv_sec == (b)->tv_sec) ?                                             \
   ((a)->tv_usec CMP (b)->tv_usec) :                                          \
   ((a)->tv_sec CMP (b)->tv_sec))
#endif

#ifndef	timeradd
# define timeradd(a, b, result)                                               \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;                          \
    if ((result)->tv_usec >= 1000000)                                         \
      {                                                                       \
        ++(result)->tv_sec;                                                   \
        (result)->tv_usec -= 1000000;                                         \
      }                                                                       \
  } while (0)
#endif

#ifndef timersub
# define timersub(a, b, result)                                               \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0 && (result)->tv_sec != 0) {                     \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)
#endif

static struct list_head timers = LIST_HEAD_INIT(timers);

struct timer_info {
	struct list_head list;
	struct timeval tv;
	timer_item_t ti;
};

static int passed;

#ifdef	NOTHREADS
static void
timercheck(maxwait)
{
	struct timeval tctv[1], *tctvp, total[1], tcnow[1], tcw[1];
	struct timeval tcstart[1], slept[1], max[1];
	fd_set fds;
	int srv;

	memset(tcstart, 0, sizeof (*tcstart));
	memset(slept, 0, sizeof (*slept));
	max->tv_sec = maxwait;
	max->tv_usec = 0;
	for (;;) {
		if ((tctvp = timer_check(tctv)) == NULL) break;
		FD_ZERO(&fds);
		gettimeofday(tcnow, NULL);
		if (!timerisset(tcstart)) {
			*tcstart = *tcnow;
			total->tv_sec = 0;
			total->tv_usec = 0;
		} else {
			timersub(tcnow, tcstart, slept);
			if (slept->tv_sec >= maxwait &&
			    slept->tv_usec > THRESH_TEST) {
				break;
			}
		}
		timersub(tctvp, tcnow, tcw);
		timeradd(tcw, slept, total);
		if (total->tv_sec >= maxwait) {
			timersub(max, slept, tcw);
		}
		if (tcw->tv_sec == 0 && tcw->tv_usec < 0) {
			continue;
		}
		printf("sleeping for %ld.%.6ld\n", tcw->tv_sec, tcw->tv_usec);
		if ((srv = select(0, &fds, NULL, NULL, tcw)) != 0) {
			if (srv < 0) {
				perror("select");
				exit(1);
			} else {
				printf("select returned > 0\n");
				exit(1);
			}
		}
	}
}
#else
#define	timercheck(maxwait) sleep(maxwait)
#endif

static void
walker(void *t, void *a)
{
	timer_item_t *ti = t;

	printf("%ld.%.6ld\n", ti->tv.tv_sec, ti->tv.tv_usec);
}

static void yar() { fprintf(stderr, "!!! yar !!!\n"); }

static void
timer(void *a)
{
	struct timer_info *ti = a;
	struct timeval now[1], diff[1];
	long udiff;

	gettimeofday(now, NULL);

	//timersub(now, &ti->tv, diff);

	diff->tv_sec = now->tv_sec - ti->tv.tv_sec;
	diff->tv_usec = now->tv_usec - ti->tv.tv_usec;
	if (diff->tv_sec < 0) {
		yar();
	}

	udiff = diff->tv_usec / 1000;
	printf("timer fire: now is \t%ld.%.6ld\n\t\ttv is \t%ld.%.6ld\n"
	       "\t\t\tdiff: %ld.%.6ld (%ld)\n",
	       now->tv_sec, now->tv_usec, ti->tv.tv_sec, ti->tv.tv_usec,
	       diff->tv_sec, diff->tv_usec, udiff);

	if (diff->tv_sec != 0 || (diff->tv_usec / 1000) > THRESH_TEST ||
	    (diff->tv_usec / 1000) < -THRESH_TEST) {
		printf("*** timer missed\n");
		passed = 0;
		yar();
	} else {
		passed = 1;
	}
	list_del(&ti->list);

	free(ti);
}

static void
resched(void *a)
{
	struct timer_info *ti = a;
	struct timeval now[1], diff[1];
	long udiff;

	gettimeofday(now, NULL);
	timersub(now, &ti->tv, diff);
	udiff = diff->tv_usec / 1000;
	printf("timer fire: now is \t%ld.%.6ld\n\t\ttv is \t%ld.%.6ld\n"
	       "\t\t\tdiff: %ld.%.6ld (%ld)\n",
	       now->tv_sec, now->tv_usec, ti->tv.tv_sec, ti->tv.tv_usec,
	       diff->tv_sec, diff->tv_usec, udiff);

	if (diff->tv_sec != 0 || (diff->tv_usec / 1000) > THRESH_TEST ||
	    (diff->tv_usec / 1000) < -THRESH_TEST) {
		printf("*** timer missed\n");
		passed = 0;
	} else {
		passed++;
		printf("\t\treps is %d\n", passed);

		if (passed == RESCHED_REPS) {
			list_del(&ti->list);
			free(ti);
			return;
		}
		diff->tv_sec = 1;
		diff->tv_usec = 0;
		if (timer_set(diff, resched, ti, &ti->ti) != 0) {
			printf("timer_set_failed\n");
			exit(1);
		}
		timeradd(now, diff, &ti->tv);
	}
}

static struct timer_info *
add_timer(struct timeval *atv, timer_func cb, struct timer_info *cti)
{
	struct timer_info *ti;
	struct timeval now[1];

	if (!cti) {
		if ((ti = malloc(sizeof (*ti))) == NULL) {
			fprintf(stderr, "no memory\n");
			exit(1);
		}
		timer_init_item(&ti->ti);
	} else {
		ti = cti;
	}

	if (timer_set(atv, cb, ti, &ti->ti) != 0) {
		printf("timer_set failed\n");
		exit(1);
	}

	if (!cti) {
		list_add(&ti->list, &timers);
	}

	gettimeofday(now, NULL);
	timeradd(now, atv, &ti->tv);

	return (ti);
}

static void
rem_timer(struct timer_info *ti)
{
	timer_clear(&ti->ti);
	list_del(&ti->list);
	free(ti);
}

static void
check_test(void)
{
	if (!passed) {
		printf("FAILED\n");
		exit(1);
	}
	passed = 0;

	if (!list_empty(&timers)) {
		printf("FAILED (list not empty)\n");
		exit(1);
	}
}

int
main(int argc, char **argv)
{
	struct timeval tv[1];
	struct timer_info *ti, *ti2;

	applog_open(L_STDERR, "timertest");
#ifdef	DEBUG
	applog_addlevel(log_all_on);
#endif
	timer_init();

	printf("\nOne timer\n");
	tv->tv_sec = 1;
	tv->tv_usec = 0;
	add_timer(tv, timer, NULL);
	timer_walk(walker, NULL);
	timercheck(2);
	check_test();

	printf("\nTwo timers, in order\n");
	add_timer(tv, timer, NULL);
	tv->tv_sec = 1;
	tv->tv_usec = 500 * 1000;
	add_timer(tv, timer, NULL);
	timer_walk(walker, NULL);
	timercheck(2);
	check_test();

	printf("\nThree timers, reverse\n");
	tv->tv_sec = 2;
	tv->tv_usec = 0;
	add_timer(tv, timer, NULL);
	tv->tv_sec = 1;
	tv->tv_usec = 750 * 1000;
	add_timer(tv, timer, NULL);
	tv->tv_sec = 1;
	tv->tv_usec = 250 * 1000;
	add_timer(tv, timer, NULL);
	timer_walk(walker, NULL);
	timercheck(3);
	check_test();

	printf("\nFive timers, out-of-order\n");
	tv->tv_sec = 1;
	tv->tv_usec = 750 * 1000;
	add_timer(tv, timer, NULL);
	tv->tv_usec = 750 * 1000;
	add_timer(tv, timer, NULL);
	tv->tv_usec = 250 * 1000;
	add_timer(tv, timer, NULL);
	tv->tv_usec = 250 * 1000;
	add_timer(tv, timer, NULL);
	tv->tv_usec = 500 * 1000;
	add_timer(tv, timer, NULL);
	timercheck(2);
	check_test();

	printf("\nTwo timers, clear last\n");
	tv->tv_sec = 1;
	tv->tv_usec = 750 * 1000;
	ti = add_timer(tv, timer, NULL);
	tv->tv_usec = 250 * 1000;
	add_timer(tv, timer, NULL);
	rem_timer(ti);
	timercheck(2);
	check_test();

	printf("\nFour timers, clear two\n");
	tv->tv_sec = 1;
	tv->tv_usec = 750 * 1000;
	ti2 = add_timer(tv, timer, NULL);
	tv->tv_usec = 750 * 1000;
	add_timer(tv, timer, NULL);
	tv->tv_usec = 250 * 1000;
	ti = add_timer(tv, timer, NULL);
	tv->tv_usec = 500 * 1000;
	add_timer(tv, timer, NULL);
	timercheck(1);
	rem_timer(ti);
	rem_timer(ti2);
	timercheck(1);
	check_test();

	printf("\nTwo timers, clear all\n");
	passed = 1;
	tv->tv_sec = 1;
	tv->tv_usec = 750 * 1000;
	ti = add_timer(tv, timer, NULL);
	tv->tv_usec = 500 * 1000;
	ti2 = add_timer(tv, timer, NULL);
	timercheck(1);
	rem_timer(ti);
	rem_timer(ti2);
	timercheck(1);
	check_test();

	printf("\nOne timer, reset\n");
	tv->tv_sec = 1;
	tv->tv_usec = 250 * 1000;
	ti = add_timer(tv, timer, NULL);
	timercheck(1);
	tv->tv_usec = 750 * 1000;
	add_timer(tv, timer, ti);
	timercheck(2);
	check_test();

	printf("\nTwo timers, move back\n");
	tv->tv_sec = 1;
	tv->tv_usec = 750 * 1000;
	ti = add_timer(tv, timer, NULL);
	tv->tv_usec = 500 * 1000;
	add_timer(tv, timer, NULL);
	timercheck(1);
	tv->tv_sec = 0;
	tv->tv_usec = 250 * 1000;
	add_timer(tv, timer, ti);
	timercheck(1);
	check_test();

	printf("\nTwo timers, move forward\n");
	tv->tv_sec = 1;
	tv->tv_usec = 250 * 1000;
	ti = add_timer(tv, timer, NULL);
	tv->tv_usec = 500 * 1000;
	add_timer(tv, timer, NULL);
	timercheck(1);
	tv->tv_sec = 0;
	tv->tv_usec = 750 * 1000;
	timercheck(1);
	check_test();

	printf("\nReschedule Self\n");
	tv->tv_sec = 1;
	tv->tv_usec = 0;
	add_timer(tv, resched, NULL);
	timercheck(RESCHED_REPS + 1);
	check_test();

	printf("*** PASSED ***\n");
	exit(0);
}
