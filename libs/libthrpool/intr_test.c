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
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "config.h"
#include "thrpool.h"

static int sd;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int done;

static void
readthr(void *a)
{
	int r;
	fd_set fds[1];

	for (;;) {
		FD_ZERO(fds);
		FD_SET(sd, fds);
		r = select(sd + 1, fds, NULL, NULL, NULL);
		if (r < 0) {
			if (errno == EINTR) {
				pthread_mutex_lock(&lock);
				done = 1;
				pthread_cond_signal(&cv);
				pthread_mutex_unlock(&lock);
				return;
			} else {
				perror("recv");
				printf("*** FAILED ***\n");
				exit(1);
			}
		}
	}
}

int
main(int argc, char **argv)
{
	thrpool_id_t tid[1];
	int r;
	struct timeval now[1];
	struct timespec tv[1];

	if (thrpool_req(readthr, NULL, tid, 0) < 0) {
		printf("*** FAILED *** (thrpool_req)\n");
		exit(1);
	}

	if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		printf("*** FAILED ***\n");
		exit(1);
	}

	sleep(1);
	thr_interrupt(tid);

	pthread_mutex_lock(&lock);
	gettimeofday(now, NULL);
	tv->tv_sec = now->tv_sec + 5;
	tv->tv_nsec = 0;
	while (!done) {
		r = pthread_cond_timedwait(&cv, &lock, tv);
		if (r == ETIMEDOUT) {
			printf("*** FAILED *** (timed out)\n");
			exit(1);
		}
	}
	pthread_mutex_unlock(&lock);

	close(sd);
	printf("*** PASSED ***\n");
	return (0);
}
