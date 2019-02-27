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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "config.h"
#include "thrpool.h"

#define	THRPOOL

struct pkt {
	int sd;
	char pkt[128];
	int len;
	struct sockaddr_in from;
};

static void
process(void *a)
{
	struct pkt *p = a;

	sleep(2);
	if (sendto(p->sd, p->pkt, p->len, 0, (const struct sockaddr *)&p->from,
	    sizeof (p->from)) < 0) {
		perror("sendto");
	}
	free(p);
}

int
main(int argc, char **argv)
{
	int sd;
	struct sockaddr_in sin[1];
	struct pkt *p;
	socklen_t slen;
	int reqn = 0;

	if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}

	sin->sin_family = AF_INET;
	sin->sin_port = htons(20000);
	sin->sin_addr.s_addr = INADDR_ANY;
	if (bind(sd, (struct sockaddr *)sin, sizeof (*sin)) < 0) {
		perror("bind");
		exit(1);
	}

	for (;;) {
		if ((p = malloc(sizeof (*p))) == NULL) {
			exit(1);
		}
		p->sd = sd;
		slen = sizeof (*sin);
		if ((p->len = recvfrom(sd, p->pkt, 128, 0,
		    (struct sockaddr *)&p->from, &slen)) < 0) {
			perror("recv");
			exit(1);
		}

#ifdef	THRPOOL
		thrpool_req(process, p, NULL, 0);
#else
		process(p);
#endif

		if (reqn++ > 10) {
			thrpool_set_max(6);
			reqn = 0;
		}
	}

	return (0);
}
