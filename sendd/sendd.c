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
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/select.h>

#include "config.h"
#include <pkixip_ext.h>
#include <applog.h>
#include <appconsole.h>
#include <thrpool.h>
#include <timer.h>

#include "sendd_local.h"
#include "snd_config.h"
#include "os_specific.h"
#include "os/snd_freebsd.h"
#include "dbg.h"

#ifdef	DEBUG
enum snd_dbg_lvl snd_dbg;
struct dlog_desc dbg_snd = {
	.desc = "send",
	.ctx = SENDD_NAME
};
#endif

static int cfd = -1;

static struct timeval *
get_next_wait(struct timeval *tvb)
{
	struct timeval now[1], tctv[1];

	if (timer_check(tctv) == NULL) {
		return (NULL);
	}

	/* Calculate next wait period */
	gettimeofday(now, NULL);
	timersub(tctv, now, tvb);
	// DBG(&dbg_snd, "next wake: %ld.%.6ld", tvb->tv_sec, tvb->tv_usec);

	return (tvb);
}

static int
do_select(int icmps, int ctlfd)
{
	fd_set fds[1];
	int maxfd = -1;
	struct timeval *tv, tvb[1];

	if (cfd != -1) maxfd = cfd;
	maxfd = sendd_max(icmps, maxfd);
	maxfd = sendd_max(ctlfd, maxfd);

	for (;;) {
		FD_ZERO(fds);
		if (cfd != -1) FD_SET(cfd, fds);
		FD_SET(icmps, fds);
		FD_SET(ctlfd, fds);
		os_specific_add_fds(fds, &maxfd);

		tv = get_next_wait(tvb);
		if (select(maxfd + 1, fds, NULL, NULL, tv) < 0) {
			if (errno == EINTR) {
				continue;
			}
			applog(LOG_ERR, "%s: select: %s", __FUNCTION__,
			       strerror(errno));
			return (-1);
		}

#ifdef	USE_CONSOLE
		if (cfd != -1 && FD_ISSET(cfd, fds)) {
#ifdef	USE_READLINE
			console_read_char();
#else
			console_read();
#endif	/* USE_READLINE */
		}
#endif	/* USE_CONSOLE */
		if (FD_ISSET(icmps, fds)) {
			snd_icmp_sock_read();
		}
		if (FD_ISSET(ctlfd, fds)) {
			snd_ctl_read(ctlfd);
		}
		os_specific_dispatch_fds(fds);
		snd_replace_non_cga_linklocals();
	}
}

static void
sighandler(int sig)
{
	snd_cleanup();
	exit(0);
}

void
snd_cleanup(void)
{
#ifdef	USE_CONSOLE
	if (cfd != -1) {
		snd_console_exit();
	}
#endif
	os_specific_fini();
	snd_ra_fini();
	snd_proto_fini();
	snd_sigmeth_fini();
	snd_cga_fini();
	snd_ssl_fini();
	snd_params_fini();
	snd_config_fini();
}

static void
usage(const char *this)
{
	const char **lm = applog_get_methods();

	fprintf(stderr, "Usage: %s [-fV] [-c <conf>] [-i <iface>] "
		"[-l <log method>]\n", this);
	fprintf(stderr, "  log methods: ");
	for (; *lm; lm++) {
		fprintf(stderr, "%s ", *lm);
	}
	fprintf(stderr, "\n");
}

int
main(int argc, char **argv)
{
	int r, c, icmps, ctlfd, do_daemon = 1;
	char *cfile = SNDD_CONF_FILE;

#ifdef	DEBUG
	if (applog_open(L_STDERR, SENDD_NAME) < 0) {
		exit(1);
	}
#else
	if (applog_open(L_SYSLOG, SENDD_NAME) < 0) {
		exit(1);
	}
#endif

	while (argc > 1 && (c = getopt(argc, argv, "fdc:i:l:V")) != -1) {
		switch (c) {
		case 'f':
			do_daemon = 0;
			break;
		case 'c':
			cfile = optarg;
			break;
		case 'i':
			if (snd_add_iface(optarg) < 0) {
				exit(1);
			}
			break;
		case 'd':
#ifdef	DEBUG
			snd_dbg++;
#endif
			break;
		case 'l':
			applog_set_method(applog_str2method(optarg));
			break;
		case 'V':
			printf("%s (SEND rfc3971)\n", SND_VERSION_STR);
			exit(0);
		case 'h':
		default:
			usage(*argv);
			exit(1);
		}
	}

#ifdef	DEBUG
	if (snd_dbg >= SND_DBG_ERR) {
		struct dlog_desc *dbgs[] = {
			&dbg_snd,
			NULL
		};

		if (applog_register(dbgs) < 0) {
			exit(1);
		}
		applog_enable_level(dbg_snd.ctx, dbg_snd.desc);
	}
	if (snd_dbg >= SND_DBG_ALL) {
		applog_addlevel(log_all_on);
	}
#endif

	if (signal(SIGINT, sighandler) < 0 ||
	    signal(SIGTERM, sighandler) < 0) {
		applog(LOG_CRIT, "signal: %s", strerror(errno));
		exit(1);
	}

	thrpool_init();
	if (timer_init() < 0 ||
	    pkixip_init() < 0 ||
	    snd_read_config(cfile) < 0 ||
	    snd_ssl_init() < 0 ||
	    snd_cga_init() < 0 ||
	    snd_params_init() < 0 ||
	    (icmps = snd_net_init()) < 0 ||
	    snd_init_cert() < 0 ||
	    snd_pkixip_config() < 0 ||
	    snd_proto_init() < 0 ||
	    snd_init_opt() < 0 ||
	    snd_ra_init() < 0 ||
	    snd_certpath_init() < 0 ||
	    snd_addr_init() < 0 ||
	    os_specific_init() < 0 ||
	    snd_sigmeth_init() < 0 ||
	    snd_replace_non_cga_linklocals() < 0 ||
	    (ctlfd = snd_ctl_init()) < 0) {
		snd_cleanup();
		exit(1);
	}
	thrpool_set_max(snd_conf_get_int(snd_thrpool_max));

	if (do_daemon) {
		daemon(0, 0);
	}
#ifdef	USE_CONSOLE
	else {
		if (snd_console_init() < 0) {
			exit(1);
		}
		cfd = 0;
	}
#endif
	r = do_select(icmps, ctlfd);

	snd_cleanup();
	exit(r);
}
