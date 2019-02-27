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

#ifndef	_SENDD_CTL_H
#define	_SENDD_CTL_H

enum senddctl_status {
	SENDDCTL_STATUS_OK,
	SENDDCTL_STATUS_PROTOERR,
	SENDDCTL_STATUS_INVAL,
	SENDDCTL_STATUS_NOMEM,
	SENDDCTL_STATUS_NOENT,
	SENDDCTL_STATUS_BUSY,
	SENDDCTL_STATUS_SYSERR,
	SENDDCTL_STATUS_BADMETH,
};

/* Response handlers on client */
struct senddctl_clt_handlers {
	void		(*handle_add)(enum senddctl_status, void *cookie);
	void		(*handle_del)(enum senddctl_status, void *cookie);
};

/* Request handlers on server */
struct senddctl_srv_handlers {
	void		(*handle_add_addr)(int, void *, struct in6_addr *, int,
					   const char *, const char *,
					   const char *, int, uint8_t);
	void		(*handle_add_named)(int, void *, const char *,
					    const char *, const char *,
					    const char *, int, uint8_t);
	void		(*handle_del_addr)(int, void *, struct in6_addr *,
					   int);
	void		(*handle_del_named)(int, void *, const char *);
};

extern int senddctl_add_addr_req(int sd, struct in6_addr *, int, const char *,
    const char *, const char *, int, uint8_t);
extern int senddctl_add_named_req(int, const char *, const char *,
    const char *, const char *, int, uint8_t);
extern int senddctl_add_rep(int, void *, enum senddctl_status);
extern void senddctl_close(int);
extern int senddctl_del_addr_req(int, struct in6_addr *, int);
extern int senddctl_del_named_req(int, const char *);
extern int senddctl_del_rep(int, void *, enum senddctl_status);
extern int senddctl_open_clt(void);
extern int senddctl_open_srv(void);
extern void senddctl_clt_read(int, struct senddctl_clt_handlers *, void *);
extern void senddctl_srv_read(int, struct senddctl_srv_handlers *);
extern const char *senddctl_status2str(enum senddctl_status);

#endif	/* _SENDD_CTL_H */
