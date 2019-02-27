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

#ifndef	_SENDDCTL_PROTO_H
#define	_SENDDCTL_PROTO_H

#define	SENDD_CTL_PATH	"/var/run/sendd.ctl"
#define	SENDDCTL_BUFSZ	2048

enum {
	SENDDCTL_ADD_ADDR,
	SENDDCTL_ADD_NAMED,
	SENDDCTL_ADD_REPLY,
	SENDDCTL_DEL_ADDR,
	SENDDCTL_DEL_NAMED,
	SENDDCTL_DEL_REPLY,
};

enum {
	SENDDCTL_SRC_USE,
	SENDDCTL_SRC_EXP,
};

/*
 * For add requests, the parameters can either be for an address or  new
 * named parameters. If for named parameters, a string containing the
 * name for the new parameters follows the header.
 *
 * Next, for both named and address parameters, if source is "used",
 * one string follows the header:
 * 1. Name to use.
 *
 * If the source is "explicit", two strings follow the header, in this order:
 * 1. CGA paramaters file name
 * 2. Private key file name
 *
 * For delete requests, the add headers are reused. For an addr deletion,
 * no strings follow the header. For a named deletion, one string follows
 * the header, containing the name of the parameters to delete.
 *
 * The sec member is ignored if the source is "used".
 * All integers are in host byte order.
 * All strings are NULL-terminated.
 */
struct senddctl_add_addr_req {
	uint8_t		cmd;
	uint8_t		src;
	uint16_t	ifidx;
	struct in6_addr	addr;
	uint8_t		sec;
	uint8_t		sigmeth;
	uint8_t		strings[];
} __attribute__ ((packed));

struct senddctl_add_named_req {
	uint8_t		cmd;
	uint8_t		src;
	uint8_t		sec;
	uint8_t		sigmeth;
	uint8_t		strings[];
} __attribute__ ((packed));;

struct senddctl_add_rep {
	uint8_t		cmd;
	uint8_t		status;
} __attribute__ ((packed));

#endif	/* _SENDDCTL_PROTO_H */
