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
#include "config.h"
#include <applog.h>

#ifdef	DEBUG
struct dlog_desc dbg_gen = {
	.desc = "generate",
	.ctx = "libcga"
};
struct dlog_desc dbg_ver = {
	.desc = "verify",
	.ctx = "libcga"
};
struct dlog_desc dbg_asn1 = {
	.desc = "ASN1",
	.ctx = "libcga"
};
struct dlog_desc dbg_mt = {
	.desc = "mt",
	.ctx = "libcga"
};
struct dlog_desc dbg_ssl = {
	.desc = "libssl",
	.ctx = "libcga"
};
struct dlog_desc dbg_stats = {
	.desc = "stats",
	.ctx = "libcga"
};

int
cga_dbg_init(void)
{
	struct dlog_desc *dbgs[] = {
		&dbg_gen,
		&dbg_ver,
		&dbg_asn1,
		&dbg_mt,
		&dbg_ssl,
		&dbg_stats,
		NULL
	};

	return (applog_register(dbgs));
}
#endif