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


#include "config.h"
#include <applog.h>

#include "sendd_local.h"
#include "dbg.h"

static DEFINE_LIST_HEAD(sig_methods);

void
snd_register_sig_method(struct snd_sig_method *m)
{
	list_add_tail(&m->list, &sig_methods);
}

struct snd_sig_method *
snd_find_sig_method_byname(const char *n)
{
	struct snd_sig_method *m;

	list_for_each_entry(m, &sig_methods, list) {
		if (strcasecmp(m->name, n) == 0) {
			return (m);
		}
	}
	return (NULL);
}

struct snd_sig_method *
snd_find_sig_method_bytype(uint8_t t)
{
	struct snd_sig_method *m;

	list_for_each_entry(m, &sig_methods, list) {
		if (m->type == t) {
			return (m);
		}
	}
	return (NULL);
}

void
snd_walk_sig_methods(int (*cb)(struct snd_sig_method *, void *), void *c)
{
	struct snd_sig_method *m;

	list_for_each_entry(m, &sig_methods, list) {
		if (!cb(m, c)) {
			return;
		}
	}
}

int
snd_sigmeth_params_init(struct snd_sig_method *m, struct snd_cga_params *p)
{
	if (m->params_init) {
		return (m->params_init(p));
	}
	return (0);
}

void
snd_dump_sig_methods(void)
{
	struct snd_sig_method *m;

	list_for_each_entry(m, &sig_methods, list) {
		printf("\t%s (%d)\n", m->name, m->type);
	}
}

int
snd_sigmeth_init(void)
{
	struct snd_sig_method *m;

	list_for_each_entry(m, &sig_methods, list) {
		if (m->init && m->init() < 0) {
			return (-1);
		}
	}
	return (0);
}

void
snd_sigmeth_fini(void)
{
	struct snd_sig_method *m;

	list_for_each_entry(m, &sig_methods, list) {
		if (m->fini) {
			m->fini();
		}
	}
}
