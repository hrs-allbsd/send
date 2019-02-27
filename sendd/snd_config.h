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

#ifndef	_SENDD_CONFIG_H
#define	_SENDD_CONFIG_H

/* Configurables */
enum snd_conf_syms {
	snd_accept_unconstrained_ra,
	snd_addr_autoconf,
	snd_adv_nonce_cache_life,
	snd_cga_minsec,
	snd_cga_params,
	snd_full_secure,
	snd_min_key_bits,
	snd_nonce_cache_gc_intvl,
	snd_pfx_cache_gc_intvl,
	snd_pkixip_conf,
	snd_replace_linklocals,
	snd_sol_nonce_cache_life,
	snd_timestamp_cache_gc_intvl,
	snd_timestamp_cache_life,
	snd_timestamp_cache_max,
	snd_timestamp_delta,
	snd_timestamp_drift,
	snd_timestamp_fuzz,
#ifndef	NOTHREADS
	snd_thrpool_max,
#endif
#ifdef	DEBUG
	snd_debugs,
#endif
};

enum snd_conf_parse {
	SND_CONF_P_INT,
	SND_CONF_P_STR,
	SND_CONF_P_BOOL,
};

struct snd_conf {
	const char		*sym;
	union {
		const char	*v_str;
		int		v_int;
	} tu;
	const char		*units;
	enum snd_conf_parse	parse;
	int			mandatory;
	enum snd_conf_parse	type;
};

extern struct snd_conf snd_confs[];

#define	snd_conf_get_int(_sym) (snd_confs[_sym].tu.v_int)
#define	snd_conf_get_str(_sym) (snd_confs[_sym].tu.v_str)

#endif	/* _SENDD_CONFIG_H */
