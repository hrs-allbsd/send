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

#ifndef	_SENDD_LOCAL_H
#define	_SENDD_LOCAL_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <list.h>
#include <sbuff.h>
#include <openssl/sha.h>

#define	SENDD_NAME	"sendd"
#define	SNDD_CONF_FILE	"/etc/sendd.conf"

#define	SND_HASH_SZ	7

/* Convenience macro */
#define	ARR_SZ(a)	sizeof (a) / sizeof (*(a))

#define	SND_MAX_PKT		2048

/* Infinite lifetime for configuring addresses in the kernel */
#define	SND_LIFE_INF		0xffffffff

/* Macros to assist with setting thrpool priorities - higher is better */
#define	SND_THR_PRIO_OUT	20
#define	SND_THR_PRIO_IN		1
#define	SND_THR_PRIO_RESP	10

/* Default signature method, per RFC3971 */
#define	SND_DEFAULT_SIGMETH	"rfc3971"

struct snd_cga_params;

struct snd_sig_method {
	uint8_t		*(*sign)(struct iovec *, int, int *, void *);
	int		(*verify)(struct iovec *, int, uint8_t *, int,
				  uint8_t *, int);
	void		*(*load_key)(const char *);
	void		(*free_key)(void *);
	int		(*init)(void);
	int		(*params_init)(struct snd_cga_params *);
	void		(*fini)(void);
	uint8_t		type;
	const char	*name;
	struct list_head list;
};

struct snd_cga_params {
	void			*key;
	struct snd_sig_method	*sigmeth;
	uint8_t			*der;
	int			dlen;
	uint8_t			sec;
	uint8_t			refcnt;
	uint8_t			keyhash[SHA_DIGEST_LENGTH];
};

/* addr.c */
extern int snd_addr_init(void);
extern int snd_replace_non_cga_linklocals(void);
extern int snd_replace_this_non_cga_linklocal(struct in6_addr *, int);

/* cert.c */
extern int snd_can_verify_now(uint8_t *khash, void **x);
extern int snd_cert_rcvd(uint8_t *, void *, void *, int);
extern int snd_init_cert(void);

/* cga.c */
extern int snd_is_lcl_cga(struct in6_addr *, int ifidx);
extern void snd_cga_fini(void);
extern int snd_cga_gen(struct in6_addr *, struct snd_cga_params *);
extern struct snd_cga_params *snd_cga_get_params(struct in6_addr *, int);
extern int snd_cga_init(void);
extern uint8_t *snd_readder(const char *, int *);
extern void snd_cga_set_keyhash(struct snd_cga_params *);
extern int snd_cga_verify(struct in6_addr *, uint8_t *, int, uint8_t **,
    int *);

/* config.c */
extern int snd_add_iface(const char *);
extern void snd_config_fini(void);
extern void snd_dump_ifaces(void);
extern int snd_iface_ok(int);
extern int snd_read_config(char *);

/* cpa.c */
extern int snd_certpath_init(void);
extern void snd_handle_cps(struct sbuff *, struct sockaddr_in6 *, int);

/* cps.c */
extern void snd_handle_cpa(struct sbuff *, struct sockaddr_in6 *);
extern int snd_make_cps(uint8_t *, void *, void *, struct in6_addr *, int,
    void *);

/* ctl.c */
extern int snd_ctl_init(void);
extern void snd_ctl_read(int);

/* net.c */
extern void snd_icmp_sock_read(void);
extern int snd_net_init(void);
extern struct sbuff *snd_get_buf(void);
extern void snd_put_buf(struct sbuff *);
extern int snd_send_icmp(struct sbuff *, struct sockaddr_in6 *, int);

/* openssl.c */
extern int snd_have_chain(void *);
extern int snd_pkixip_config(void);
extern void snd_pkixip_walk_store(void);
extern void snd_print_cert(void);
extern char *snd_x509_name(void *, char *, int);
extern void snd_ssl_fini(void);
extern int snd_ssl_init(void);
extern void snd_ssl_err(const char *, const char *);

/* opt.c */
extern int snd_add_cert_opt(struct sbuff *, void *);
extern int snd_add_cga_opt(struct sbuff *, uint8_t *, int);
extern int snd_add_nonce_opt(struct sbuff *, uint8_t *, int);
extern int snd_add_timestamp_opt(struct sbuff *);
extern int snd_add_sig_opt(struct sbuff *, uint8_t *, uint8_t *, int, uint8_t);
extern int snd_add_trustanchor_opt(struct sbuff *, void *);
extern int snd_init_opt(void);

/* params.c */
extern int snd_add_addr_params(struct in6_addr *, int, const char *,
    const char *, int, struct snd_sig_method *);
extern int snd_add_addr_params_use(struct in6_addr *, int, const char *);
extern int snd_add_named_params(const char *, const char *, const char *, int,
    struct snd_sig_method *);
extern int snd_add_named_params_use(const char *, const char *);
extern int snd_del_addr_params(struct in6_addr *, int);
extern int snd_del_named_params(const char *);
extern void snd_dump_params(void);
extern struct snd_cga_params *snd_find_params_byaddr(struct in6_addr *, int);
extern struct snd_cga_params *snd_find_params_byifidx(int);
extern void snd_hold_cga_params(struct snd_cga_params *);
extern void snd_put_cga_params(struct snd_cga_params *);
extern int snd_params_init(void);
extern void snd_params_fini(void);

/* proto.c */
extern struct snd_sig_method *snd_packetinfo_sigmeth(void *);
extern int snd_proto_init(void);
extern void snd_proto_fini(void);
extern void snd_finish_racheck(void *, int);

/* ra.c */
extern int snd_process_ra(uint8_t *, int, int, struct in6_addr *);
extern int snd_ra_init(void);
extern void snd_ra_fini(void);
extern void snd_verify_ra(uint8_t *, int, int, void *);

/* sendd.c */
extern void snd_cleanup(void);

/* sigmeth.c */
extern void snd_dump_sig_methods(void);
extern struct snd_sig_method *snd_find_sig_method_byname(const char *);
extern struct snd_sig_method *snd_find_sig_method_bytype(uint8_t);
extern void snd_register_sig_method(struct snd_sig_method *);
extern void snd_sigmeth_fini(void);
extern int snd_sigmeth_init(void);
extern int snd_sigmeth_params_init(struct snd_sig_method *,
    struct snd_cga_params *);
extern void snd_walk_sig_methods(int (*)(struct snd_sig_method *, void *),
    void *);

#ifdef	USE_CONSOLE
/* console.c */
extern void snd_console_exit(void);
extern int snd_console_init(void);

extern void dump_advert_cache(void);
extern void dump_pfx_cache(void);
extern void dump_solicit_cache(void);
extern void dump_timestamp_cache(void);
extern void dump_trustanchors(void);
#endif	/* USE_CONSOLE */

#endif	/* _SENDD_LOCAL_H */
