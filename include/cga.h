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

#ifndef	_CGA_H
#define	_CGA_H

#include <string.h>
#include <netinet/in.h>

#define	CGA_MODLEN	16
#define	CGA_SECMULT	16	/* sec multiplier */
#define	CGA_PARAM_LEN	(CGA_MODLEN + 8 + 1)
#define	CGA_MAX_COL	2
#define	CGA_MAX_SEC	7

#define	CGA_SEND_MSG_TYPE_TAG { \
	0x08, 0x6f, 0xca, 0x5e, 0x10, 0xb2, 0x00, 0xc9, \
	0x9c, 0x8c, 0xe0, 0x01, 0x64, 0x27, 0x7c, 0x08 }

struct cga_pseudo {
	uint8_t		msgtype[16];
	struct in6_addr	src;
	struct in6_addr	dst;
} __attribute__ ((packed));

typedef struct {
	/* public members; access directly */
	uint8_t		*key;	/* DER-encoded Public key */
	int		klen;
	struct in6_addr	prefix;	/* Prefix */
	struct in6_addr	addr;	/* Generated address */
	int		collisions; /* Collision count */
	uint8_t		sec;	/* Sec value */
	int		thrcnt;	/* Number of threads to use for generation */
	uint32_t	batchsize; /* work chunk size for each thread */

	/* private members; use accessor functions to modify */
	int		derlen;	/* Length of der, in bytes */
	uint8_t		*der;	/* DER-encoded key and CGA parameters */
	uint8_t		modifier[CGA_MODLEN]; /* Modifier */
	uint8_t
			key_set : 1,
			prefix_set : 1,
			mod_set : 1,
			der_set : 1,
			addr_set : 1,
			free_der : 1,
			free_key : 1;
} cga_ctx_t;

typedef struct cga_parsed_params {
	uint8_t *buf;
	uint8_t	*mod;
	uint8_t *pfx;
	uint8_t *col;
	uint8_t *key;
	int dlen;
	int klen;
} cga_parsed_params_t;

#define	cga_init_ctx(__ctx) \
	do { \
		memset(__ctx, 0, sizeof (*__ctx)); \
		__ctx->batchsize = 500000; \
		__ctx->thrcnt = 1; \
	} while (0)

#define	cga_ready_to_gen(__ctx) \
	((__ctx)->key_set && (__ctx)->prefix_set)

#define	cga_ready_to_ver(__ctx) \
	((__ctx)->der_set && (__ctx)->addr_set)

#define	cga_get_sec(__a) (((__a)->s6_addr[8] & 0xe0) >> 5)

extern void cga_cleanup_ctx(cga_ctx_t *);
extern void cga_free_ctx(cga_ctx_t *);
extern int cga_generate(cga_ctx_t *);
extern void cga_gen_cancel(void);
extern int cga_verify(cga_ctx_t *);
extern cga_ctx_t *new_cga_ctx(void);
extern int cga_parse_params(struct cga_parsed_params *);
extern int cga_parse_params_ctx(cga_ctx_t *);
extern int cga_init(void);

/* accessors */
extern int cga_set_der(cga_ctx_t *, uint8_t *, int);
extern uint8_t *cga_get_der(cga_ctx_t *, int *);
extern void cga_set_modifier(cga_ctx_t *, uint8_t *);
extern uint8_t *cga_get_modifier(cga_ctx_t *);
extern void cga_set_addr(cga_ctx_t *, struct in6_addr *);
extern void cga_set_prefix(cga_ctx_t *, struct in6_addr *);
extern int cga_set_sec(cga_ctx_t *, int);
extern int cga_set_col(cga_ctx_t *, int);

extern const char *cga_version;

#endif	/* _CGA_H */
/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
