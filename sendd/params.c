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
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>

#include "config.h"
#include <hashtbl.h>
#include <applog.h>
#include <list.h>
#include <senddctl.h>

#include "sendd_local.h"
#include "snd_config.h"

struct snd_named_params {
	struct list_head	list;
	const char *		name;
	int			free_params;
	const char		*using;
	struct snd_cga_params	*params;
};

struct snd_addr_params {
	htbl_item_t		hit;
	struct in6_addr		addr;
	int			ifidx;
	int			free_params;
	const char		*using;
	struct snd_cga_params	*params;
};

static DEFINE_LIST_HEAD(named_params);
static htbl_t *addr_params;

extern FILE *params_in;
extern int params_parse(void);

static uint32_t
hash_ent(void *a, int sz)
{
	struct snd_addr_params *p = a;
	return (hash_in6_addr(&p->addr, sz));
}

static int
match_ent(void *a, void *b)
{
	struct snd_addr_params *x = a;
	struct snd_addr_params *y = b;

	if (x->ifidx != y->ifidx) {
		return (x->ifidx - y->ifidx);
	}
	return (memcmp(&x->addr, &y->addr, sizeof (x->addr)));
}

static struct snd_addr_params *
find_params_byaddr(struct in6_addr *a, int ifidx)
{
	struct snd_addr_params k[1];

	k->addr = *a;
	k->ifidx = ifidx;
	return (htbl_find(addr_params, k));
}

static struct snd_named_params *
find_params_byname(const char *name)
{
	struct snd_named_params *p;

	list_for_each_entry(p, &named_params, list) {
		if (strcasecmp(name, p->name) == 0) {
			return (p);
		}
	}

	return (NULL);
}

struct snd_cga_params *
snd_find_params_byaddr(struct in6_addr *a, int ifidx)
{
	struct snd_addr_params *p;

	if ((p = find_params_byaddr(a, ifidx)) != NULL) {
		return (p->params);
	}
	return (snd_find_params_byifidx(ifidx));
}

struct snd_cga_params *
snd_find_params_byifidx(int ifidx)
{
	char ifname[IF_NAMESIZE];
	struct snd_named_params *p;

	if (if_indextoname(ifidx, ifname) == NULL) {
		applog(LOG_ERR, "%s: can't map ifidx %d to name",
		       __FUNCTION__, ifidx);
		return (NULL);
	}

	if ((p = find_params_byname(ifname)) != NULL) {
		return (p->params);
	}
	p = find_params_byname("default");
	return (p->params);
}

/* XXX now that we can delete arbitrary params, we need to refcnt each
 * usage of a set of given params
 */
static void
free_cga_params(struct snd_cga_params *p)
{
	if (p->der) free(p->der);
	if (p->key) p->sigmeth->free_key(p->key);
	free(p);
}

static void
free_addr_params(struct snd_addr_params *p)
{
	if (p->free_params) {
		snd_put_cga_params(p->params);
	}
	free(p);
}

static void
free_named_params(struct snd_named_params *p)
{
	if (p->free_params) {
		snd_put_cga_params(p->params);
	}
	free(p);
}

static int
add_named_params(const char *name, struct snd_cga_params *params,
    int free_params, const char *use)
{
	struct snd_named_params *p;

	if ((p = find_params_byname(name)) != NULL) {
		applog(LOG_WARNING, "%s: %s already configured", __FUNCTION__,
		       name);
		return (0);
	}
	if ((p = malloc(sizeof (*p))) == NULL) {
		APPLOG_NOMEM();
		return (SENDDCTL_STATUS_NOMEM);
	}
	memset(p, 0, sizeof (*p));

	if ((p->name = strdup(name)) == NULL) { // XXX need to free this, but be careful dangling refs
		free(p);
		APPLOG_NOMEM();
		return (SENDDCTL_STATUS_NOMEM);
	}

	p->free_params = free_params;
	p->params = params;
	p->using = use;
	list_add_tail(&p->list, &named_params);

	return (0);
}

static int
add_addr_params(struct in6_addr *a, int ifidx,
    struct snd_cga_params *params, int free_params, const char *use)
{
	struct snd_addr_params *p;
	char abuf[INET6_ADDRSTRLEN];

	if (find_params_byaddr(a, ifidx) != 0) {
		applog(LOG_WARNING, "%s: %s already configured", __FUNCTION__,
		       inet_ntop(AF_INET6, a, abuf, sizeof (abuf)));
		return (0);
	}

	if ((p = malloc(sizeof (*p))) == NULL) {
		APPLOG_NOMEM();
		return (SENDDCTL_STATUS_NOMEM);
	}
	memset(p, 0, sizeof (*p));

	p->addr = *a;
	p->ifidx = ifidx;
	p->free_params = free_params;
	p->params = params;
	p->using = use;
	htbl_add(addr_params, p, &p->hit);

	return (0);
}

static struct snd_cga_params *
new_snd_cga_params(uint8_t *der, int dlen, void *key, int sec,
    struct snd_sig_method *m, enum senddctl_status *status)
{
	struct snd_cga_params *p;

	if ((p = malloc(sizeof (*p))) == NULL) {
		APPLOG_NOMEM();
		free(der);
		m->free_key(key);
		*status = SENDDCTL_STATUS_NOMEM;
		return (NULL);
	}
	p->key = key;
	p->sigmeth = m;
	p->der = der;
	p->dlen = dlen;
	p->sec = sec;
	p->refcnt = 1;
	snd_cga_set_keyhash(p);

	if (snd_sigmeth_params_init(m, p) == 0) {
		*status = SENDDCTL_STATUS_OK;
	} else {
		*status = SENDDCTL_STATUS_SYSERR;
		free_cga_params(p);
		p = NULL;
	}
	return (p);
}

static struct snd_cga_params *
create_snd_cga_params(const char *name, const char *derfile,
    const char *keyfile, int sec, struct snd_sig_method *m,
    enum senddctl_status *status)
{
	uint8_t *der;
	int dlen;
	void *key;

	if (m == NULL &&
	    (m = snd_find_sig_method_byname(SND_DEFAULT_SIGMETH)) == NULL) {
		applog(LOG_ERR, "%s: Can't find any valid signature method!",
		       __FUNCTION__);
		*status = SENDDCTL_STATUS_SYSERR;
		return (NULL);
	}
	if ((der = snd_readder(derfile, &dlen)) == NULL) {
		applog(LOG_ERR, "%s: reading params failed for %s",
		       __FUNCTION__, name);
		*status = SENDDCTL_STATUS_INVAL;
		return (NULL);
	}

	if ((key = m->load_key(keyfile)) == NULL) {
		free(der);
		applog(LOG_ERR, "%s: reading key failed for %s",
		       __FUNCTION__, name);
		*status = SENDDCTL_STATUS_INVAL;
		return (NULL);
	}

	return (new_snd_cga_params(der, dlen, key, sec, m, status));
}

int
snd_add_named_params(const char *name, const char *derfile,
    const char *keyfile, int sec, struct snd_sig_method *m)
{
	struct snd_cga_params *p;
	enum senddctl_status st;

	if ((p = create_snd_cga_params(name, derfile, keyfile, sec, m, &st))
	    == NULL) {
		return (st);
	}
	if ((st = add_named_params(name, p, 1, NULL)) != 0) {
		free_cga_params(p);
	}
	return (st);
}

int
snd_add_named_params_use(const char *name, const char *use)
{
	struct snd_named_params *p;
	enum senddctl_status st;

	if ((p = find_params_byname(use)) == NULL) {
		applog(LOG_ERR, "%s: Can't find params %s", __FUNCTION__,
		       use);
		return (SENDDCTL_STATUS_NOENT);
	}

	snd_hold_cga_params(p->params);
	if ((st = add_named_params(name, p->params, 0, p->name)) != 0) {
		snd_put_cga_params(p->params);
	}
	return (st);
}

int
snd_add_addr_params(struct in6_addr *a, int ifidx, const char *derfile,
    const char *keyfile, int sec, struct snd_sig_method *m)
{
	struct snd_cga_params *p;
	enum senddctl_status st;

	if ((p = create_snd_cga_params("addr", derfile, keyfile, sec, m, &st))
	    == NULL) {
		return (st);
	}
	if ((st = add_addr_params(a, ifidx, p, 1, NULL)) != 0) {
		free_cga_params(p);
	}
	return (st);
}

int
snd_add_addr_params_use(struct in6_addr *a, int ifidx, const char *use)
{
	struct snd_named_params *p;
	enum senddctl_status st;

	if ((p = find_params_byname(use)) == NULL) {
		applog(LOG_ERR, "%s: Can't find params %s", __FUNCTION__, use);
		return (SENDDCTL_STATUS_NOENT);
	}

	snd_hold_cga_params(p->params);
	if ((st = add_addr_params(a, ifidx, p->params, 0, p->name)) != 0) {
		snd_put_cga_params(p->params);
	}
	return (st);
}

int
snd_del_addr_params(struct in6_addr *a, int ifidx)
{
	struct snd_addr_params *p;

	if ((p = find_params_byaddr(a, ifidx)) == NULL) {
		return (SENDDCTL_STATUS_NOENT);
	}
	if (!p->using && p->params->refcnt > 1) {
		return (SENDDCTL_STATUS_BUSY);
	}
	htbl_rem_hit(addr_params, &p->hit);
	free_addr_params(p);
	return (0);
}

int
snd_del_named_params(const char *name)
{
	struct snd_named_params *p;

	if ((p = find_params_byname(name)) == NULL) {
		return (SENDDCTL_STATUS_NOENT);
	}
	/* Don't delete if this is being referenced */
	if (!p->using && p->params->refcnt > 1) {
		return (SENDDCTL_STATUS_BUSY);
	}

	list_del(&p->list);
	free_named_params(p);
	return (0);
}

static int
read_cga_params(void)
{
	const char *f = snd_conf_get_str(snd_cga_params);

	if (f == NULL) {
		return (0);
	}

	if ((params_in = fopen(f, "r")) == NULL) {
		applog(LOG_ERR, "%s: fopen(%s): %s", __FUNCTION__, f,
		       strerror(errno));
		return (-1);
	}

	if (params_parse() != 0) {
		return (-1);
	}

	fclose(params_in);
	return (0);
}

void
snd_hold_cga_params(struct snd_cga_params *p)
{
	p->refcnt++;
}

void
snd_put_cga_params(struct snd_cga_params *p)
{
	p->refcnt--;
	if (p->refcnt == 0) {
		free_cga_params(p);
	}
}

static void
hexdump(uint8_t *b, int len, char *indent)
{
	int i;

	if (indent) printf(indent);
	for (i = 0; i < len; i++) {
		int v = b[i] & 0xff;
		printf("%.2x ", v);

		if (((i + 1) % 16) == 0) {
			printf("\n");
			if (indent) printf(indent);
		} else if (((i + 1) % 8) == 0) {
			printf(" ");
		}
	}
	printf("\n");
}

static void
dump_cga_params(struct snd_cga_params *p)
{
	printf("\tref: %d sig method: %s (%d)\n", p->refcnt, p->sigmeth->name,
	       p->sigmeth->type);
	hexdump(p->der, 16, "\t");
}

static void
dump_walker(void *p, void *c)
{
	struct snd_addr_params *pa = p;
	char abuf[INET6_ADDRSTRLEN];

	printf("%-25s  sec %d ifidx %d %s%s\n",
	       inet_ntop(AF_INET6, &pa->addr, abuf, sizeof (abuf)),
	       pa->params->sec, pa->ifidx,
	       pa->using ? "use: " : "", pa->using ? pa->using : "");
	if (!pa->using) {
		dump_cga_params(pa->params);
	}
}

void
snd_dump_params(void)
{
	struct snd_named_params *pn;

	list_for_each_entry(pn, &named_params, list) {
		printf("%-25s  sec %d %s%s\n", pn->name,
		       pn->params->sec,
		       pn->using ? "use: " : "", pn->using ? pn->using : "");
		if (!pn->using) {
			dump_cga_params(pn->params);
		}
	}

	htbl_walk(addr_params, dump_walker, NULL);
}

int
snd_params_init(void)
{
	if ((addr_params = htbl_create(SND_HASH_SZ, hash_ent, match_ent))
	    == NULL) {
		applog(LOG_ERR, "%s: htbl_create() failed", __FUNCTION__);
		return (-1);
	}

	if (read_cga_params() < 0) {
		return (-1);
	}
	if (find_params_byname("default") == NULL) {
		applog(LOG_ERR, "%s: missing 'default' params", __FUNCTION__);
		return (-1);
	}
	return (0);
}

void
snd_params_fini(void)
{
	// XXX improve cleanup - list too
	if (addr_params) htbl_destroy(addr_params, free);
}
