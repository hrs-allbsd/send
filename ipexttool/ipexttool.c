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
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include "config.h"
#include <applog.h>
#include "pkixip_ext.h"

static void
asn1dump(IPAddrBlocks *ipb)
{
	uint8_t *p, *b;
	int len;
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);

	len = i2d_IPAddrBlocks(ipb, NULL);

	b = malloc(len);

	p = b;
	len = i2d_IPAddrBlocks(ipb, &p);

	/* ASN1_parse_* leaks memory, but who cares... */
	ASN1_parse_dump(bio, b, len, 1, -1);
	BIO_free(bio);
}

static struct option cmd_opts[] = {
	{ "cacert", 1, 0, 'C' },
	{ "cert", 1, 0, 'c' },
	{ "debug", 0, 0, 'D' },
	{ "help", 0, 0, 'h' },
	{ "infile", 1, 0, 'i' },
	{ "outfile", 1, 0, 'o' },
	{ "print", 0, 0, 'p' },
	{ "privkey", 1, 0, 'k' },
	{ "verify", 0, 0, 'v' },
	{ "version", 0, 0, 'V' },
	{ "write", 0, 0, 'w' },
	{ 0 }
};

static const char *cmd_exps[] = {
	"File containing an X509 signer's certificate",
	"File contianing an X509 certificate",
	"Turn on verbose debugging, if built with DEBUG",
	"Show this help synopsis",
	"PKIPExt library configuration file",
	"Output file for X509 certificate with IP Extensions",
	"Display an X509 certificate with IP Extensions",
	"File containing PEM-encoded private key for signing",
	"Verify a certificate chain with IP extensions",
	"Show version",
	"Write an X509 certificate with IP extensions",
};

static void
usage(const char *this)
{
	struct option *op;
	const char **exp;

	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s\n", this);

	fprintf(stderr, "\nOptions:\n");
	for (op = cmd_opts, exp = cmd_exps; op->name; op++, exp++) {
		printf("  --%-12s(-%c)\t%s\n", op->name, op->val, *exp);
	}
}

int
main(int argc, char **argv)
{
	int rv = 0;
	IPAddrBlocks *ipb = NULL;
	int c;
	int write = 0;
	int ver = 0;
	int print = 0;
	X509 *x = NULL;
	X509 *cax = NULL;
	EVP_PKEY *pkey = NULL;
	const char *infile = NULL;
	struct pkixip_config cf[1];

	if (argc == 1) {
		usage(*argv);
		return (1);
	}

	if (applog_open(L_STDERR, "PKIX IP Ext") < 0) {
		return (1);
	}

	memset(cf, 0, sizeof (cf));

	while ((c = getopt_long_only(argc, argv, "C:c:dhi:o:pk:vVw", cmd_opts,
				     NULL)) != -1) {

		switch (c) {
		case 'C':
			cf->cacert = optarg;
			break;
		case 'c':
			cf->certfile = optarg;
			break;
		case 'd':
			applog_addlevel(log_all_on);
			break;
		case 'h':
			usage(*argv);
			exit(0);
		case 'i':
			infile = optarg;
			break;
		case 'o':
			cf->outfile = optarg;
			break;
		case 'p':
			print = 1;
			break;
		case 'k':
			cf->capriv = optarg;
			break;
		case 'v':
			ver = 1;
			break;
		case 'V':
			fprintf(stderr, "%s (IPExt rfc3779)\n",
				SND_VERSION_STR);
			exit(0);
		case 'w':
			write = 1;
			break;
		default:
			fprintf(stderr, "Invalid flag '%c'\n", c);
			usage(*argv);
			exit(1);
		}
	}

	if (pkixip_init() < 0) {
		return (1);
	}

	if (infile && pkixip_read_config(infile, cf, &ipb) < 0) {
		fprintf(stderr, "pkixip_read_config() failed\n");
		rv = 1;
		goto cleanup;
	}

	if (cf->certfile && (x = pkixip_load_cert(cf->certfile)) == NULL) {
			rv = 1;
			goto cleanup;
	}

	if (x && ipb && ver && pkixip_verify_cert(x, ipb) < 0) {
		fprintf(stderr, "verify failed\n");
		rv = 1;
		goto cleanup;
	}

	if (cf->capriv && (pkey = pkixip_load_pkey(cf->capriv)) == NULL) {
		rv = 1;
		goto cleanup;
	}

	if (cf->cacert && (cax = pkixip_load_cert(cf->cacert)) == NULL) {
		rv = 1;
		goto cleanup;
	}

	if (x && write &&
	    pkixip_write_ext(x, cf->outfile ? cf->outfile : cf->certfile, ipb, cax, pkey) < 0) {
		rv = 1;
		goto cleanup;
	}

	if (x && print) {
		X509_print_fp(stdout, x);
	}
	if (print && ipb) {
		asn1dump(ipb);
	}

cleanup:
	if (x) X509_free(x);

	if (ipb) IPAddrBlocks_free(ipb);

	return (rv);
}
