#ifndef YYERRCODE
#define YYERRCODE 256
#endif

#define T_ADDRESSES 257
#define T_IPV4 258
#define T_IPV6 259
#define T_SAFI 260
#define T_INHERIT 261
#define T_PREFIX 262
#define T_RANGE 263
#define T_IPV4_ADDR 264
#define T_IPV6_ADDR 265
#define T_UNICAST 266
#define T_MULTICAST 267
#define T_BOTH 268
#define T_MPLS 269
#define T_FILES 270
#define T_TRUSTEDCERT 271
#define T_CERTFILE 272
#define T_OUTFILE 273
#define T_CACERT 274
#define T_CAPRIV 275
#define T_STRING 276
#define T_NUMBER 277
#define T_BAD_TOKEN 278
typedef union {
	char		*string;
	int		num;
	struct in_addr	addr4;
	struct in6_addr addr6;
} YYSTYPE;
extern YYSTYPE pkixip_lval;
