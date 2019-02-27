#ifndef YYERRCODE
#define YYERRCODE 256
#endif

#define T_STRING 257
#define T_IPV6_ADDR 258
#define T_NAMED 259
#define T_ADDR 260
#define T_USE 261
#define T_SIGMETH 262
#define T_DERFILE 263
#define T_KEYFILE 264
#define T_SEC 265
#define T_INTERFACE 266
#define T_BAD_TOKEN 267
#define T_NUMBER 268
typedef union {
	char		*string;
	int		num;
	struct in6_addr addr6;
} YYSTYPE;
extern YYSTYPE params_lval;
