include ../../Makefile.config

OBJS= asn1.o config.o pkixip_ext.o pkixip_ext_gram.o pkixip_ext_lex.o \
	util.o ver.o x509.o vers
LIB= pkixipext
VERSION= 1

LDLIBS= -lcrypto -llog

YFLAGS= -d -p pkixip_
LFLAGS= -Ppkixip_
EXTRACLEAN= y.tab.h

include ../Makefile.lib.common
