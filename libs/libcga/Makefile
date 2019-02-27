include ../../Makefile.config

OBJS= cga.o cga_keyutils.o cga_mt.o cga_dbg.o vers
LIB= cga
VERSION= 1
TESTS= cmp mpadd

LDLIBS= -llog -lcrypto

ifeq ($(USE_THREADS),y)
LDLIBS += -lpthread
endif

include ../Makefile.lib.common
