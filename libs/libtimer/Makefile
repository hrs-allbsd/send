
include ../../Makefile.config

OBJS= timer.o vers
LIB= timer
VERSION= 1
INC= timer.h
TESTS= test
RUNTESTS= test
DEP_LIBS= prioq log hashtbl

#
# For this SEND implementation, the timer always runs in the main IO thread
# so we need to override the global threads policy here.
#
CPPFLAGS += -DNOTHREADS

#ifeq ($(USE_THREADS),y)
#DEP_LIBS += thrpool
#endif

include ../Makefile.lib.common
