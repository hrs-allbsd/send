
include ../../Makefile.config

OBJS= thrpool.o vers
LIB= thrpool
VERSION= 1
DEP_LIBS= hashtbl prioq log

ifeq ($(USE_THREADS),y)
LDLIBS = -lpthread
TESTS= test tsrv tcli thrspec_test intr_test prio_test excl_test
RUNTESTS= test thrspec_test intr_test excl_test
endif

# un-comment if you want gobs of debug into
# CPPFLAGS += -DTHRPOOL_LOTS_AND_LOTS_OF_DEBUG

include ../Makefile.lib.common
