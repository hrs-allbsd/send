include ../Makefile.config

PROG= sendd
OBJS= addr.o cert.o cga.o config.o cpa.o cps.o ctl.o net.o openssl.o opt.o \
	params.o proto.o proto_nonce.o proto_sig.o proto_timestamp.o ra.o \
	sendd.o sigmeth.o sig_rfc3971.o
INC= sendd_local.h snd_proto.h snd_config.h

CFLAGS= -Wall -O3
CPPFLAGS=  -I../include -I../../src/sys 
YFLAGS= -d -p params_
LFLAGS= -Pparams_

DEPLIBS_THR_$(USE_THREADS)= -lthrpool
DEPLIBS= $(DEPLIBS_THR_y) -lcga -llog -lconfig -lhashtbl -lincksum -ltimer -lprioq -lpkixipext -lsenddctl

ifeq ($(USE_CONSOLE),y)
OBJS += console.o
DEPLIBS += -lappconsole
endif

include os/Makefile

ifeq ($(STATIC),y)
LDLIBS= $(patsubst -l%,../libs/.libs/lib%.a,$(DEPLIBS))
else
LDLIBS= $(DEPLIBS)
LDFLAGS= -L../libs/.libs
endif

LDLIBS += -lcrypto
LDLIBS += $(OSLIBS)

ifeq ($(USE_THREADS),y)
LDLIBS += -lpthread
endif

ifeq ($(USE_CONSOLE),y)
ifeq ($(USE_READLINE),y)
LDLIBS += -lreadline -lncurses
endif
endif

ifeq ($(DEBUG_POLICY),DEBUG)
OBJS += dbg.o
CFLAGS += -g
endif

OBJS += params_gram.o params_lex.o

all: $(PROG) $(OSEXTRA)

$(PROG): $(OBJS)

$(OBJS): $(INC) Makefile ../Makefile.config

clean:
	$(RM) *.o $(PROG) *~ os*/*.o os*/*~ $(EXTRACLEAN) y.tab.h

include ../Makefile.install
