include ../Makefile.config

PROG= cgatool
DEPLIBS= -llog -lconfig -lhashtbl -lcga -lsenddctl
CFLAGS= -Wall
CPPFLAGS= -I../include

ifeq ($(USE_CONSOLE),y)
DEPLIBS += -lappconsole
endif

ifeq ($(STATIC),y)
LDLIBS= $(patsubst -l%,../libs/.libs/lib%.a,$(DEPLIBS))

else
LDLIBS= $(DEPLIBS)
LDFLAGS= -L../libs/.libs
endif

LDLIBS += -lcrypto

ifeq ($(USE_THREADS),y)
LDLIBS += -lpthread
endif

ifeq ($(USE_CONSOLE),y)
ifeq ($(USE_READLINE),y)
LDLIBS += -lreadline -lncurses
endif
endif

all: $(PROG)

$(PROG): $(PROG).o

$(PROG).o: Makefile ../include/config.h

clean:
	$(RM) $(PROG) *.o *~

include ../Makefile.install
