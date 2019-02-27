include ../Makefile.config

PROG= ipexttool
DEPLIBS= -llog -lpkixipext
CFLAGS= -Wall
CPPFLAGS= -I../include

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

all: $(PROG)

$(PROG): $(PROG).o

$(PROG).o: Makefile ../include/config.h

clean:
	$(RM) $(PROG) *.o *~

include ../Makefile.install
