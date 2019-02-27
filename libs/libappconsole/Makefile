
include ../../Makefile.config

LIB= appconsole
VERSION= 1
OBJS= appconsole.o vers
INC= appconsole.h
TESTS= test

# Don't use a console thread for SEND
USE_THREADS=n
ifeq ($(USE_THREADS),y)
LDLIBS= -lpthread
endif

ifeq ($(USE_READLINE),y)
LDLIBS += -lreadline -lcurses
endif

include ../Makefile.lib.common
