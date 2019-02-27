
include ../../Makefile.config

OBJS= log.o vers
INC= applog.h
LIB= log
VERSION= 1
TESTS= log_example
RUNTEST= true

log_example: CPPFLAGS += -DLOG_TIMESTAMP

include ../Makefile.lib.common
