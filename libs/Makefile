include ../Makefile.config

SUBDIRS= liblog libprioq libhashtbl libconfig libtimer libincksum \
	libcga libpkixipext libsenddctl

ifeq ($(USE_CONSOLE),y)
SUBDIRS += libappconsole
endif

ifeq ($(USE_THREADS),y)
SUBDIRS += libthrpool
endif

all :		TARGET= all
clean :		TARGET= clean
runtest :	TARGET= runtest

all runtest: $(SUBDIRS)

#
# By default we don't install libs and their headers for SEND,
# opting instead for static linking.
# If you want the SEND applications to dynamically link against shared
# objects, make sure CREATE_SHARED is configured, and change the following
# install uninstall: rule to
#   install uninstall: $(SUBDIRS)
#
install: all

uninstall:

.PHONY: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(TARGET)

clean: $(SUBDIRS)
	$(RM) -r *~ .libs
