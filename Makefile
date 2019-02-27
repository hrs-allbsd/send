
SUBDIRS= include libs cgatool ipexttool sendd

all :		TARGET= all
install :	TARGET= install
uninstall :	TARGET= uninstall
clean :		TARGET= clean

all install: sendd/os include/config.h $(SUBDIRS)

uninstall: $(SUBDIRS)

.PHONY: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(TARGET)

clean: sendd/os $(SUBDIRS)
	$(RM) *~ sendd/os include/config.h

sendd/os: Makefile.config
	cd sendd; $(RM) os; ln -s os-$(OS) os

include Makefile.config

dist: clean
	cd ..; mv send $(SND_VERSION_DISTNAME); tar jcf $(SND_VERSION_DISTNAME).tar.bz2 $(SND_VERSION_DISTNAME) -X $(SND_VERSION_DISTNAME)/dist_excl; mv $(SND_VERSION_DISTNAME) send

include/config.h: Makefile.config
	@echo "rebuilding config.h"
	@echo "#ifndef _SND_CONFIG_H" > include/config.h
	@echo "#define _SND_CONFIG_H" >> include/config.h
	@echo "#define SND_OS_$(OS)" >> include/config.h
ifeq ($(DEBUG_POLICY),DEBUG)
	@echo "#define DEBUG" >> include/config.h
endif
ifeq ($(USE_THREADS),n)
	@echo "#ifndef NOTHREADS" >> include/config.h
	@echo "#define NOTHREADS" >> include/config.h
	@echo "#endif" >> include/config.h
endif
ifeq ($(USE_CONSOLE),y)
	@echo "#define USE_CONSOLE" >> include/config.h
endif
ifeq ($(USE_READLINE),y)
	@echo "#define USE_READLINE" >> include/config.h
endif
ifeq ($(LOG_BACKTRACE),y)
	@echo "#define LOG_BACKTRACE" >> include/config.h
endif
ifeq ($(LOG_TIMESTAMP),y)
	@echo "#define LOG_TIMESTAMP" >> include/config.h
endif
	@echo "#define SND_VERSION_STR \"$(SND_VERSION_STR)\"" >> include/config.h
	@echo "#endif" >> include/config.h

