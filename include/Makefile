include ../Makefile.config

INC= cga.h cga_keyutils.h libinit.h list.h pkixip_ext_asn.h pkixip_ext.h \
	sbuff.h snd_version.h thrpool.h

all install uninstall:

clean:
	$(RM) *~
	$(RM) $(filter-out $(INC),$(wildcard *.h))
