
OBJS += os/addr.o os/snd_freebsd.o os/netgraph.o os-linux/rand.o

OSLIBS= -lnetgraph -l$(DNET)

OSEXTRA= os/sendd
EXTRAINSTALL= /usr/local/etc/rc.d 
EXTRAUNINSTALL=$(EXTRAINSTALL)

/usr/local/etc/rc.d/%: os/%
	install $< $@

