
OBJS += os/addr.o os/snd_freebsd.o os-linux/rand.o
CPPFLAGS +=	-I/usr/local/include

OSLIBS= -L/usr/local/lib -l$(DNET)

OSEXTRA= os/sendd
EXTRAINSTALL= /usr/local/etc/rc.d/sendd
EXTRAUNINSTALL=$(EXTRAINSTALL)

/usr/local/etc/rc.d/%: os/%
	install $< $@

