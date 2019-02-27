
OBJS += os/addr.o os/ipq.o os/rand.o os/snd_linux.o
OSLIBS= -ldl -lipq

OSEXTRA= os/sendd os/snd_upd_fw

ETCINIT= /etc/init.d
EXTRAINSTALL= $(ETCINIT)/sendd $(ETCINIT)/snd_upd_fw $(ETCINIT)/snd_fw_functions.sh
EXTRAUNINSTALL=$(EXTRAINSTALL)
EXTRACLEAN= os/sendd os/snd_upd_fw os/snd_fw_functions.sh

$(ETCINIT)/%: os/%
	install $< $@

os/%: os/%.in
	sed "s/@etcinit@/\/etc\/init.d/g" $< > $@

os/%: os/%.in2
	@./os/find_ip6tables.sh

# Sometimes libipq.h is installed in include/libipq.h, other times it is
# installed in include/libipq/libipq.h. This rule helps cpp to find it.
os/ipq.o: CPPFLAGS += -I/usr/include/libipq -I/usr/local/include/libipq
