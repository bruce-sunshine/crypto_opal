SUBDIRS =  audio/GSM0610 audio/gsm-amr audio/iLBC audio/Speex audio/G722 audio/G.722.1 audio/G.722.2 audio/G726 audio/LPC_10 audio/IMA_ADPCM video/H.261-vic

all debug opt both \
optshared debugshared bothshared \
optnoshared debugnoshared bothnoshared:
	@set -e; $(foreach dir,$(SUBDIRS),if test -d ${dir} ; then $(MAKE) -C $(dir); fi ; )

clean optclean debugclean:
	@set -e; $(foreach dir,$(SUBDIRS),if test -d ${dir} ; then $(MAKE) -C $(dir) clean; fi ; )

install uninstall:
	@set -e; $(foreach dir,$(SUBDIRS),if test -d ${dir} ; then $(MAKE) -C $(dir) $@; fi ; )

depend optdepend debugdepend bothdepend release tagbuild:
	@echo
