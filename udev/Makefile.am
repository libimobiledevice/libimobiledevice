udevdir=$(sysconfdir)/udev/rules.d/
udev_DATA=89-libiphone.rules

edit = sed \
        -e 's|@bindir[@]|$(bindir)|g' 

89-libiphone.rules:
	rm -f $@ $@.tmp
	$(edit) '$(srcdir)/$@.in' >$@.tmp
	mv $@.tmp $@

bin_SCRIPTS = set-usb-configuration-3.sh
