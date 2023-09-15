SUBDIRS=libcomposefs tools tests

EXTRA_DIST=\
	composefs.pc.in \
	composefs.spec.in \
	composefs.spec

pkgconfig_DATA = composefs.pc

man/%.1: man/%.md
	pandoc $+ -s -t man > $@

install-man: man/mount.composefs.1 man/mkcomposefs.1
	install -m 644 -D --target-directory=$(DESTDIR)$(mandir)/man1 $^
