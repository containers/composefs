SUBDIRS=libcomposefs tools tests

CLEANFILES=

MANPAGES=\
	man/mount.composefs.md \
	man/mkcomposefs.md

EXTRA_DIST=\
	composefs.pc.in \
	composefs.spec.in \
	composefs.spec \
	${MANPAGES}

pkgconfig_DATA = composefs.pc

if ENABLE_MAN

man/%.1: man/%.md
	mkdir -p man
	${PANDOC} $+ -s -t man > $@

man1_MANS = $(MANPAGES:.md=.1)

CLEANFILES += ${man1_MANS}

endif
