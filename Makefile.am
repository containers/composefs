SUBDIRS=libcomposefs tools tests

CLEANFILES=

MAN1PAGES=\
	man/mount.composefs.md \
	man/mkcomposefs.md \
	man/composefs-info.md
MAN5PAGES=\
	man/composefs-dump.md

MANPAGES=${MAN1PAGES} ${MAN5PAGES}

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

man/%.5: man/%.md
	mkdir -p man
	${PANDOC} $+ -s -t man > $@

man1_MANS = $(MAN1PAGES:.md=.1)
man5_MANS = $(MAN5PAGES:.md=.5)

CLEANFILES += ${man1_MANS} ${man5_MANS}

endif
