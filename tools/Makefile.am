bin_PROGRAMS = mkcomposefs
noinst_PROGRAMS = dump

if USE_YAJL
noinst_PROGRAMS += writer-json
endif

AM_CFLAGS = $(WARN_CFLAGS)

dump_SOURCES = dump.c
dump_LDADD = ../libcomposefs/libcomposefs.la

mkcomposefs_SOURCES = mkcomposefs.c
mkcomposefs_LDADD =  ../libcomposefs/libcomposefs.la

writer_json_SOURCES = writer-json.c read-file.c read-file.h
writer_json_LDADD = ../libcomposefs/libcomposefs.la $(LIBS_YAJL)
