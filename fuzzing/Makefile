all: main main-run-single run

main: main.c ../kernel/lcfs.h ../kernel/lcfs-fuzzing.h ../kernel/lcfs-reader.h ../kernel/lcfs-reader.c  ../tools/read-file.h ../tools/read-file.c
	HFUZZ_CC_UBSAN=1 HFUZZ_CC_ASAN=1 hfuzz-clang -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,indirect-calls -I ../kernel -DSTANDALONE_COMPOSEFS=1 -DFUZZING=1 main.c ../kernel/lcfs-reader.c ../tools/read-file.c -o $@

main-run-single: main.c ../kernel/lcfs.h ../kernel/lcfs-fuzzing.h ../kernel/lcfs-reader.h ../kernel/lcfs-reader.c  ../tools/read-file.h ../tools/read-file.c
	$(CC) -ggdb3 -I ../kernel -DFUZZING=1 -DFUZZING_RUN_SINGLE=1 -DSTANDALONE_COMPOSEFS=1 main.c ../kernel/lcfs-reader.c ../tools/read-file.c -o $@

corpus:
	rm -rf corpus_
	mkdir corpus_
	../tools/writer-json < ../tools/test-assets/config.json  > corpus_/tree.1
	../tools/writer-json < ../tools/test-assets/config-with-hard-link.json  > corpus_/tree.2
	../tools/writer --chdir .. > corpus_/tree.3
	mv corpus_ corpus

run: corpus
	honggfuzz --timeout=10s --exit_upon_crash -i corpus -- ./main

.PHONY: run

clean:
	rm -rf main corpus main-run-single
