all:

clang-format:
	# do not format files that were copied into the source directory.
	git ls-files ../../libcomposefs ../../tools ../../kernel | egrep "\\.[hc]" | grep -v "bitrotate\|hash\|xalloc-oversized\|erofs_fs" | xargs clang-format -style=file -i

.PHONY: clang-format
