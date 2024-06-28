source_files = files([
  'bitrotate.h',
  'erofs_fs.h',
  'erofs_fs_wrapper.h',
  'hash.c',
  'hash.h',
  'lcfs-internal.h',
  'lcfs-erofs.h',
  'lcfs-erofs-internal.h',
  'lcfs-fsverity.c',
  'lcfs-fsverity.h',
  'lcfs-writer-erofs.c',
  'lcfs-writer.c',
  'lcfs-writer.h',
  'lcfs-utils.h',
  'lcfs-mount.c',
  'lcfs-mount.h',
  'xalloc-oversized.h',
])

libcomposefs = both_libraries('composefs',
  source_files,
  c_args : composefs_hash_cflags + hidden_visibility_cflags,
  dependencies : libcrypto_dep,
  version : libversion,
  soversion : soversion,
  include_directories : config_inc,
  install : true,
)

pkg.generate(libcomposefs,
  description : 'library for generating and using composefs images',
)

install_headers([
    'lcfs-writer.h',
    'lcfs-erofs.h',
    'lcfs-mount.h',
  ],
  subdir : 'libcomposefs',
)
