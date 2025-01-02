project(
  'composefs',
  'c',
  version : '1.0.8',
  default_options : [
    'c_std=c11',
    'warning_level=1',
  ],
)

pkg = import('pkgconfig')

libcomposefs_version_major = 1
libcomposefs_version_minor = 4
libcomposefs_version_micro = 0
libversion = '@0@.@1@.@2@'.format(libcomposefs_version_major, libcomposefs_version_minor, libcomposefs_version_micro)
soversion = libcomposefs_version_major

cc = meson.get_compiler('c')
add_project_arguments(
  cc.get_supported_arguments([
    '-Werror=shadow',
    '-Werror=empty-body',
    '-Werror=strict-prototypes',
    '-Werror=missing-prototypes',
    '-Werror=implicit-function-declaration',
    '-Werror=format=2 -Werror=format-security -Werror=format-nonliteral',
    '-Werror=pointer-arith',
    '-Werror=init-self',
    '-Werror=missing-declarations',
    '-Werror=return-type',
    '-Werror=switch',
    '-Werror=overflow',
    '-Werror=int-conversion',
    '-Werror=parentheses',
    '-Werror=undef',
    '-Werror=incompatible-pointer-types',
    '-Werror=misleading-indentation',
    '-Werror=missing-include-dirs',
    '-Wstrict-aliasing=2',
    '-Werror=unused-result',
  ]),
  language: 'c'
)

# Check for headers
cc.check_header('sys/mount.h')
cc.check_header('sys/capability.h')

# Check for libraries
fuse3_dep = dependency('fuse3', version : '>= 3.10.0', required : get_option('fuse'))
libcrypto_dep = dependency('libcrypto')

foreach required_function : ['getcwd', 'memset', 'mmap', 'munmap', 'strdup']
  if not cc.has_function(required_function)
    error('Required function ' + required_function + ' not found')
  endif
endforeach

# Flags for libcomposefs/hash.c
composefs_hash_cflags = ['-DUSE_OBSTACK=0', '-DTESTING=0', '-DUSE_DIFF_HASH=0']

# Configuration data for conditional compilation
conf = configuration_data()
conf.set('HAVE_FUSE3', fuse3_dep.found())
conf.set('HAVE_OPENSSL', libcrypto_dep.found())

if cc.check_header('endian.h')
  conf.set('HAVE_ENDIAN_H', '1')
endif
if cc.check_header('sys/endian.h')
  conf.set('HAVE_SYS_ENDIAN_H', 1)
endif
if cc.check_header('machine/endian.h')
  conf.set('HAVE_MACHINE_ENDIAN_H', 1)
endif
if cc.has_function('reallocarray')
  conf.set('HAVE_REALLOCARRAY', 1)
endif

mount_attr_idmap = '''
#include <sys/mount.h>
#include <linux/mount.h>
int foo = MOUNT_ATTR_IDMAP;
'''
if cc.compiles(mount_attr_idmap, name : 'MOUNT_ATTR_IDMAP in linux/mount.h')
  conf.set('HAVE_MOUNT_ATTR_IDMAP', 1)
endif

sys_mount_fsconfig_cmd_create = '''
#include <sys/mount.h>
int cmd = FSCONFIG_CMD_CREATE;
'''
if cc.compiles(sys_mount_fsconfig_cmd_create, name : 'new mount API in sys/mount.h (fsconfig)')
  conf.set('HAVE_FSCONFIG_CMD_CREATE_SYS_MOUNT_H', 1)
endif

linux_mount_fsconfig_cmd_create = '''
/* also make sure it doesn't conflict with <sys/mount.h> since it is always used.  */
#include <sys/mount.h>
#include <linux/mount.h>
int cmd = FSCONFIG_CMD_CREATE;
'''
if cc.compiles(linux_mount_fsconfig_cmd_create, name : 'new mount API in linux/mount.h (fsconfig)')
  conf.set('HAVE_FSCONFIG_CMD_CREATE_LINUX_MOUNT_H', 1)
endif

if cc.has_argument('-fvisibility=hidden')
  hidden_visibility_cflags = ['-fvisibility=hidden']
  conf.set('LCFS_EXTERN', '__attribute__((visibility("default"))) extern')
else
  hidden_visibility_cflags = ['']
  conf.set('LCFS_EXTERN', 'extern')
endif

config_h = configure_file(
  output : 'config.h',
  configuration : conf
)
config_inc = include_directories('.')

subdir('libcomposefs')
subdir('tools')
subdir('tests')

go_md2man = find_program('go-md2man', required : get_option('man'))
if go_md2man.found()
  subdir('man')
endif

# For use as a subproject
composefs_dep = declare_dependency(
  link_with : libcomposefs,
)
