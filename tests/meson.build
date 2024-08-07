test_assets_small = [
  'config.dump.gz',
  'config-with-hard-link.dump.gz',
  'special.dump',
  'special_v1.dump',
]

test_assets_small_extra = [
  'special.dump.version',
  'special_v1.dump.version',
]

test_assets_should_fail = [
  'should-fail-long-link.dump'
]

test_assets = test_assets_small + [
  'cs9-x86_64-developer.dump.gz',
  'cs9-x86_64-minimal.dump.gz',
  'f36-x86_64-silverblue.dump.gz',
]

extra_dist = [
  'gendir',
  'dumpdir',
  'test-lib.sh',
  'test-units.sh',
  'test-random-fuse.sh',
  'test-checksums.sh',
  'test-should-fail.sh',
  'integration.sh',
]

foreach asset : test_assets_should_fail
  extra_dist += ['assets/' + asset]
endforeach
foreach asset : test_assets_small_extra
  extra_dist += ['assets/' + asset]
endforeach
foreach asset : test_assets_small
  extra_dist += ['assets/' + asset, 'assets/' + asset + '.sha256']
endforeach

tools_dir = meson.current_build_dir() / '../tools'

test('check-units', find_program('test-units.sh'), args : [tools_dir])
test('check-checksums', find_program('test-checksums.sh'), args : [tools_dir, meson.current_source_dir() / 'assets', ' '.join(test_assets)])
test('check-random-fuse', find_program('test-random-fuse.sh'), args : [tools_dir], timeout : 300)

# support running the tests under valgrind using 'meson test -C build --setup=valgrind'
valgrind = find_program('valgrind', required : false)
if valgrind.found()
  add_test_setup('valgrind',
    exe_wrapper : [
      valgrind,
      '--quiet',
      '--leak-check=yes',
      '--error-exitcode=42',
    ],
    timeout_multiplier : 10,
  )
endif
