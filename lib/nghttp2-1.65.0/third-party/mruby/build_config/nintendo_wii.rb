# Cross Compiling configuration for the Nintendo Wii
# This configuration requires devkitPPC
# https://devkitpro.org/wiki/Getting_Started
#
#
MRuby::CrossBuild.new("wii") do |conf|
  toolchain :gcc

  DEVKITPRO_PATH = "/opt/devkitpro"
  BIN_PATH = "#{DEVKITPRO_PATH}/devkitPPC/bin"

  # C compiler
  conf.cc do |cc|
    cc.command = "#{BIN_PATH}/powerpc-eabi-gcc"
    cc.compile_options = %(%{flags} -o "%{outfile}" -c "%{infile}")
  end

  # C++ compiler
  conf.cxx do |cxx|
    cxx.command = "#{BIN_PATH}/powerpc-eabi-g++"
    cxx.include_paths = conf.cc.include_paths.dup
    cxx.flags = conf.cc.flags.dup
    cxx.defines = conf.cc.defines.dup
    cxx.compile_options = conf.cc.compile_options.dup
  end

  # Linker
  conf.linker do |linker|
    linker.command = "#{BIN_PATH}/powerpc-eabi-gcc"
  end

  # No executables
  conf.bins = []

  # Do not build executable test
  conf.build_mrbtest_lib_only

  # Disable C++ exception
  conf.disable_cxx_exception

  # All current core gems with ones with build issues commented out
  conf.gem 'mrbgems/mruby-array-ext/'
  conf.gem 'mrbgems/mruby-bigint/'
  conf.gem 'mrbgems/mruby-bin-config/'
  conf.gem 'mrbgems/mruby-bin-debugger/'
  conf.gem 'mrbgems/mruby-bin-mirb/'
  conf.gem 'mrbgems/mruby-bin-mrbc/'
  conf.gem 'mrbgems/mruby-bin-mruby/'
  conf.gem 'mrbgems/mruby-bin-strip/'
  conf.gem 'mrbgems/mruby-binding/'
  conf.gem 'mrbgems/mruby-catch/'
  conf.gem 'mrbgems/mruby-class-ext/'
  conf.gem 'mrbgems/mruby-cmath/'
  conf.gem 'mrbgems/mruby-compar-ext/'
  conf.gem 'mrbgems/mruby-compiler/'
  conf.gem 'mrbgems/mruby-complex/'
  conf.gem 'mrbgems/mruby-data/'
  #conf.gem 'mrbgems/mruby-dir/'
  conf.gem 'mrbgems/mruby-enum-chain/'
  conf.gem 'mrbgems/mruby-enum-ext/'
  conf.gem 'mrbgems/mruby-enum-lazy/'
  conf.gem 'mrbgems/mruby-enumerator/'
  conf.gem 'mrbgems/mruby-errno/'
  conf.gem 'mrbgems/mruby-error/'
  conf.gem 'mrbgems/mruby-eval/'
  conf.gem 'mrbgems/mruby-exit/'
  conf.gem 'mrbgems/mruby-fiber/'
  conf.gem 'mrbgems/mruby-hash-ext/'
  #conf.gem 'mrbgems/mruby-io/'
  conf.gem 'mrbgems/mruby-kernel-ext/'
  conf.gem 'mrbgems/mruby-math/'
  conf.gem 'mrbgems/mruby-metaprog/'
  conf.gem 'mrbgems/mruby-method/'
  conf.gem 'mrbgems/mruby-numeric-ext/'
  conf.gem 'mrbgems/mruby-object-ext/'
  conf.gem 'mrbgems/mruby-objectspace/'
  conf.gem 'mrbgems/mruby-os-memsize/'
  conf.gem 'mrbgems/mruby-pack/'
  conf.gem 'mrbgems/mruby-print/'
  conf.gem 'mrbgems/mruby-proc-binding/'
  conf.gem 'mrbgems/mruby-proc-ext/'
  conf.gem 'mrbgems/mruby-random/'
  conf.gem 'mrbgems/mruby-range-ext/'
  conf.gem 'mrbgems/mruby-rational/'
  conf.gem 'mrbgems/mruby-set/'
  conf.gem 'mrbgems/mruby-sleep/'
  #conf.gem 'mrbgems/mruby-socket/'
  conf.gem 'mrbgems/mruby-sprintf/'
  conf.gem 'mrbgems/mruby-string-ext/'
  conf.gem 'mrbgems/mruby-struct/'
  conf.gem 'mrbgems/mruby-symbol-ext/'
  conf.gem 'mrbgems/mruby-test-inline-struct/'
  #conf.gem 'mrbgems/mruby-test/'
  conf.gem 'mrbgems/mruby-time/'
  conf.gem 'mrbgems/mruby-toplevel-ext/'
end
