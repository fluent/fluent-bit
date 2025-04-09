# Cross Compiling configuration for the Sega Dreamcast
# https://dreamcast.wiki/Using_Ruby_for_Sega_Dreamcast_development
#
# Requires KallistiOS (KOS)
# http://gamedev.allusion.net/softprj/kos/
#
# This configuration has been improved to be used as KallistiOS Port (kos-ports)
# Updated: 2023-12-24
#
# Tested on GNU/Linux, macOS and Windows (MinGW-w64/MSYS2, Cygwin, DreamSDK)
# DreamSDK is based on MinGW/MSYS: https://dreamsdk.org/
#
# Install mruby for Sega Dreamcast using the "mruby" kos-port.
#
MRuby::CrossBuild.new("dreamcast") do |conf|
  toolchain :gcc

  # Getting critical environment variables
  KOS_BASE = ENV["KOS_BASE"]
  KOS_CC_BASE = ENV["KOS_CC_BASE"]

  if (KOS_BASE.nil? || KOS_BASE.empty? || KOS_CC_BASE.nil? || KOS_CC_BASE.empty?)
    raise "Error: KallistiOS is required; KOS_BASE/KOS_CC_BASE needs to be declared; Stop."
  end

  # C compiler
  # All flags and settings below were extracted from KallistiOS environment files
  conf.cc do |cc|
    cc.command = "#{KOS_CC_BASE}/bin/sh-elf-gcc"
    cc.include_paths << ["#{KOS_BASE}/include", "#{KOS_BASE}/kernel/arch/dreamcast/include", "#{KOS_BASE}/addons/include", "#{KOS_BASE}/../kos-ports/include"]
    cc.flags << ["-O2", "-fomit-frame-pointer", "-fno-builtin", "-ml", "-m4-single-only", "-ffunction-sections", "-fdata-sections", "-matomic-model=soft-imask", "-ftls-model=local-exec", "-Wall", "-g"]
    cc.compile_options = %Q[%{flags} -o "%{outfile}" -c "%{infile}"]
    cc.defines << %w(_arch_dreamcast)
    cc.defines << %w(_arch_sub_pristine)
  end

  # C++ compiler
  conf.cxx do |cxx|
    cxx.command = conf.cc.command.dup
    cxx.include_paths = conf.cc.include_paths.dup
    cxx.flags = conf.cc.flags.dup
    cxx.flags << %w(-fno-operator-names)
    cxx.defines = conf.cc.defines.dup
    cxx.compile_options = conf.cc.compile_options.dup
  end

  # Linker
  conf.linker do |linker|
    linker.command = "#{KOS_CC_BASE}/bin/sh-elf-gcc"
    linker.flags << ["-Wl,-Ttext=0x8c010000", "-Wl,--gc-sections", "-T#{KOS_BASE}/utils/ldscripts/shlelf.xc", "-nodefaultlibs", "-Wl,--start-group -lkallisti -lc -lgcc -Wl,--end-group"]
    linker.library_paths << ["#{KOS_BASE}/lib/dreamcast", "#{KOS_BASE}/addons/lib/dreamcast", "#{KOS_BASE}/../kos-ports/lib"]
  end

  # Archiver
  conf.archiver do |archiver|
    archiver.command = "#{KOS_CC_BASE}/bin/sh-elf-ar"
    archiver.archive_options = 'rcs "%{outfile}" %{objs}'
  end

  # No executables needed for KallistiOS
  conf.bins = []

  # Do not build test binaries
  conf.build_mrbtest_lib_only

  # Gemboxes
  conf.gembox "default-no-stdio"
  conf.gembox "stdlib-ext"
  conf.gembox "metaprog"

  # Additional Gems
  # Currently unsupported on KallistiOS: "mruby-io", "mruby-dir", "mruby-socket"
  conf.gem :core => "mruby-binding"
  conf.gem :core => "mruby-catch"
  conf.gem :core => "mruby-enum-chain"
  conf.gem :core => "mruby-errno"
  conf.gem :core => "mruby-error"
  conf.gem :core => "mruby-exit"
  conf.gem :core => "mruby-os-memsize"
  conf.gem :core => "mruby-print"
  conf.gem :core => "mruby-proc-binding"
  conf.gem :core => "mruby-sleep"
end
