# Cross Compiling configuration for MS-DOS
#
# Requires DJGPP cross-compiler, see
# https://github.com/andrewwutw/build-djgpp/releases

MRuby::CrossBuild.new("i586-pc-msdosdjgpp") do |conf|
  toolchain :gcc

  # If DJGPP is not in the PATH, set this to the bin directory
  DJGPP_PATH = nil

  GCC = 'i586-pc-msdosdjgpp-gcc'
  GXX = 'i586-pc-msdosdjgpp-g++'
  AR  = 'i586-pc-msdosdjgpp-ar'

  conf.cc do |cc|
    cc.command = DJGPP_PATH ? File.join(DJGPP_PATH, GCC) : GCC
    cc.defines << 'MRB_WITHOUT_IO_PREAD_PWRITE'
    cc.defines << 'MRB_UTF8_STRING'
  end

  conf.cxx do |cxx|
    cxx.command = DJGPP_PATH ? File.join(DJGPP_PATH, GXX) : GXX
    cxx.defines << 'MRB_WITHOUT_IO_PREAD_PWRITE'
    cxx.defines << 'MRB_UTF8_STRING'
  end

  conf.linker do |linker|
    linker.command = DJGPP_PATH ? File.join(DJGPP_PATH, GXX) : GXX
    linker.libraries = %w(m)
  end

  conf.archiver do |archiver|
    archiver.command = DJGPP_PATH ? File.join(DJGPP_PATH, AR) : AR
  end

  # All provided gems that can be reasonably made to compile:
  # default.gembox, minus mruby-socket and replacing mruby-cmath with mruby-cmath-alt
  conf.gembox "stdlib"
  conf.gembox "stdlib-ext"

  conf.gem :core => 'mruby-io'              # stdlib-io.gembox <- default.gembox
# No socket support in DJGPP
# conf.gem :core => 'mruby-socket'          # stdlib-io.gembox <- default.gembox
  conf.gem :core => 'mruby-print'           # stdlib-io.gembox <- default.gembox
  conf.gem :core => 'mruby-errno'           # stdlib-io.gembox <- default.gembox
  conf.gem :core => 'mruby-dir'             # stdlib-io.gembox <- default.gembox

  conf.gem :core => 'mruby-bigint'          # math.gembox <- default.gembox
  conf.gem :core => 'mruby-complex'         # math.gembox <- default.gembox
  conf.gem :core => 'mruby-math'            # math.gembox <- default.gembox
  conf.gem :core => 'mruby-rational'        # math.gembox <- default.gembox
  # Alternative implementation of cmath, not requiring <complex.h>
# conf.gem :github => 'chasonr/mruby-cmath-alt' # math.gembox <- default.gembox

  conf.gembox "metaprog"

  conf.gem :core => 'mruby-bin-mrbc'        # default.gembox
  conf.gem :core => 'mruby-bin-debugger'    # default.gembox
  conf.gem :core => 'mruby-bin-mirb'        # default.gembox
  conf.gem :core => 'mruby-bin-mruby'       # default.gembox
  conf.gem :core => 'mruby-bin-strip'       # default.gembox
  conf.gem :core => 'mruby-bin-config'      # default.gembox

  # Other compilable gems
  conf.gem :core => 'mruby-binding'
  conf.gem :core => 'mruby-catch'
  conf.gem :core => 'mruby-enum-chain'
  conf.gem :core => 'mruby-error'
  conf.gem :core => 'mruby-exit'
  conf.gem :core => 'mruby-os-memsize'
  conf.gem :core => 'mruby-proc-binding'
  conf.gem :core => 'mruby-sleep'

  # For Onigmo regular expression support
  conf.gem :github => 'mattn/mruby-onig-regexp'
end
