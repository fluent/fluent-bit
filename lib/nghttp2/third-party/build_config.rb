def config(conf)
  toolchain :clang if ENV['MRUBY_CC'].include? "clang"
  toolchain :gcc if ENV['MRUBY_CC'].include? "gcc"

  conf.cc.command = ENV['MRUBY_CC']
  conf.cxx.command = ENV['MRUBY_CXX']

  if ENV['MRUBY_LD']
    conf.linker.command = ENV['MRUBY_LD']
  end
  if ENV['MRUBY_AR']
    conf.archiver.command = ENV['MRUBY_AR']
  end

  # C++ project needs this.  Without this, mruby exception does not
  # properly destroy C++ object allocated on stack.
  conf.enable_cxx_exception

  conf.build_dir = ENV['BUILD_DIR']

  # include the default GEMs
  conf.gembox 'default'
  conf.gem :core => 'mruby-eval'
end

if ENV['BUILD'] == ENV['HOST'] then
  MRuby::Build.new do |conf|
    config(conf)
  end
else
  MRuby::CrossBuild.new(ENV['HOST']) do |conf|
    config(conf)
  end
end
