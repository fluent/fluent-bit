# NOTE: Currently, this configuration file does not support VisualC++!
#       Your help is needed!

MRuby::Build.new do |conf|
  # load specific toolchain settings
  conf.toolchain

  # include the GEM box
  conf.gembox 'default'

  # C compiler settings
  conf.compilers.each do |cc|
    cc.flags << '-fPIC'
  end

  conf.archiver do |archiver|
    archiver.command = cc.command
    archiver.archive_options = '-shared -o %{outfile} %{objs}'
  end

  # file extensions
  conf.exts do |exts|
    exts.library = '.so'
  end

  # file separator
  # conf.file_separator = '/'

  # enable this if better compatibility with C++ is desired
  #conf.enable_cxx_exception

  # Turn on `enable_debug` for better debugging
  conf.enable_debug
  conf.enable_bintest
  conf.enable_test
end
