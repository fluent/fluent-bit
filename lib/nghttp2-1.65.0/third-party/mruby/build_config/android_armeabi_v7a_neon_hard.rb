# Requires Android NDK r13 or later.
MRuby::CrossBuild.new('android-armeabi-v7a-neon-hard') do |conf|
  params = {
    :arch => 'armeabi-v7a',
    :mfpu => 'neon',
    :mfloat_abi => 'hard',
    :sdk_version => 33,
    :toolchain => :clang
  }
  toolchain :android, params

  conf.gembox 'default'
end
