import platform

Import('env', 'CPPFLAGS', 'LINKFLAGS', 'valgrind')

# we add the C/C++ specific flags here. we can't use CCFLAGS/CXXFLAGS
# because as far as SCons is concerned, they are all C files; we're
# passing -x c++ to force the language.
if "c++" in CPPFLAGS:
    CPPFLAGS += ["-Wmissing-declarations"]
    LINKFLAGS += ["-lstdc++"]
else:
    CPPFLAGS += ["-Wmissing-prototypes", "-Wc++-compat"]

srcs = env.Object(env.Glob('src/mpack/*.c') + env.Glob('test/test*.c'),
        CPPFLAGS=env['CPPFLAGS'] + CPPFLAGS)

prog = env.Program("mpack-test", srcs,
        LINKFLAGS=env['LINKFLAGS'] + LINKFLAGS)

# only some architectures are supported by valgrind. we don't check
# whether it's available though because we want to force mpack developers
# to install and use it if their architecture supports it.

if valgrind and platform.system() == "Linux" and platform.machine() in ["i386", "x86_64"]:
    valgrind = "valgrind --leak-check=full --error-exitcode=1 "
    valgrind += "--suppressions=tools/valgrind-suppressions "
    # travis version of valgrind is too old, doesn't support leak kinds
    if "TRAVIS" not in env["ENV"]:
        valgrind += "--show-leak-kinds=all --errors-for-leak-kinds=all "
else:
    valgrind = ""

env.Default(env.AlwaysBuild(env.Alias("test",
    [prog],
    valgrind + Dir('.').path + "/mpack-test")))
