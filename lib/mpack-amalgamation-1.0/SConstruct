import platform, os

simpletest = """
int main(int argc, char** argv) {
    // array dereference to test for the existence of
    // sanitizer libs when using -fsanitize (libubsan)
    return argv[argc - 1] == 0;
}
"""

def CheckFlags(context, cppflags, linkflags = [], message = None, testcode = simpletest, testformat = '.c'):
    if message == None:
        message = " ".join(cppflags + ((cppflags != linkflags) and linkflags or []))
    context.Message("Checking for " + message + " support... ")

    env.Prepend(CPPFLAGS = cppflags, LINKFLAGS = linkflags)
    result = context.TryLink(testcode, testformat)
    env.Replace(CPPFLAGS = env["CPPFLAGS"][len(cppflags):], LINKFLAGS = env["LINKFLAGS"][len(linkflags):])

    context.Result(result)
    return result

def AddFlagIfSupported(flag):
    if conf.CheckFlags([flag]):
        env.Append(CPPFLAGS = [flag])


# Common environment setup

env = Environment()
conf = Configure(env, custom_tests = {'CheckFlags': CheckFlags})

for x in os.environ.keys():
    if x in ["CC", "CXX"]:
        env[x] = os.environ[x]
    if x in ["PATH", "TRAVIS", "TERM"] or x.startswith("CLANG_") or x.startswith("CCC_"):
        env["ENV"][x] = os.environ[x]

env.Append(CPPFLAGS = [
    "-Wall", "-Wextra", "-Wpedantic", "-Werror",
    "-Wconversion", "-Wundef",
    "-Wshadow", "-Wcast-qual",
    "-Isrc", "-Itest",
    "-DMPACK_SCONS=1",
    "-DMPACK_HAS_CONFIG=1",
    "-g",
    ])
env.Append(LINKFLAGS = [
    "-g",
    ])

# Check if isnanf is a function

if conf.CheckFunc('isnanf'):
    conf.env.Append(CPPFLAGS= '-DMPACK_ISNANF_IS_FUNC')

# Additional warning flags are passed in SConscript based on the language (C/C++)

AddFlagIfSupported("-Wmissing-variable-declarations")
AddFlagIfSupported("-Wstrict-aliasing=1")
AddFlagIfSupported("-Wfloat-conversion")
AddFlagIfSupported("-Wmisleading-indentation")


# Optional flags used in various builds

defaultfeatures = [
    "-DMPACK_READER=1",
    "-DMPACK_WRITER=1",
    "-DMPACK_EXPECT=1",
    "-DMPACK_NODE=1",
]
allfeatures = defaultfeatures + [
    "-DMPACK_COMPATIBILITY=1",
    "-DMPACK_EXTENSIONS=1",
]

noioconfigs = [
    "-DMPACK_STDLIB=1",
    "-DMPACK_MALLOC=test_malloc",
    "-DMPACK_FREE=test_free",
]
allconfigs = noioconfigs + ["-DMPACK_STDIO=1"]

hasOg = conf.CheckFlags(["-Og"])
if hasOg:
    debugflags = ["-DDEBUG", "-Og"]
else:
    debugflags = ["-DDEBUG", "-O0"]
releaseflags = ["-O2"]

hasC11 = conf.CheckFlags(["-std=c11"])
if hasC11:
    cflags = ["-std=c11"]
else:
    cflags = ["-std=c99"]

gcovflags = []
if ARGUMENTS.get('gcov'):
    gcovflags = [
        "-DMPACK_GCOV=1",
        "--coverage",
        "-fno-inline",
        "-fno-inline-small-functions",
        "-fno-default-inline"
    ]

ltoflags = ["-O3", "-flto", "-fuse-linker-plugin", "-fno-fat-lto-objects"]

if conf.CheckFlags(["-Wstrict-aliasing=3"]):
    ltoflags.append("-Wstrict-aliasing=3")
elif conf.CheckFlags(["-Wstrict-aliasing=2"]):
    ltoflags.append("-Wstrict-aliasing=2")


# -lstdc++ is added in SConscript
cxxflags = ["-x", "c++"]


# Functions to add a variant build. One variant build will build and run the
# entire library and test suite in a given configuration.

def AddBuild(variant_dir, cppflags, linkflags = [], valgrind = True):
    env.SConscript("SConscript",
            variant_dir="build/" + variant_dir,
            src="../..",
            exports={
                'env': env,
                'CPPFLAGS': cppflags,
                'LINKFLAGS': linkflags,
                'valgrind': valgrind,
                },
            duplicate=0)

def AddBuilds(variant_dir, cppflags, linkflags = [], valgrind = True):
    AddBuild("debug-" + variant_dir, debugflags + cppflags, debugflags + linkflags, valgrind)
    if ARGUMENTS.get('all'):
        AddBuild("release-" + variant_dir, releaseflags + cppflags, releaseflags + linkflags, valgrind)


# The default build, everything in debug. This is also the build
# used for code coverage measurement and static analysis.
# Note that the default build does not use the default config; it enables
# MPACK_COMPATIBILITY and MPACK_EXTENSIONS.
AddBuild("debug", defaultfeatures + allconfigs + debugflags + cflags + gcovflags, gcovflags)


# Run "scons more=1" to run a handful of builds that are likely
# to reveal configuration errors.
if ARGUMENTS.get('more') or ARGUMENTS.get('all'):
    AddBuild("release", allfeatures + allconfigs + releaseflags + cflags)
    AddBuilds("default", defaultfeatures + allconfigs + cflags)
    AddBuilds("embed", defaultfeatures + cflags + ["-DMPACK_NO_BUILTINS=1"])
    AddBuilds("noio", allfeatures + noioconfigs + cflags)
    AddBuild("debug-size", ["-DMPACK_OPTIMIZE_FOR_SIZE=1"] + debugflags + allfeatures + allconfigs + cflags)
    if conf.CheckFlags(cxxflags + ["-std=c++11"], [], "-std=c++11"):
        AddBuilds("cxx11", allfeatures + allconfigs + cxxflags + ["-std=c++11"])


# Run "scons all=1" to run all builds. This is what the CI runs.
if ARGUMENTS.get('all'):

    # various release builds
    AddBuild("release-unopt", allfeatures + allconfigs + cflags + ["-O0"])
    AddBuild("release-fastmath", allfeatures + allconfigs + releaseflags + cflags + ["-ffast-math"])
    if conf.CheckFlags(ltoflags, ltoflags, "-flto"):
        AddBuild("release-lto", allfeatures + allconfigs + ltoflags + cflags, ltoflags)
    AddBuild("release-size", ["-Os", "-DMPACK_STRINGS=0"] + allfeatures + allconfigs + cflags)

    # feature subsets with default configuration
    AddBuilds("empty", allconfigs + cflags)
    AddBuilds("writer", ["-DMPACK_WRITER=1"] + allconfigs + cflags)
    AddBuilds("reader", ["-DMPACK_READER=1"] + allconfigs + cflags)
    AddBuilds("expect", ["-DMPACK_READER=1", "-DMPACK_EXPECT=1"] + allconfigs + cflags)
    AddBuilds("node", ["-DMPACK_NODE=1"] + allconfigs + cflags)
    AddBuilds("compatibility", ["-DMPACK_COMPATIBILITY=1"] + defaultfeatures + allconfigs + cflags)
    AddBuilds("extensions", ["-DMPACK_EXTENSIONS=1"] + defaultfeatures + allconfigs + cflags)

    # no i/o
    AddBuilds("noio-writer", ["-DMPACK_WRITER=1"] + noioconfigs + cflags)
    AddBuilds("noio-reader", ["-DMPACK_READER=1"] + noioconfigs + cflags)
    AddBuilds("noio-expect", ["-DMPACK_READER=1", "-DMPACK_EXPECT=1"] + noioconfigs + cflags)
    AddBuilds("noio-node", ["-DMPACK_NODE=1"] + noioconfigs + cflags)

    # embedded builds without libc (using builtins)
    AddBuilds("embed-writer", ["-DMPACK_WRITER=1"] + cflags)
    AddBuilds("embed-reader", ["-DMPACK_READER=1"] + cflags)
    AddBuilds("embed-expect", ["-DMPACK_READER=1", "-DMPACK_EXPECT=1"] + cflags)
    AddBuilds("embed-node", ["-DMPACK_NODE=1"] + cflags)
    AddBuilds("embed-full", allfeatures + cflags)

    # miscellaneous test builds
    AddBuilds("notrack", ["-DMPACK_NO_TRACKING=1"] + allfeatures + allconfigs + cflags)
    AddBuilds("realloc", allfeatures + allconfigs + debugflags + cflags + ["-DMPACK_REALLOC=test_realloc"])
    if hasOg:
        AddBuild("debug-O0", allfeatures + allconfigs + ["-DDEBUG", "-O0"] + cflags)

    # other language standards (C99, various C++ versions)
    # Note: We disable pedantic in C++98 due to our use of variadic macros,
    # trailing commas, ll format specifiers, and probably more. We technically
    # only support C++98 with those extensions.
    AddBuilds("cxx", allfeatures + allconfigs + cxxflags + ["-std=c++98", "-Wno-pedantic"])
    if hasC11:
        AddBuilds("c99", allfeatures + allconfigs + ["-std=c99"])
    if conf.CheckFlags(cxxflags + ["-std=c++14"], [], "-std=c++14"):
        AddBuilds("cxx14", allfeatures + allconfigs + cxxflags + ["-std=c++14"])
    if conf.CheckFlags(cxxflags + ["-std=gnu++11"], [], "-std=gnu++11"):
        AddBuilds("gnuxx11", allfeatures + allconfigs + cxxflags + ["-std=gnu++11"]) # Clang supports _Generic in gnu++11 mode

    # 32-bit builds
    if conf.CheckFlags(["-m32"], ["-m32"]):
        AddBuilds("32bit",     allfeatures + allconfigs + cflags + ["-m32"], ["-m32"])
        # As above, pedantic is disabled in C++98
        AddBuilds("cxx-32bit",  allfeatures + allconfigs + cxxflags + ["-std=c++98", "-Wno-pedantic", "-m32"], ["-m32"])
    if conf.CheckFlags(cxxflags + ["-std=c++11", "-m32"], ["-m32"], "-std=c++11"):
        AddBuilds("cxx11-32bit", allfeatures + allconfigs + cxxflags + ["-std=c++11", "-m32"], ["-m32"])

    # sanitize build tests
    sanitizers = {
        "stack-protector": ["-Wstack-protector", "-fstack-protector-all"],
        "undefined": ["-fsanitize=undefined"],
        # ASAN is temporarily disabled because the containerized Travis-CI
        # nodes no longer allow ptrace. We need to switch to our own docker
        # image anyway to get newer compilers so we'll add the ptrace cap to it
        # and re-enable this.
        #     https://github.com/google/sanitizers/issues/764
        #"address": ["-fsanitize=address"],
        "safestack": ["-fsanitize=safe-stack"],
    }
    # memory sanitizer isn't working on the version of Clang on Travis-CI's Trusty container right now
    if not ("CC" in os.environ and os.environ["CC"] == "clang" and "TRAVIS" in os.environ):
        sanitizers["memory"] = ["-fsanitize=memory"]
    for name, flags in sanitizers.items():
        if conf.CheckFlags(flags, flags):
            AddBuilds("sanitize-" + name, allfeatures + allconfigs + cflags + flags, flags, valgrind=False)
