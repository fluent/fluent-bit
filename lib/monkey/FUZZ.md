# Fuzz Monkey

## Prepare and Build

Set the compiler path:

```
$ export CC=PATH/TO/honggfuzz/hfuzz_cc/hfuzz-clang
```

Build Monkey Fuzz tool with the following options:

```
$ cd build/
$ cmake -DMK_LOCAL=On -DMK_DEBUG=On \
        -DMK_LIB_ONLY=On -DMK_SYSTEM_MALLOC=On \
        -DMK_FUZZ_MODE=On ../
$ make
```

the build process will generate two executables:

- mk_fuzz_me: to be used with honggfuzz for the Fuzzing process
- mk_check: used to validate a crash/fix

## Run HonggFuzz with mk-fuzz-me

Fuzz Monkey using Apache corpus and wordlist:

```
$ cd /path/to/honggfuzz/examples/apache-httpd/
$ honggfuzz -Q --logfile out.log -f corpus_http1 -w ./httpd.wordlist -- /path/to/mk-fuzz-me
```
