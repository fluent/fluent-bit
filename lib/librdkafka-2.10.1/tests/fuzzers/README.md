# Fuzzing
librdkafka supports fuzzing by way of Libfuzzer and OSS-Fuzz. This is ongoing work.

## Launching the fuzzers
The easiest way to launch the fuzzers are to go through OSS-Fuzz. The only prerequisite to this is having Docker installed.

With Docker installed, the following commands will build and run the fuzzers in this directory:

```
git clone https://github.com/google/oss-fuzz
cd oss-fuzz
python3 infra/helper.py build_image librdkafka
python3 infra/helper.py build_fuzzers librdkafka
python3 infra/helper.py run_fuzzer librdkafka FUZZ_NAME
```
where FUZZ_NAME references the name of the fuzzer. Currently the only fuzzer we have is fuzz_regex

Notice that the OSS-Fuzz `helper.py` script above will create a Docker image in which the code of librdkafka will be built. As such, depending on how you installed Docker, you may be asked to have root access (i.e. run with `sudo`).


## Running a single reproducer

Download the reproducer file from the OSS-Fuzz issue tracker, then build
the failed test case by running `make` in this directory, and then
run the test case and pass it the reproducer files, e.g:

    $ make
    $ ./fuzz_regex ~/Downloads/clusterfuzz-testcase-...

**Note:** Some test cases, such as fuzz_regex, requires specific librdkafka
          build configuration. See the test case source for details.
