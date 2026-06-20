# BA Issues

For how to add a new test case, you should refer to following steps:

1. [Creating directories for new issue test cases](#helper-shell-script)
2. If the new issue test cases require new CMake build config of `warmc`/`iwasm` rather than existing ones, modify [build script](#warmc-and-iwasm-build-script) for new build config
3. Add [running configuration](#add-a-new-configuration-for-how-to-run-your-issue-test-case) for the new issue test cases
4. [Running tests and check test results](#running-test-cases-and-getting-results)

## helper shell script

`helper.sh` is to help you quickly create corresponding directory for test cases and unzip them if they are in zip file. It's helpful if you want to add many cases all together.

```shell
# helper scripts will create issues/issue-xxx where xxx is from 2944 to 2966
./helper.sh 2944 2966
# helper scripts will create issues/issue-2999
./helper.sh 2999
# helper scripts will extract any zip files under issues/issue-xxx where xxx is from 2944 to 2966
./helper.sh -x 2944 2966
```

## `warmc` and `iwasm` build script

To build wamrc and iwasm(this could take a while for we are building multiple version of iwasm with different CMake cache variable configurations)

```shell
./build_wamr.sh
```

Inside the file, if you want to add a new for you case, you can append a new build command to this file.

```shell
# format: build_iwasm "CMake cache variable configurations" "runtime name"
build_iwasm "-DWAMR_BUILD_LIBC_WASI=0 -DWAMR_BUILD_LIBC_BUILTIN=1 -DWAMR_BUILD_REF_TYPES=1 -DWAMR_BUILD_BULK_MEMORY=1 -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_FAST_JIT=1" "multi-tier-wasi-disabled"
```

Above line will compile a `iwasm-multi-tier-wasi-disabled` runtime under directory build, so you can indicate use it in your running config entry in Json.

> PS: if you add some

## Add a new configuration for how to run your issue test case

In `running_config.json`, add new entry for your issue test case

### Here is a simply running configuration that only uses `iwasm`

```Json
{
    "deprecated": false,
    "ids": [
        2955
    ],
    "runtime": "iwasm-default-wasi-disabled",
    "file": "iwasm_fast_interp_unexpected_value.wasm",
    "mode": "fast-interp",
    "options": " --heap-size=0 -f to_test",
    "argument": "",
    "expected return": {
        "ret code": 0,
        "stdout content": "0x44e5d17eb93a0ce:i64",
        "description": "expected output 0x44e5d17eb93a0ce:i64"
    }
}
```

Maybe some test cases can shared a running config(for example, they all come from a fuzz reporting issues). When it comes to that, you can simply add their ids all together. And use the wildcard for
matching file names.

```JSon
{
    "deprecated": false,
    "ids": [
        2966,
        2964,
        2963,
        2962
    ],
    "runtime": "iwasm-multi-tier-wasi-disabled",
    "file": "*.wasm",
    "mode": "fast-jit",
    "options": " --heap-size=0 -f to_test",
    "argument": "",
    "expected return": {
        "ret code": 0,
        "stdout content": "0x0:i32",
        "description": "expected output 0x0:i32"
    }
}
```

### Here is a simply running configuration that uses only `wamrc`

TODO: this is only a dummy config example, changes to actual test case configuration

```JSon
{
    "deprecated": false,
    "ids": [
        2956
    ],
    "compile_options": {
        "compiler": "wamrc", 
        "only compile": true, 
        "in file": "*.wasm", 
        "out file": "out.aot", 
        "options": "--target=x86_64",
        "expected return": {
            "ret code": 0,
            "stdout content": "",
            "description": ""
        }
    }
}
```

### Here is a simply running configuration that uses both `wamrc` and `iwasm`

TODO: this is only a dummy config example, changes to actual test case configuration

```JSon
{
    "deprecated": false,
    "ids": [
        2956
    ],
    "compile_options": {
        "compiler": "wamrc", 
        "only compile": false, 
        "in file": "*.wasm", 
        "out file": "out.aot", 
        "options": "--target=x86_64",
        "expected return": {
            "ret code": 0,
            "stdout content": "",
            "description": ""
        }
    },
    "runtime": "iwasm-multi-tier-wasi-disabled",
    "file": "out.aot",
    "mode": "aot",
    "options": " --heap-size=0 -f to_test",
    "argument": "",
    "expected return": {
        "ret code": 0,
        "stdout content": "0x0:i32",
        "description": "expected output 0x0:i32"
    }
}
```

### For deprecated issue test cases

Due to the spec changes, some cases may be deprecated in the future. When the running result is not as expected and after making sure it's not the bug in WAMR but the test cases should be deprecated(maybe using wasm-validate or some other tool). They should be moved into directory `issues-deprecated.` And simply set the `"deprecated": true,` in their corresponding running configuration.

For example:

```JSon
{
    "deprecated": true,
    "ids": [
        47,
        48,
        49,
        50,
        51,
        52,
        53,
        54,
        55,
        56,
        57,
        58,
        59,
        60,
        61,
        62,
        63,
        64,
        65,
        66,
        67,
        68,
        69,
        70,
        71,
        72,
        73,
        74,
        75,
        76,
        77,
        78,
        79,
        80,
        81,
        82,
        83,
        84
    ],
    "runtime": "iwasm-default",
    "mode": "classic-interp",
    "file": "PoC.wasm",
    "argument": "",
    "expected return": {
        "ret code": 0,
        "stdout content": "",
        "description": "no segfault"
    }
}
```

## Running test cases and getting results

simply run `run.py`

```shell
./run.py
```

Specify a specific issue with option `--issues`/`-i`

```shell
./run.py --issues 2833         # test 1 issue #2833
./run.py -i 2833,2834,2835     # test 3 issues #2833 #2834 #2835
```

If everything went well, you should see similarly output in your command line output

```shell
==== Test results ====
   Total: 22
  Passed: 22
  Failed: 0
  Left issues in folder: no more
  Cases in JSON but not found in folder: no more
```

If you add the test case under directory `issues` but forget to add the running config in json file, the output can be something like

```shell
==== Test results ====
   Total: 21
  Passed: 21
  Failed: 0
  missed: 0
  Left issues in folder: #3022
  Cases in JSON but not found in folder: no more
```

If you add the test case in `running_config.json` but used the wrong id or forget to add the test case under directory `issues`, the output can be someting like

```shell
==== Test results ====
   Total: 21
  Passed: 21
  Failed: 0
  missed: 0
  Left issues in folder: #2855
  Cases in JSON but not found in folder: #12345
```

If some test case are failing, then it will be something like

```shell
==== Test results ====
   Total: 22
  Passed: 21
  Failed: 1
  Left issues in folder: no more
  Cases in JSON but not found in folder: no more
```

And a log file named `issues_tests.log` will be generated and inside it will display the details of the failing cases, for example:

```dummy
=======================================================
Failing issue id: 2945.
run with command_lists: ['./build/iwasm-default-wasi-disabled', '--heap-size=0', '-f', 'to_test', '/home/tl/TL/clion_projects/wamr-internal-test/tests/regression/ba-issues/issues/issue-2945/iwasm_fast_interp_moob_unhandled.wasm']
exit code (actual, expected) : (1, 0)
stdout (actual, expected) : ('Exception: out of bounds memory access', 'Exception: out of bounds memory access')
=======================================================
```

