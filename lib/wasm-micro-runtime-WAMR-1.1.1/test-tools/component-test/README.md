# Component Test

The purpose of this test suite is to verify the basic components of WAMR work well in combination. It is highly recommended to run pass all suites before each commitment.

Prerequisites
==============
- clang is available to build wasm application.
- python is installed to run test script.


Run the test
=============
```
start.py [-h] [-s SUITE_ID [SUITE_ID ...]] [-t CASE_ID [CASE_ID ...]]
              [-n REPEAT_TIME] [--shuffle_all]
              [--cases_list CASES_LIST_FILE_PATH] [--skip_proc]
              [-b BINARIES] [-d] [--rebuild]
```
It builds out the simple project binary including WAMR runtime binary ```simple``` and the testing tool ```host_tool``` before running the test suites.

Test output is like:
```
Test Execution Summary:
        Success:              8
        Cases fails:          0
        Setup fails:          0
        Case load fails:      0


------------------------------------------------------------
The run folder is [run-03-23-16-29]
that's all. bye
kill to quit..
Killed
```

The detailed report and log is generated in ```run``` folder. The binaries copy is also put in that folder.

Usage samples
==============

Run default test suite:
</br>
```python start.py```

Rebuild all test apps and then run default test suite:
</br>
```python start.py --rebuild```

Run a specified test suite:
</br>
```python start.py -s 01-life-cycle```

Run a specified test case:
</br>
```python start.py -t 01-install```