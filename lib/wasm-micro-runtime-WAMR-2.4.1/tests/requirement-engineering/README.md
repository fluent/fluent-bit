# Requirement Engineering Tests

This directory contains requirement engineering test cases. Each directory corresponds to a test case suite for a requirement, comprised of test cases for sub-requirements.

## How to Run a Requirement Test

You can use the [all-in-one script](../wamr-test-suites/test_wamr.sh). Here are examples of its usage for testing the "gc-aot" requirement:

```shell
cd ../wamr-test-suites
# Run "gc-aot" requirement test on cases corresponding to sub-requirement ids 1, 2, 3
./test_wamr.sh -r "gc-aot" 1 2 3
# If no sub-requirement id is specified, it will test all cases for this requirement
./test_wamr.sh -r "gc-aot"
```

Or, use the helper scripts under a specific requirement directory. Refer to the help information of that helper script:

```shell
cd gc-aot
# Build first
./build.py

# Print help info
./run.py -h
# Test sub-requirement 1, and output to file output.csv
./run.py -o output 1
# Test all sub-requirements, and output to file output.csv
./run.py -o output
```

## How to Add a New Requirement Test

1. First, create a subdirectory, e.g., `new-requirement`, in this directory. Its name should reflect the requirement, like "gc-aot", and it should contain two helper scripts (`build.py` and `run.py`) to build and run tests under the `new-requirement` sub-directory.

   > If you need to use relative paths in your script, it's fine. The caller Python script [../wamr-test-suites/requirement-engineering-test-script/run_requirement.py](../wamr-test-suites/requirement-engineering-test-script/run_requirement.py) will use `os.chdir()` to change to that sub-directory.

   Start by writing and testing the helper script in that sub-directory, and add anything helpful (for instance, a main function and CLI argument parser).

2. After finishing the helper script, to let [the all-in-one script `test_wamr.sh`](../wamr-test-suites/test_wamr.sh) -> [../wamr-test-suites/requirement-engineering-test-script/run_requirement.py](../wamr-test-suites/requirement-engineering-test-script/run_requirement.py) invoke the new requirement test, you don't have to modify this script. Just ensure your helper script follows these guidelines:

   - The `build.py` should have a **build** function to build everything necessary for running the requirement tests. The signature should be:

     ```Python
     def build(verbose: bool) -> None:
       # your implementation
     ```

   - The `run.py` should have a **run** function to execute the test cases. The signature should be:

     ```Python
     def run(output_dir: str, subrequirement_ids: List[int]) -> Dict[int, Dict[Tuple[str, str], bool]]:
       # your implementation
     ```

     The result should be a dictionary with sub-requirement ids as keys and inner dictionaries as values. The inner dictionary should map tuples of (test_case, test_case_description) to a boolean indicating the test case's success.

     `run.py` should also contain a **SUBREQUIREMENT_DESCRIPTIONS** dictionary, describing each sub-requirement. For example:

     ```Python
     SUBREQUIREMENT_DESCRIPTIONS = {
      1: ("633", "Modify existing opcodes to conform to the semantics of the GC proposal when needed."),
      2: ("634", "Supporting new GC opcodes(semantics of GC MVP proposal spec)."),
      3: ("635", "Supporting new GC opcode(semantics of Binaryen GC spec)."),
     }
     ```

   > PS: If anything goes wrong during the build and run process, throw an exception and let it crash, so that it can be seen by the top-level caller (shell script).

3. Now you can test whether [the all-in-one script `test_wamr.sh`](../wamr-test-suites/test_wamr.sh) can correctly execute `new-requirement` and generate a report.

   ```shell
   ./test_wamr.sh -r "new-requirement"
   ```
