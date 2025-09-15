#!/usr/bin/env python3
import os
import sys
import re
import subprocess
import signal
curr_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(curr_dir)

# This test script accepts the same arguments as run-test.sh, and
# the same environment variables as well. Additionally, it reads the following
# environment variables and can run tests in batches and for a certain
# number of iterations, especially useful when running tests with valgrind or
# to debug infrequent errors.
#
# TESTS: A comma-separated list of test numbers or test names. In case
#        they're numeric there's no need to pad them with zeros. There can be
#        ranges of tests, open ranges and they're sorted and deduplicated.
#        If not set, it defaults to all tests in the current directory.
#        Example: TESTS=1,2,3-5,2-,11
#
# TESTS_BATCH_SIZE: The number of tests to run in each batch. If not set, it
#                   defaults to the number of tests in TESTS.
#
# TEST_ITERATIONS: The number of iterations to run the tests. If not set, it
#                  defaults to 1. It continues iterating only if there are no
#                  errors. When "-a" is set it stops after the first error
#                  in any batch, when it isn't set it stops after the
#                  first error in any iteration.

# Max number of tests
max_automatic_tests = 1000
# Higher test number
max_test = 0
tests = set()
for f in os.listdir(curr_dir):
    m = re.match(r'^(\d{4}).*\.c$', f)
    if m:
        test_num = int(m.group(1))
        if test_num < max_automatic_tests:
            tests.add(test_num)
max_test = max(tests)
# Tests batch size, defaults to len(TESTS).
batch_size = os.environ.get('TESTS_BATCH_SIZE', None)
if batch_size and batch_size.isnumeric():
    batch_size = int(batch_size)

# Number of iterations for each batch, it continues iterating only
# if there are no errors, even when "-a" isn't set
test_iterations = os.environ.get('TEST_ITERATIONS', "1")
test_iterations = test_iterations.isnumeric() and int(test_iterations) or 1


def valid_test_number(test_number):
    return test_number >= 0 and test_number <= max_test


def test_number_to_str(test_number):
    return str(test_number).rjust(4, '0')


def test_numbers_to_str(test_numbers):
    return list(map(test_number_to_str, test_numbers))


def extract_tests(tests):
    test_ranges = [test_range for test_range in tests.strip().split(',')
                   if len(test_range.strip()) > 0]
    all_tests = []
    for test_range in test_ranges:

        if '-' in test_range:
            # 13-15 or 13- or -13
            start, end = test_range.split('-')
            start, end = start.strip(), end.strip()

            if start.isnumeric() and end.isnumeric():
                start, end = int(start), int(end)
                if valid_test_number(start) and valid_test_number(
                        end) and start <= end:
                    all_tests.extend(
                        test_numbers_to_str(range(start, end + 1)))

            elif start.isnumeric() and end == '':
                start = int(start)
                if valid_test_number(start):
                    all_tests.extend(
                        test_numbers_to_str(range(start, max_test + 1)))
            elif start == '' and end.isnumeric():
                end = int(end)
                if valid_test_number(end):
                    all_tests.extend(
                        test_numbers_to_str(range(0, end + 1)))

        elif test_range.isnumeric():
            # 13 or 0013
            all_tests.append(test_number_to_str(test_range))
        else:
            # A specific test like 0045_subscribe_update_racks_mock
            all_tests.append(test_range)

    return list(sorted(set(all_tests)))


if 'TESTS' in os.environ:
    TESTS = extract_tests(os.environ['TESTS'])
else:
    TESTS = test_numbers_to_str(range(0, max_test + 1))

if batch_size is None:
    batch_size = len(TESTS)

args = sys.argv[1:]

exit_on_first_error = '-a' in args


def run_tests():
    first_error = None
    for i in range(test_iterations):
        for j in range(0, len(TESTS), batch_size):
            interrupted = False
            TESTS_BATCH = ','.join(TESTS[j:j + batch_size])
            print(f"Running tests: {TESTS_BATCH}, iteration: {i + 1}",
                  file=sys.stderr)
            p = subprocess.Popen(['./run-test.sh', '-D'] + args,
                                 env={**os.environ, 'TESTS': TESTS_BATCH},
                                 start_new_session=True)
            try:
                p.communicate()
                if p.returncode != 0 and first_error is None:
                    first_error = p.returncode
                    if exit_on_first_error:
                        return first_error
            except BaseException:
                first_error = 1
                interrupted = True
                return first_error
            finally:
                if interrupted:
                    print('Terminating process group...', file=sys.stderr)
                    os.killpg(p.pid, signal.SIGTERM)
                    try:
                        p.wait(10)
                    except subprocess.TimeoutExpired:
                        os.killpg(p.pid, signal.SIGKILL)
                        p.wait(10)
        if first_error is not None:
            # Stop running more iterations if there was an error
            return first_error
    return first_error


first_error = run_tests()
print('End of run-test-batches', file=sys.stderr)
if first_error:
    sys.exit(first_error)
