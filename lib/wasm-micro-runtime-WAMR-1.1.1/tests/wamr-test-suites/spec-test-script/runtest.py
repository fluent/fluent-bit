#!/usr/bin/env python

from __future__ import print_function
import os, sys, re
from pickletools import long1
import argparse, time
import signal, atexit, tempfile, subprocess

from subprocess import Popen, STDOUT, PIPE
from select import select

# Pseudo-TTY and terminal manipulation
import pty, array, fcntl, termios

import shutil

import struct
import math
import traceback

try:
    long
    IS_PY_3 = False
except NameError:
    long = int
    IS_PY_3 = True

test_aot = False
# "x86_64", "i386", "aarch64", "armv7" or "thumbv7"
test_target = "x86_64"

debug_file = None
log_file = None

# to save the register module with self-define name
temp_file_repo = []

# get current work directory
current_work_directory = os.getcwd()
# set temporal file directory
temp_file_directory = os.path.join(current_work_directory,"tempfile")

def debug(data):
    if debug_file:
        debug_file.write(data)
        debug_file.flush()

def log(data, end='\n'):
    if log_file:
        log_file.write(data + end)
        log_file.flush()
    print(data, end=end)
    sys.stdout.flush()

# TODO: do we need to support '\n' too
import platform
if platform.system().find("CYGWIN_NT") >= 0:
    # TODO: this is weird, is this really right on Cygwin?
    sep = "\n\r\n"
else:
    sep = "\r\n"
rundir = None

class Runner():
    def __init__(self, args, no_pty=False):
        self.no_pty = no_pty

        # Cleanup child process on exit
        atexit.register(self.cleanup)

        self.process = None
        env = os.environ
        env['TERM'] = 'dumb'
        env['INPUTRC'] = '/dev/null'
        env['PERL_RL'] = 'false'
        if no_pty:
            self.process = Popen(args, bufsize=0,
                           stdin=PIPE, stdout=PIPE, stderr=STDOUT,
                           preexec_fn=os.setsid,
                           env=env)
            self.stdin = self.process.stdin
            self.stdout = self.process.stdout
        else:
            # Use tty to setup an interactive environment
            master, slave = pty.openpty()

            # Set terminal size large so that readline will not send
            # ANSI/VT escape codes when the lines are long.
            buf = array.array('h', [100, 200, 0, 0])
            fcntl.ioctl(master, termios.TIOCSWINSZ, buf, True)

            self.process = Popen(args, bufsize=0,
                           stdin=slave, stdout=slave, stderr=STDOUT,
                           preexec_fn=os.setsid,
                           env=env)
            # Now close slave so that we will get an exception from
            # read when the child exits early
            # http://stackoverflow.com/questions/11165521
            os.close(slave)
            self.stdin = os.fdopen(master, 'r+b', 0)
            self.stdout = self.stdin

        self.buf = ""

    def read_to_prompt(self, prompts, timeout):
        wait_until = time.time() + timeout
        while time.time() < wait_until:
            [outs,_,_] = select([self.stdout], [], [], 1)
            if self.stdout in outs:
                read_byte = self.stdout.read(1)
                if not read_byte:
                    # EOF on macOS ends up here.
                    break
                read_byte = read_byte.decode('utf-8') if IS_PY_3 else read_byte

                debug(read_byte)
                if self.no_pty:
                    self.buf += read_byte.replace('\n', '\r\n')
                else:
                    self.buf += read_byte
                self.buf = self.buf.replace('\r\r', '\r')

                # filter the prompts
                for prompt in prompts:
                    pattern = re.compile(prompt)
                    match = pattern.search(self.buf)
                    if match:
                        end = match.end()
                        buf = self.buf[0:end-len(prompt)]
                        self.buf = self.buf[end:]
                        return buf
        return None

    def writeline(self, str):
        str_to_write = str + '\n'
        str_to_write = bytes(
            str_to_write, 'utf-8') if IS_PY_3 else str_to_write

        self.stdin.write(str_to_write)

    def cleanup(self):
        if self.process:
            try:
                self.writeline("__exit__")
                time.sleep(.020)
                self.process.kill()
            except OSError:
                pass
            except IOError:
                pass
            self.process = None
            self.stdin.close()
            if self.stdin != self.stdout:
                self.stdout.close()
            self.stdin = None
            self.stdout = None
            sys.exc_clear()

def assert_prompt(runner, prompts, timeout, is_need_execute_result):
    # Wait for the initial prompt
    header = runner.read_to_prompt(prompts, timeout=timeout)
    if not header and is_need_execute_result:
        log(" ---------- will terminate cause the case needs result while there is none inside of buf. ----------")
        sys.exit(1)
    if not header == None:
        if header:
            log("Started with:\n%s" % header)
    else:
        log("Did not one of following prompt(s): %s" % repr(prompts))
        log("    Got      : %s" % repr(r.buf))
        sys.exit(1)


### WebAssembly specific

parser = argparse.ArgumentParser(
        description="Run a test file against a WebAssembly interpreter")
parser.add_argument('--wast2wasm', type=str,
        default=os.environ.get("WAST2WASM", "wast2wasm"),
        help="Path to wast2wasm program")
parser.add_argument('--interpreter', type=str,
        default=os.environ.get("IWASM_CMD", "iwasm"),
        help="Path to WebAssembly interpreter")
parser.add_argument('--aot-compiler', type=str,
        default=os.environ.get("WAMRC_CMD", "wamrc"),
        help="Path to WebAssembly AoT compiler")

parser.add_argument('--no_cleanup', action='store_true',
        help="Keep temporary *.wasm files")

parser.add_argument('--rundir',
        help="change to the directory before running tests")
parser.add_argument('--start-timeout', default=30, type=int,
        help="default timeout for initial prompt")
parser.add_argument('--test-timeout', default=20, type=int,
        help="default timeout for each individual test action")
parser.add_argument('--no-pty', action='store_true',
        help="Use direct pipes instead of pseudo-tty")
parser.add_argument('--log-file', type=str,
        help="Write messages to the named file in addition the screen")
parser.add_argument('--debug-file', type=str,
        help="Write all test interaction the named file")

parser.add_argument('test_file', type=argparse.FileType('r'),
        help="a WebAssembly *.wast test file")

parser.add_argument('--aot', action='store_true',
        help="Test with AOT")

parser.add_argument('--aot-target', type=str,
        default="x86_64",
        help="Set aot target")

parser.add_argument('--sgx', action='store_true',
        help="Test SGX")

parser.add_argument('--simd', default=False, action='store_true',
        help="Enable SIMD")

parser.add_argument('--xip', default=False, action='store_true',
        help="Enable XIP")

parser.add_argument('--multi-thread', default=False, action='store_true',
        help="Enable Multi-thread")

parser.add_argument('--verbose', default=False, action='store_true',
        help='show more logs')

# regex patterns of tests to skip
C_SKIP_TESTS = ()
PY_SKIP_TESTS = (
        # names.wast
        'invoke \"~!',
        # conversions.wast
        '18446742974197923840.0',
        '18446744073709549568.0',
        '9223372036854775808',
        'reinterpret_f.*nan',
        # endianness
        '.const 0x1.fff' )

def read_forms(string):
    forms = []
    form = ""
    depth = 0
    line = 0
    pos = 0
    while pos < len(string):
        # Keep track of line number
        if string[pos] == '\n': line += 1

        # Handle top-level elements
        if depth == 0:
            # Add top-level comments
            if string[pos:pos+2] == ";;":
                end = string.find("\n", pos)
                if end == -1: end == len(string)
                forms.append(string[pos:end])
                pos = end
                continue

            # TODO: handle nested multi-line comments
            if string[pos:pos+2] == "(;":
                # Skip multi-line comment
                end = string.find(";)", pos)
                if end == -1:
                    raise Exception("mismatch multiline comment on line %d: '%s'" % (
                        line, string[pos:pos+80]))
                pos = end+2
                continue

            # Ignore whitespace between top-level forms
            if string[pos] in (' ', '\n', '\t'):
                pos += 1
                continue

        # Read a top-level form
        if string[pos] == '(': depth += 1
        if string[pos] == ')': depth -= 1
        if depth == 0 and not form:
            raise Exception("garbage on line %d: '%s'" % (
                line, string[pos:pos+80]))
        form += string[pos]
        if depth == 0 and form:
            forms.append(form)
            form = ""
        pos += 1
    return forms

def get_module_exp_from_assert(string):
    depth = 0
    pos = 0
    module = ""
    exception = ""
    start_record = False
    result = []
    while pos < len(string):
        # record from the " (module "
        if string[pos:pos+7] == "(module":
            start_record = True
        if start_record:
            if string[pos] == '(' : depth += 1
            if string[pos] == ')' : depth -= 1
            module += string[pos]
            # if we get all (module ) .
            if depth == 0 and module:
                result.append(module)
                start_record = False
        # get expected exception
        if string[pos] == '"':
            end = string.find("\"", pos+1)
            if end != -1:
                end_rel = string.find("\"",end+1)
                if end_rel == -1:
                    result.append(string[pos+1:end])
        pos += 1
    return result

def string_to_unsigned(number_in_string, lane_type):
    if not lane_type in ['i8x16', 'i16x8', 'i32x4', 'i64x2']:
        raise Exception("invalid value {} and type {} and lane_type {}".format(number_in_string, type, lane_type))

    number = int(number_in_string, 16) if '0x' in number_in_string else int(number_in_string)

    if "i8x16" == lane_type:
        if number < 0:
            packed = struct.pack('b', number)
            number = struct.unpack('B', packed)[0]
    elif "i16x8" == lane_type:
        if number < 0:
            packed = struct.pack('h', number)
            number = struct.unpack('H', packed)[0]
    elif "i32x4" == lane_type:
        if number < 0:
            packed = struct.pack('i', number)
            number = struct.unpack('I', packed)[0]
    else: # "i64x2" == lane_type:
        if number < 0:
            packed = struct.pack('q', number)
            number = struct.unpack('Q', packed)[0]

    return number

def cast_v128_to_i64x2(numbers, type, lane_type):
    numbers = [n.replace("_", "") for n in numbers]

    if "i8x16" == lane_type:
        assert(16 == len(numbers)), "{} should like {}".format(numbers, lane_type)
        # str -> int
        numbers = [string_to_unsigned(n, lane_type) for n in numbers]
        # i8 -> i64
        packed = struct.pack(16 * "B", *numbers)
    elif "i16x8" == lane_type:
        assert(8 == len(numbers)), "{} should like {}".format(numbers, lane_type)
        # str -> int
        numbers = [string_to_unsigned(n, lane_type) for n in numbers]
        # i16 -> i64
        packed = struct.pack(8 * "H", *numbers)
    elif "i32x4" == lane_type:
        assert(4 == len(numbers)), "{} should like {}".format(numbers, lane_type)
        # str -> int
        numbers = [string_to_unsigned(n, lane_type) for n in numbers]
        # i32 -> i64
        packed = struct.pack(4 * "I", *numbers)
    elif "i64x2" == lane_type:
        assert(2 == len(numbers)), "{} should like {}".format(numbers, lane_type)
        # str -> int
        numbers = [string_to_unsigned(n, lane_type) for n in numbers]
        # i64 -> i64
        packed = struct.pack(2 * "Q", *numbers)
    elif "f32x4" == lane_type:
        assert(4 == len(numbers)), "{} should like {}".format(numbers, lane_type)
        # str -> int
        numbers = [parse_simple_const_w_type(n, "f32")[0] for n in numbers]
        # f32 -> i64
        packed = struct.pack(4 * "f", *numbers)
    elif "f64x2" == lane_type:
        assert(2 == len(numbers)), "{} should like {}".format(numbers, lane_type)
        # str -> int
        numbers = [parse_simple_const_w_type(n, "f64")[0] for n in numbers]
        # f64 -> i64
        packed = struct.pack(2 * "d", *numbers)
    else:
        raise Exception("invalid value {} and type {} and lane_type {}".format(numbers, type, lane_type))

    assert(packed)
    unpacked = struct.unpack("Q Q", packed)
    return unpacked, "[{} {}]:{}:v128".format(unpacked[0], unpacked[1], lane_type)


def parse_simple_const_w_type(number, type):
    number = number.replace('_', '')
    if type in ["i32", "i64"]:
        number = int(number, 16) if '0x' in number else int(number)
        return number, "0x{:x}:{}".format(number, type) \
                   if number >= 0 \
                   else "-0x{:x}:{}".format(0 - number, type)
    elif type in ["f32", "f64"]:
        if "nan:" in number:
            # TODO: how to handle this correctly
            if "nan:canonical" in number:
                return float.fromhex("0x200000"), "nan:{}".format(type)
            elif "nan:arithmetic" in number:
                return float.fromhex("-0x200000"), "nan:{}".format(type)
            else:
                return float('nan'), "nan:{}".format(type)
        else:
            number = float.fromhex(number) if '0x' in number else float(number)
            return number, "{:.7g}:{}".format(number, type)
    elif type == "ref.null":
        # hard coding
        return "extern", "extern:ref.null"
    elif type == "ref.extern":
        number = int(number, 16) if '0x' in number else int(number)
        return number, "0x{:x}:ref.extern".format(number)
    else:
        raise Exception("invalid value {} and type {}".format(number, type))

def parse_assertion_value(val):
    """
    Parse something like:
    "ref.null extern" in (assert_return (invoke "get-externref" (i32.const 0)) (ref.null extern))
    "ref.extern 1" in (assert_return (invoke "get-externref" (i32.const 1)) (ref.extern 1))
    "i32.const 0" in (assert_return (invoke "is_null-funcref" (i32.const 1)) (i32.const 0))

    in summary:
    type.const (sub-type) (val1 val2 val3 val4) ...
    type.const val
    ref.extern val
    ref.null ref_type
    """
    if not val:
        return None, ""

    splitted = re.split('\s+', val)
    splitted = [s for s in splitted if s]
    type = splitted[0].split(".")[0]
    lane_type = splitted[1] if len(splitted) > 2 else ""
    numbers = splitted[2:] if len(splitted) > 2 else splitted[1:]

    if type in ["i32", "i64", "f32", "f64"]:
        return parse_simple_const_w_type(numbers[0], type)
    elif type == "ref":
        # need to distinguish between "ref.null" and "ref.extern"
        return parse_simple_const_w_type(numbers[0], splitted[0])
    else:
        return cast_v128_to_i64x2(numbers, type, lane_type)

def int2uint32(i):
    return i & 0xffffffff

def int2int32(i):
    val = i & 0xffffffff
    if val & 0x80000000:
        return val - 0x100000000
    else:
        return val

def int2uint64(i):
    return i & 0xffffffffffffffff

def int2int64(i):
    val = i & 0xffffffffffffffff
    if val & 0x8000000000000000:
        return val - 0x10000000000000000
    else:
        return val


def num_repr(i):
    if isinstance(i, int) or isinstance(i, long):
        return re.sub("L$", "", hex(i))
    else:
        return "%.16g" % i

def hexpad16(i):
    return "0x%04x" % i

def hexpad24(i):
    return "0x%06x" % i

def hexpad32(i):
    return "0x%08x" % i

def hexpad64(i):
    return "0x%016x" % i

def invoke(r, args, cmd):
    r.writeline(cmd)

    return r.read_to_prompt(['\r\nwebassembly> ', '\nwebassembly> '],
                            timeout=args.test_timeout)

def vector_value_comparison(out, expected):
    """
    out likes "<number number>:v128"
    expected likes "[number number]:v128"
    """
    # print("vector value comparision {} vs {}".format(out, expected))

    out_val, out_type = out.split(':')
    # <number nubmer> => number number
    out_val = out_val[1:-1]

    expected_val, lane_type, expected_type = expected.split(':')
    # [number nubmer] => number number
    expected_val = expected_val[1:-1]

    assert("v128" == out_type), "out_type should be v128"
    assert("v128" == expected_type), "expected_type should be v128"

    if out_type != expected_type:
        return False

    if out_val == expected_val:
        return True

    out_val = out_val.split(" ")
    expected_val = expected_val.split(" ")

    # since i64x2
    out_packed = struct.pack("QQ", int(out_val[0], 16), int(out_val[1], 16))
    expected_packed = struct.pack("QQ",
        int(expected_val[0]) if not "0x" in expected_val[0] else int(expected_val[0], 16),
        int(expected_val[1]) if not "0x" in expected_val[1] else int(expected_val[1], 16))

    if lane_type in ["i8x16", "i16x8", "i32x4", "i64x2"]:
        return out_packed == expected_packed;
    else:
        assert(lane_type in ["f32x4", "f64x2"]), "unexpected lane_type"

        if "f32x4" == lane_type:
            out_unpacked = struct.unpack("ffff", out_packed)
            expected_unpacked = struct.unpack("ffff", expected_packed)
        else:
            out_unpacked = struct.unpack("dd", out_packed)
            expected_unpacked = struct.unpack("dd", expected_packed)

        out_is_nan = [math.isnan(o) for o in out_unpacked]
        expected_is_nan = [math.isnan(e) for e in expected_unpacked]
        if out_is_nan and expected_is_nan:
            return True;

        # print("compare {} and {}".format(out_unpacked, expected_unpacked))
        result = [o == e for o, e in zip(out_unpacked, expected_unpacked)]

        if not all(result):
            result = [
                "{:.7g}".format(o) == "{:.7g}".format(e)
                for o, e in zip(out_unpacked, expected_packed)
            ]

        return all(result)


def simple_value_comparison(out, expected):
    """
    compare out of simple types which may like val:i32, val:f64 and so on
    """
    if expected == "2.360523e+13:f32" and out == "2.360522e+13:f32":
        # one case in float_literals.wast, due to float precision of python
        return True

    if expected == "1.797693e+308:f64" and out == "inf:f64":
        # one case in float_misc.wast:
        # (assert_return (invoke "f64.add" (f64.const 0x1.fffffffffffffp+1023)
        #                                  (f64.const 0x1.fffffffffffffp+969))
        #                                  (f64.const 0x1.fffffffffffffp+1023))
        # the add result in x86_32 is inf
        return True

    out_val, out_type = out.split(':')
    expected_val, expected_type = expected.split(':')

    if not out_type == expected_type:
        return False

    out_val, _ = parse_simple_const_w_type(out_val, out_type)
    expected_val, _ = parse_simple_const_w_type(expected_val, expected_type)

    if out_val == expected_val \
        or (math.isnan(out_val) and math.isnan(expected_val)):
        return True

    if "i32" == expected_type:
        out_val_binary = struct.pack('I', out_val) if out_val > 0 \
                            else struct.pack('i', out_val)
        expected_val_binary = struct.pack('I', expected_val) \
                                if expected_val > 0 \
                                    else struct.pack('i', expected_val)
    elif "i64" == expected_type:
        out_val_binary = struct.pack('Q', out_val) if out_val > 0 \
                            else struct.pack('q', out_val)
        expected_val_binary = struct.pack('Q', expected_val) \
                                if expected_val > 0 \
                                    else struct.pack('q', expected_val)
    elif "f32" == expected_type:
        out_val_binary = struct.pack('f', out_val)
        expected_val_binary = struct.pack('f', expected_val)
    elif "f64" == expected_type:
        out_val_binary = struct.pack('d', out_val)
        expected_val_binary = struct.pack('d', expected_val)
    elif "ref.extern" == expected_type:
        out_val_binary = out_val
        expected_val_binary = expected_val
    else:
        assert(0), "unknown 'expected_type' {}".format(expected_type)

    if out_val_binary == expected_val_binary:
        return True

    if expected_type in ["f32", "f64"]:
        # compare with a lower precision
        out_str = "{:.7g}".format(out_val)
        expected_str = "{:.7g}".format(expected_val)
        if out_str == expected_str:
            return True

    return False

def value_comparison(out, expected):
    if out == expected:
        return True

    if not expected:
        return False

    assert(':' in out), "out should be in a form likes numbers:type, but {}".format(out)
    assert(':' in expected), "expected should be in a form likes numbers:type, but {}".format(expected)

    if 'v128' in out:
        return vector_value_comparison(out, expected)
    else:
        return simple_value_comparison(out, expected)

def is_result_match_expected(out, expected):
    # compare value instead of comparing strings of values
    return value_comparison(out, expected)

def test_assert(r, opts, mode, cmd, expected):
    log("Testing(%s) %s = %s" % (mode, cmd, expected))

    out = invoke(r, opts, cmd)
    outs = [''] + out.split('\n')[1:]
    out = outs[-1]

    if mode=='trap':
        o = re.sub('^Exception: ', '', out)
        e = re.sub('^Exception: ', '', expected)
        if o.find(e) >= 0 or e.find(o) >= 0:
            return True

    if mode=='exhaustion':
        o = re.sub('^Exception: ', '', out)
        expected = 'Exception: stack overflow'
        e = re.sub('^Exception: ', '', expected)
        if o.find(e) >= 0 or e.find(o) >= 0:
            return True

    ## 0x9:i32,-0x1:i32 -> ['0x9:i32', '-0x1:i32']
    expected_list = re.split(',', expected)
    out_list = re.split(',', out)
    if len(expected_list) != len(out_list):
        raise Exception("Failed:\n Results count incorrect:\n expected: '%s'\n  got: '%s'" % (expected, out))
    for i in range(len(expected_list)):
        if not is_result_match_expected(out_list[i], expected_list[i]):
            raise Exception("Failed:\n Result %d incorrect:\n expected: '%s'\n  got: '%s'" % (i, expected_list[i], out_list[i]))

    return True

def test_assert_return(r, opts, form):
    """
    m. to search a pattern like (assert_return (invoke function_name ... ) ...)
    n. to search a pattern like (assert_return (invoke $module_name function_name ... ) ...)
    """
    # params, return
    m = re.search('^\(assert_return\s+\(invoke\s+"((?:[^"]|\\\")*)"\s+(\(.*\))\s*\)\s*(\(.*\))\s*\)\s*$', form, re.S)
    # judge if assert_return cmd includes the module name
    n = re.search('^\(assert_return\s+\(invoke\s+\$((?:[^\s])*)\s+"((?:[^"]|\\\")*)"\s+(\(.*\))\s*\)\s*(\(.*\))\s*\)\s*$', form, re.S)

    # print("assert_return with {}".format(form))

    if not m:
        # no params, return
        m = re.search('^\(assert_return\s+\(invoke\s+"((?:[^"]|\\\")*)"\s*\)\s+()(\(.*\))\s*\)\s*$', form, re.S)
    if not m:
        # params, no return
        m = re.search('^\(assert_return\s+\(invoke\s+"([^"]*)"\s+(\(.*\))()\s*\)\s*\)\s*$', form, re.S)
    if not m:
        # no params, no return
        m = re.search('^\(assert_return\s+\(invoke\s+"([^"]*)"\s*()()\)\s*\)\s*$', form, re.S)
    if not m:
        # params, return
        if not n:
            # no params, return
            n = re.search('^\(assert_return\s+\(invoke\s+\$((?:[^\s])*)\s+"((?:[^"]|\\\")*)"\s*\)\s+()(\(.*\))\s*\)\s*$', form, re.S)
        if not n:
            # params, no return
            n = re.search('^\(assert_return\s+\(invoke\s+\$((?:[^\s])*)\s+"([^"]*)"\s+(\(.*\))()\s*\)\s*\)\s*$', form, re.S)
        if not n:
            # no params, no return
            n = re.search('^\(assert_return\s+\(invoke\s+\$((?:[^\s])*)\s+"([^"]*)"*()()\)\s*\)\s*$', form, re.S)
    if not m and not n:
        if re.search('^\(assert_return\s+\(get.*\).*\)$', form, re.S):
            log("ignoring assert_return get");
            return
        else:
            raise Exception("unparsed assert_return: '%s'" % form)
    if m and not n:
        func = m.group(1)
        if ' ' in func:
            func = func.replace(' ', '\\')

        if m.group(2) == '':
            args = []
        else:
            #args = [re.split(' +', v)[1].replace('_', "") for v in re.split("\)\s*\(", m.group(2)[1:-1])]
            # split arguments with ')spaces(', remove leading and tailing ) and (
            args_type_and_value = re.split(r'\)\s+\(', m.group(2)[1:-1])
            args_type_and_value = [s.replace('_', '') for s in args_type_and_value]
            # args are in two forms:
            # f32.const -0x1.000001fffffffffffp-50
            # v128.const i32x4 0 0 0 0
            args = []
            for arg in args_type_and_value:
                # remove leading and tailing spaces, it might confuse following assertions
                arg = arg.strip()
                splitted = re.split('\s+', arg)
                splitted = [s for s in splitted if s]

                if splitted[0] in ["i32.const", "i64.const"]:
                    assert(2 == len(splitted)), "{} should have two parts".format(splitted)
                    # in wast 01234 means 1234
                    # in c 0123 means 83 in oct
                    number, _ = parse_simple_const_w_type(splitted[1], splitted[0][:3])
                    args.append(str(number))
                elif splitted[0] in ["f32.const", "f64.const"]:
                    # let strtof or strtod handle original arguments
                    assert(2 == len(splitted)), "{} should have two parts".format(splitted)
                    args.append(splitted[1])
                elif "v128.const" == splitted[0]:
                    assert(len(splitted) > 2), "{} should have more than two parts".format(splitted)
                    numbers, _ = cast_v128_to_i64x2(splitted[2:], 'v128', splitted[1])

                    assert(len(numbers) == 2), "has to reform arguments into i64x2"
                    args.append("{}\{}".format(numbers[0], numbers[1]))
                elif "ref.null" == splitted[0]:
                    args.append("null")
                elif "ref.extern" == splitted[0]:
                    number, _ = parse_simple_const_w_type(splitted[1], splitted[0])
                    args.append(str(number))
                else:
                    assert(0), "an unkonwn parameter type"

        if m.group(3) == '':
            returns= []
        else:
            returns = re.split("\)\s*\(", m.group(3)[1:-1])
        # processed numbers in strings
        expected = [parse_assertion_value(v)[1] for v in returns]
        test_assert(r, opts, "return", "%s %s" % (func, " ".join(args)), ",".join(expected))
    elif not m and n:
        module = os.path.join(temp_file_directory,n.group(1))
        # assume the cmd is (assert_return(invoke $ABC "func")).
        # run the ABC.wasm firstly
        if test_aot:
            r = compile_wasm_to_aot(module+".wasm", module+".aot", True, opts, r)
            try:
                assert_prompt(r, ['Compile success'], opts.start_timeout, False)
            except:
                _, exc, _ = sys.exc_info()
                log("Run wamrc failed:\n  got: '%s'" % r.buf)
                sys.exit(1)
            r = run_wasm_with_repl(module+".wasm", module+".aot", opts, r)
        else:
            r = run_wasm_with_repl(module+".wasm", None, opts, r)
        # Wait for the initial prompt
        try:
            assert_prompt(r, ['webassembly> '], opts.start_timeout, False)
        except:
            _, exc, _ = sys.exc_info()
            raise Exception("Failed:\n  expected: '%s'\n  got: '%s'" % \
                            (repr(exc), r.buf))
        func = n.group(2)
        if ' ' in func:
            func = func.replace(' ', '\\')

        if n.group(3) == '':
            args=[]
        else:
            args = [re.split(' +', v)[1] for v in re.split("\)\s*\(", n.group(3)[1:-1])]

        # a workaround for "ref.null extern" and "ref.null func"
        args = [ arg.replace('extern', 'null').replace('func', 'null') for arg in args]

        _, expected = parse_assertion_value(n.group(4)[1:-1])
        test_assert(r, opts, "return", "%s %s" % (func, " ".join(args)), expected)

def test_assert_trap(r, opts, form):
    # params
    m = re.search('^\(assert_trap\s+\(invoke\s+"([^"]*)"\s+(\(.*\))\s*\)\s*"([^"]+)"\s*\)\s*$', form)
    # judge if assert_return cmd includes the module name
    n = re.search('^\(assert_trap\s+\(invoke\s+\$((?:[^\s])*)\s+"([^"]*)"\s+(\(.*\))\s*\)\s*"([^"]+)"\s*\)\s*$', form, re.S)
    if not m:
        # no params
        m = re.search('^\(assert_trap\s+\(invoke\s+"([^"]*)"\s*()\)\s*"([^"]+)"\s*\)\s*$', form)
    if not m:
        if not n:
            # no params
            n = re.search('^\(assert_trap\s+\(invoke\s+\$((?:[^\s])*)\s+"([^"]*)"\s*()\)\s*"([^"]+)"\s*\)\s*$', form, re.S)
    if not m and not n:
        raise Exception("unparsed assert_trap: '%s'" % form)

    if m and not n:
        func = m.group(1)
        if m.group(2) == '':
            args = []
        else:
            args = [re.split(' +', v)[1] for v in re.split("\)\s*\(", m.group(2)[1:-1])]

        # workaround for "ref.null extern"
        args = [ arg.replace('extern', 'null').replace('func', 'null') for arg in args]

        expected = "Exception: %s" % m.group(3)
        test_assert(r, opts, "trap", "%s %s" % (func, " ".join(args)), expected)

    elif not m and n:
        module = n.group(1)
        # will trigger the module named in assert_return(invoke $ABC).
        # run the ABC.wasm firstly
        if test_aot:
            r = compile_wasm_to_aot(module+".wasm", module+".aot", True, opts, r)
            try:
                assert_prompt(r, ['Compile success'], opts.start_timeout, False)
            except:
                _, exc, _ = sys.exc_info()
                log("Run wamrc failed:\n  got: '%s'" % r.buf)
                sys.exit(1)
            r = run_wasm_with_repl(module+".wasm", module+".aot", opts, r)
        else:
            r = run_wasm_with_repl(module+".wasm", None, opts, r)
        # Wait for the initial prompt
        try:
            assert_prompt(r, ['webassembly> '], opts.start_timeout, False)
        except:
            _, exc, _ = sys.exc_info()
            raise Exception("Failed:\n  expected: '%s'\n  got: '%s'" % \
                            (repr(exc), r.buf))

        func = n.group(2)
        if n.group(3) == '':
            args = []
        else:
            args = [re.split(' +', v)[1] for v in re.split("\)\s*\(", n.group(3)[1:-1])]
        expected = "Exception: %s" % n.group(4)
        test_assert(r, opts, "trap", "%s %s" % (func, " ".join(args)), expected)

def test_assert_exhaustion(r,opts,form):
    # params
    m = re.search('^\(assert_exhaustion\s+\(invoke\s+"([^"]*)"\s+(\(.*\))\s*\)\s*"([^"]+)"\s*\)\s*$', form)
    if not m:
        # no params
        m = re.search('^\(assert_exhaustion\s+\(invoke\s+"([^"]*)"\s*()\)\s*"([^"]+)"\s*\)\s*$', form)
    if not m:
        raise Exception("unparsed assert_exhaustion: '%s'" % form)
    func = m.group(1)
    if m.group(2) == '':
        args = []
    else:
        args = [re.split(' +', v)[1] for v in re.split("\)\s*\(", m.group(2)[1:-1])]
    expected = "Exception: %s\n" % m.group(3)
    test_assert(r, opts, "exhaustion", "%s %s" % (func, " ".join(args)), expected)

def do_invoke(r, opts, form):
    # params
    m = re.search('^\(invoke\s+"([^"]+)"\s+(\(.*\))\s*\)\s*$', form)
    if not m:
        # no params
        m = re.search('^\(invoke\s+"([^"]+)"\s*()\)\s*$', form)
    if not m:
        raise Exception("unparsed invoke: '%s'" % form)
    func = m.group(1)

    if ' ' in func:
        func = func.replace(' ', '\\')

    if m.group(2) == '':
        args = []
    else:
        args = [re.split(' +', v)[1] for v in re.split("\)\s*\(", m.group(2)[1:-1])]

    log("Invoking %s(%s)" % (
        func, ", ".join([str(a) for a in args])))

    invoke(r, opts, "%s %s" % (func, " ".join(args)))

def skip_test(form, skip_list):
    for s in skip_list:
        if re.search(s, form):
            return True
    return False

def compile_wast_to_wasm(form, wast_tempfile, wasm_tempfile, opts):
    log("Writing WAST module to '%s'" % wast_tempfile)
    open(wast_tempfile, 'w').write(form)
    log("Compiling WASM to '%s'" % wasm_tempfile)

    # default arguments
    cmd = [opts.wast2wasm,
            "--enable-thread",
            "--no-check",
            wast_tempfile, "-o", wasm_tempfile ]

    # remove reference-type and bulk-memory enabling options since a WABT
    # commit 30c1e983d30b33a8004b39fd60cbd64477a7956c
    # Enable reference types by default (#1729)

    log("Running: %s" % " ".join(cmd))
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        print(str(e))
        return False

    return True

def compile_wasm_to_aot(wasm_tempfile, aot_tempfile, runner, opts, r):
    log("Compiling AOT to '%s'" % aot_tempfile)
    cmd = [opts.aot_compiler]

    if test_target == "x86_64":
        cmd.append("--target=x86_64")
        cmd.append("--cpu=skylake")
    elif test_target == "i386":
        cmd.append("--target=i386")
    elif test_target == "aarch64":
        cmd += ["--target=aarch64", "--cpu=cortex-a57"]
    elif test_target == "armv7":
        cmd += ["--target=armv7", "--target-abi=gnueabihf"]
    elif test_target == "thumbv7":
        cmd += ["--target=thumbv7", "--target-abi=gnueabihf", "--cpu=cortex-a15"]
    elif test_target == "riscv64_lp64d":
        cmd += ["--target=riscv64", "--target-abi=lp64d"]
    elif test_target == "riscv64_lp64":
        cmd += ["--target=riscv64", "--target-abi=lp64"]
    else:
        pass

    if opts.sgx:
        cmd.append("-sgx")

    if not opts.simd:
        cmd.append("--disable-simd")

    if opts.xip:
        cmd.append("--enable-indirect-mode")
        cmd.append("--disable-llvm-intrinsics")

    if opts.multi_thread:
        cmd.append("--enable-multi-thread")

    # disable llvm link time optimization as it might convert
    # code of tail call into code of dead loop, and stack overflow
    # exception isn't thrown in several cases
    cmd.append("--disable-llvm-lto")

    cmd += ["-o", aot_tempfile, wasm_tempfile]

    log("Running: %s" % " ".join(cmd))
    if not runner:
        subprocess.check_call(cmd)
    else:
        if (r != None):
            r.cleanup()
        r = Runner(cmd, no_pty=opts.no_pty)
        return r

def run_wasm_with_repl(wasm_tempfile, aot_tempfile, opts, r):
    if not test_aot:
        log("Starting interpreter for module '%s'" % wasm_tempfile)
        if opts.verbose:
            cmd = [opts.interpreter, "--heap-size=0", "-v=5", "--repl", wasm_tempfile]
        else:
            cmd = [opts.interpreter, "--heap-size=0", "--repl", wasm_tempfile]
    else:
        log("Starting aot for module '%s'" % aot_tempfile)
        if opts.verbose:
            cmd = [opts.interpreter, "--heap-size=0", "-v=5", "--repl", aot_tempfile]
        else:
            cmd = [opts.interpreter, "--heap-size=0", "--repl", aot_tempfile]

    log("Running: %s" % " ".join(cmd))
    if (r != None):
        r.cleanup()
    r = Runner(cmd, no_pty=opts.no_pty)
    return r

def create_tmpfiles(wast_name):
    tempfiles = []
    # make tempfile directory
    if not os.path.exists(temp_file_directory):
        os.mkdir(temp_file_directory)

    def makefile(name):
        open(name, "w").close()

    # create temporal file with particular name
    temp_wast_file = os.path.join(temp_file_directory, ""+ wast_name + ".wast")
    if not os.path.exists(temp_wast_file):
        makefile(temp_wast_file)
    tempfiles.append(temp_wast_file)

    # now we define the same file name as wast for wasm & aot
    wasm_file = wast_name +".wasm"
    temp_wasm_file = os.path.join(temp_file_directory, wasm_file)
    if not os.path.exists(temp_wasm_file):
        makefile(temp_wasm_file)
    tempfiles.append(temp_wasm_file)

    if test_aot:
        aot_file = wast_name +".aot"
        temp_aot_file =os.path.join(temp_file_directory, aot_file)
        if not os.path.exists(temp_aot_file):
            makefile(temp_aot_file)
        tempfiles.append(temp_aot_file)

    # add these temp file to temporal repo, will be deleted when finishing the test
    temp_file_repo.extend(tempfiles)
    return tempfiles

def test_assert_with_exception(form, wast_tempfile, wasm_tempfile, aot_tempfile, opts, r):
    details_inside_ast = get_module_exp_from_assert(form)
    log("module is ....'%s'"%details_inside_ast[0])
    log("exception is ....'%s'"%details_inside_ast[1])
    # parse the module
    module = details_inside_ast[0]
    expected = details_inside_ast[1]

    if not compile_wast_to_wasm(module, wast_tempfile, wasm_tempfile, opts):
        raise Exception("compile wast to wasm failed")

    if test_aot:
        r = compile_wasm_to_aot(wasm_tempfile, aot_tempfile, True, opts, r)
        try:
            assert_prompt(r, ['Compile success'], opts.start_timeout, True)
        except:
            _, exc, _ = sys.exc_info()
            if (r.buf.find(expected) >= 0):
                log("Out exception includes expected one, pass:")
                log("  Expected: %s" % expected)
                log("  Got: %s" % r.buf)
                return
            else:
                log("Run wamrc failed:\n  expected: '%s'\n  got: '%s'" % \
                    (expected, r.buf))
                sys.exit(1)
        r = run_wasm_with_repl(wasm_tempfile, aot_tempfile, opts, r)
    else:
        r = run_wasm_with_repl(wasm_tempfile, None, opts, r)

    # Wait for the initial prompt
    try:
        assert_prompt(r, ['webassembly> '], opts.start_timeout, True)
    except:
        _, exc, _ = sys.exc_info()
        if (r.buf.find(expected) >= 0):
            log("Out exception includes expected one, pass:")
            log("  Expected: %s" %expected)
            log("  Got: %s" % r.buf)
        else:
            raise Exception("Failed:\n  expected: '%s'\n  got: '%s'" % \
                            (expected, r.buf))

if __name__ == "__main__":
    opts = parser.parse_args(sys.argv[1:])

    if opts.aot: test_aot = True
    # default x86_64
    test_target = opts.aot_target

    if opts.rundir: os.chdir(opts.rundir)

    if opts.log_file:   log_file   = open(opts.log_file, "a")
    if opts.debug_file: debug_file = open(opts.debug_file, "a")

    if opts.interpreter.endswith(".py"):
        SKIP_TESTS = PY_SKIP_TESTS
    else:
        SKIP_TESTS = C_SKIP_TESTS

    (t1fd, wast_tempfile) = tempfile.mkstemp(suffix=".wast")
    (t2fd, wasm_tempfile) = tempfile.mkstemp(suffix=".wasm")
    if test_aot:
        (t3fd, aot_tempfile) = tempfile.mkstemp(suffix=".aot")

    ret_code = 0
    try:
        log("################################################")
        log("### Testing %s" % opts.test_file.name)
        log("################################################")
        forms = read_forms(opts.test_file.read())
        r = None

        for form in forms:
            # log("\n### Current Case is " + form + "\n")
            if ";;" == form[0:2]:
                log(form)
            elif skip_test(form, SKIP_TESTS):
                log("Skipping test: %s" % form[0:60])
            elif re.match("^\(assert_trap\s+\(module", form):
                if test_aot:
                    test_assert_with_exception(form, wast_tempfile, wasm_tempfile, aot_tempfile, opts, r)
                else:
                    test_assert_with_exception(form, wast_tempfile, wasm_tempfile, None, opts, r)
            elif re.match("^\(assert_exhaustion\\b.*", form):
                test_assert_exhaustion(r, opts, form)
            elif re.match("^\(assert_unlinkable\\b.*", form):
                if test_aot:
                    test_assert_with_exception(form, wast_tempfile, wasm_tempfile, aot_tempfile, opts, r)
                else:
                    test_assert_with_exception(form, wast_tempfile, wasm_tempfile, None, opts, r)
            elif re.match("^\(assert_malformed\\b.*", form):
                # remove comments in wast
                form,n = re.subn(";;.*\n", "", form)
                m = re.match("^\(assert_malformed\s*\(module binary\s*(\".*\").*\)\s*\"(.*)\"\s*\)$", form, re.DOTALL)

                if m:
                    # workaround: spec test changes error message to "malformed" while iwasm still use "invalid"
                    error_msg = m.group(2).replace("malformed", "invalid")
                    log("Testing(malformed)")
                    f = open(wasm_tempfile, 'w')
                    s = m.group(1)
                    while s:
                        res = re.match("[^\"]*\"([^\"]*)\"(.*)", s, re.DOTALL)
                        f.write(res.group(1).replace("\\", "\\x").decode("string_escape"))
                        s = res.group(2)
                    f.close()

                    # compile wasm to aot
                    if test_aot:
                        r = compile_wasm_to_aot(wasm_tempfile, aot_tempfile, True, opts, r)
                        try:
                            assert_prompt(r, ['Compile success'], opts.start_timeout, True)
                        except:
                            _, exc, _ = sys.exc_info()
                            if (r.buf.find(error_msg) >= 0):
                                log("Out exception includes expected one, pass:")
                                log("  Expected: %s" % error_msg)
                                log("  Got: %s" % r.buf)
                            else:
                                log("Run wamrc failed:\n  expected: '%s'\n  got: '%s'" % \
                                    (error_msg, r.buf))
                            continue
                        cmd = [opts.interpreter, "--heap-size=0", "--repl", aot_tempfile]
                    else:
                        cmd = [opts.interpreter, "--heap-size=0", "--repl", wasm_tempfile]
                    log("Running: %s" % " ".join(cmd))
                    output = subprocess.check_output(cmd)

                    if (error_msg == "unexpected end of section or function") \
                       and output.endswith("unexpected end\n"):
                        # one case in binary.wast
                        pass
                    elif (error_msg == "invalid value type") \
                       and output.endswith("unexpected end\n"):
                        # one case in binary.wast
                        pass
                    elif (error_msg == "length out of bounds") \
                       and output.endswith("unexpected end\n"):
                        # one case in custom.wast
                        pass
                    elif (error_msg == "integer representation too long") \
                       and output.endswith("invalid section id\n"):
                        # several cases in binary-leb128.wast
                        pass
                    elif not error_msg in output:
                        raise Exception("Failed:\n  expected: '%s'\n  got: '%s'" % (error_msg, output[0:-1]))
                    else:
                        pass
                elif re.match("^\(assert_malformed\s*\(module quote", form):
                    log("ignoring assert_malformed module quote")
                else:
                    log("unrecognized assert_malformed")
            elif re.match("^\(assert_return[_a-z]*_nan\\b.*", form):
                log("ignoring assert_return_.*_nan")
                pass
            elif re.match(".*\(invoke\s+\$\\b.*", form):
                # invoke a particular named module's function
                if form.startswith("(assert_return"):
                    test_assert_return(r,opts,form)
                elif form.startswith("(assert_trap"):
                    test_assert_trap(r,opts,form)
            elif re.match("^\(module\\b.*", form):
                # if the module includes the particular name startswith $
                m = re.search("^\(module\s+\$.\S+", form)
                if m:
                    # get module name
                    module_name = re.split('\$', m.group(0).strip())[1]
                    if module_name:
                        # create temporal files
                        temp_files = create_tmpfiles(module_name)
                        if not compile_wast_to_wasm(form, temp_files[0], temp_files[1], opts):
                            raise Exception("compile wast to wasm failed")

                        if test_aot:
                            r = compile_wasm_to_aot(temp_files[1], temp_files[2], True, opts, r)
                            try:
                                assert_prompt(r, ['Compile success'], opts.start_timeout, False)
                            except:
                                _, exc, _ = sys.exc_info()
                                log("Run wamrc failed:\n  got: '%s'" % r.buf)
                                sys.exit(1)
                            r = run_wasm_with_repl(temp_files[1], temp_files[2], opts, r)
                        else:
                            r = run_wasm_with_repl(temp_files[1], None, opts, r)
                else:
                    if not compile_wast_to_wasm(form, wast_tempfile, wasm_tempfile, opts):
                        raise Exception("compile wast to wasm failed")

                    if test_aot:
                        r = compile_wasm_to_aot(wasm_tempfile, aot_tempfile, True, opts, r)
                        try:
                            assert_prompt(r, ['Compile success'], opts.start_timeout, False)
                        except:
                            _, exc, _ = sys.exc_info()
                            log("Run wamrc failed:\n  got: '%s'" % r.buf)
                            sys.exit(1)
                        r = run_wasm_with_repl(wasm_tempfile, aot_tempfile, opts, r)
                    else:
                        r = run_wasm_with_repl(wasm_tempfile, None, opts, r)

                # Wait for the initial prompt
                try:
                    assert_prompt(r, ['webassembly> '], opts.start_timeout, False)
                except:
                    _, exc, _ = sys.exc_info()
                    raise Exception("Failed:\n  expected: '%s'\n  got: '%s'" % \
                                    (repr(exc), r.buf))

            elif re.match("^\(assert_return\\b.*", form):
                assert(r), "iwasm repl runtime should be not null"
                test_assert_return(r, opts, form)
            elif re.match("^\(assert_trap\\b.*", form):
                test_assert_trap(r, opts, form)
            elif re.match("^\(invoke\\b.*", form):
                assert(r), "iwasm repl runtime should be not null"
                do_invoke(r, opts, form)
            elif re.match("^\(assert_invalid\\b.*", form):
                if test_aot:
                    test_assert_with_exception(form, wast_tempfile, wasm_tempfile, aot_tempfile, opts, r)
                else:
                    test_assert_with_exception(form, wast_tempfile, wasm_tempfile, None, opts, r)


            elif re.match("^\(register\\b.*", form):
                # get module's new name from the register cmd
                name_new =re.split('\"',re.search('\".*\"',form).group(0))[1]
                if name_new:
                    # if the register cmd include the new and old module name.
                    # like: (register "new" $old)
                    # we will replace the old with new name.
                    name_old = re.search('\$.*\)',form)
                    if name_old:
                        old_ = re.split('\W', re.search('\$.*\)',form).group(0))[1]
                        old_module = os.path.join(temp_file_directory,old_+".wasm")
                    else:
                    # like: (register "new")
                    # this kind of register cmd will be behind of a noramal module
                    # these modules' name are default temporal file name
                    # we replace them with new name.
                        old_module = wasm_tempfile

                    new_module = os.path.join(current_work_directory,name_new+".wasm")
                    shutil.copyfile(old_module,new_module)
                    # add new_module copied from the old into temp_file_repo[]
                    temp_file_repo.append(new_module)
                else:
                    # there is no name defined in register cmd
                    raise Exception("can not find module name from the register")
            else:
                raise Exception("unrecognized form '%s...'" % form[0:40])
    except Exception as e:
        traceback.print_exc()
        print("THE FINAL EXCEPTION IS {}".format(e))
        ret_code = 101
    else:
        ret_code = 0
    finally:
        if not opts.no_cleanup:
            log("Removing tempfiles")
            os.remove(wast_tempfile)
            os.remove(wasm_tempfile)
            if test_aot:
                os.remove(aot_tempfile)

            # remove the files under /tempfiles/ and copy of .wasm files
            if temp_file_repo:
                for t in temp_file_repo:
                    if(len(str(t))!=0 and os.path.exists(t)):
                        os.remove(t)
            # remove /tempfiles/ directory
            if os.path.exists(temp_file_directory):
                shutil.rmtree(temp_file_directory)

            log("### End testing %s" % opts.test_file.name)
        else:
            log("Leaving tempfiles: %s" % ([wast_tempfile, wasm_tempfile]))

        sys.exit(ret_code)
