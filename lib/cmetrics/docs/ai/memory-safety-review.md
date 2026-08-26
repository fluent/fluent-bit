# Memory-safety review

## Purpose

Validate allocation, ownership, lifetime, and cleanup changes in this C library.

## When to use

Use for constructors/destructors, containers, codecs, arenas, metadata,
submodule allocator changes, and crash or leak reports.

## Investigation

1. Inventory allocations and their matching destructors by allocation family.
2. Trace ownership transfers, shared/borrowed pointers, arena lifetime, and
   partial initialization.
3. Audit every normal and error exit, including empty collections and nested
   values.
4. Check concurrent mutation/destruction and untrusted length arithmetic.
5. Add focused zero/one/many and failure-path regression cases where practical.

## Validation

First run the focused test normally. For AddressSanitizer, use a separate build
with compiler/linker sanitizer flags and execute CTest with leak detection. For
Valgrind, use a non-sanitized debug build and treat definite leaks/errors as
failures. Record the exact compiler, flags, commands, and test count; sanitizer
and Valgrind runs are complementary, not interchangeable.

## Expected report

Report the ownership model, confirmed defect, cleanup coverage, sanitizer and
Valgrind results, allocation-failure coverage, and untested paths.

## Stop conditions

Stop when ownership cannot be established from callers, allocator injection is
required but unavailable, or a proposed lifetime change affects a public
structure without compatibility review.
