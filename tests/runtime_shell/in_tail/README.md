# Fluent Bit Tail Input Plugin Tests

The following directory contains tests for Tail input plugin behaviors.

## run_tests.sh

This script provide validations for offsets, database file entries and rotation under different scenarios. The following tests are available in the script

- test_normal_rotation
- test_single_static_rotation
- test_truncate
- test_rotate_link
- test_truncate_link

Running the script ```test_rotation.sh``` will run every test listed above, to run a single test just append it name, e.g:

```
./test_rotation.sh -- test_truncate
```

### 1. Normal Rotation

**Unit**

```test_normal_rotation```

**Description**

Run the logger tool that creates 5 different files, write 100000 messages to each one while rotating at 256KB.

This test enable the database backend for Tail so it also helps to validate expected entries into the 'in_tail_files' table.

**Configuration File**

```conf/normal_rotation.conf```

### 2. Single Static Rotation

**Unit**

```test_single_static_rotation```

**Description**

Run the logger tool that creates 1 big file and let Fluent Bit process it in the static mode, before to promote it to 'events' and it gets rotated.

**Configuration File**

```conf/single_static_rotation.conf```

### 3. Truncate

**Unit**

```test_truncate```

**Description**

 Some environments still rely on truncation mode or well known as copytruncate,
 this is the definition by logrotate(8):

> Truncate the original log file to zero size in place after creating a copy,
> instead of moving the old log file and optionally creating a new one.  It
> can be used when some program cannot  be told  to  close its logfile and
> thus might continue writing (appending) to the previous log file forever.
>
> Note that there is a very  small  time  slice between copying the file and
> truncating it, so some logging data might be lost.   When  this  option is
> used, the create option will have no effect, as the old log file stays in
> place.

This test checks that after a truncation the new lines added are properly
processed.

**Configuration File**

```conf/truncate_rotation.conf```

### 4. Rotate Link

**Unit**

```test_rotate_link```

**Description**

This test checks that a monitored link, upon rotation, keeps the proper offset and database status for the real file.

 Example:

 - file with data:  data.log
 - monitored link:  test.log

 Check the behavior upon the following rotation: test.log -> test.log.1

**Configuration File**

```conf/rotate_link.conf```

### 5. Truncate Link

**Unit**

```test_truncate_link```

**Description**

Test a link that gets a truncation and Fluent Bit properly use the new offset

**Configuration File**

```conf/truncate_link.conf```

### 6. Multiline Rotation

**Unit**

```test_multiline_rotation```

**Description**

Test a multiline rotation for issue 4190.

**Configuration File**

```conf/multiline_rotation.conf```
