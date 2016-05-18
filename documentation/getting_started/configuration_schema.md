# Configuration Schema

Fluent Bit may use optionally a configuration file to define how the service will behave, and before to proceed we need to understand how the configuration schema works. The schema is defined by three concepts:

* Sections
* Entries: Key/Value
* Indented Configuration Mode

A simple example of a configuration file is as follows:

```Python
[SERVICE]
    # This is a commented line
    Daemon    off
    log_level debug
```

## Sections

A section is defined by a name or title inside brackets. Looking at the example above a Server section have been set using __[SERVICE]__ definition. Section rules:

* All section content must be indented (4 spaces ideally).
* Multiples sections can exists on the same file.
* Under a section is expected to have comments and entries, a section cannot be empty.
* Any commented line under a section, must be indented too.

## Entries: Key/Value

A section may contain __Entries__, an entry is defined by a line of text that contains a __Key__ and a __Value__, using the above example, the __[SERVICE]__ section contains two entries, one is the key __Daemon__ with value __off__ and the other the key __Log\_Level__ with the value __on__. Entries rules:

* An entry is defined by a key and a value.
* A key must be indented.
* A key must contain a value which ends in the breakline.
* Multiple keys with the same name can exists.

Also commented lines are set prefixing the __#__ character, those lines are not processed but they must be indented too.

## Indented Configuration Mode

Fluent Bit configuration files are based in a strict __Indented Mode__,  that means that each configuration file must follow the same pattern of alignment from left to right when writing text. By default is suggested an indentation level of four spaces from left to right. Example:

```Python
[FIRST_SECTION]
    # This is a commented line
    Key1  some value
    Key2  another value
    # more comments

[SECOND_SECTION]
    KeyN  3.14
```

As you can see there are two sections with multiple entries and comments, note also that empty lines are allowed and they do not need to be indented.
