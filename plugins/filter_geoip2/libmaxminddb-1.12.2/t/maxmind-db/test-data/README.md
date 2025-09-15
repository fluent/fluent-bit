## How to generate test data
Use the [write-test-data](https://github.com/maxmind/MaxMind-DB/blob/main/cmd/write-test-data)
go tool to create a small set of test databases with a variety of data and
record sizes.

These test databases are useful for testing code that reads MaxMind DB files.

There are several ways to figure out what IP addresses are actually in the
test databases. You can take a look at the
[source-data directory](https://github.com/maxmind/MaxMind-DB/tree/main/source-data)
in this repository. This directory contains JSON files which are used to
generate many (but not all) of the database files.

You can also use the
[mmdb-dump-database script](https://github.com/maxmind/MaxMind-DB-Reader-perl/blob/main/eg/mmdb-dump-database)
in the
[MaxMind-DB-Reader-perl repository](https://github.com/maxmind/MaxMind-DB-Reader-perl).

## Static test data
Some of the test files are remnants of the
[old perl test data writer](https://github.com/maxmind/MaxMind-DB/blob/f0a85c671c5b6e9c5e514bd66162724ee1dedea3/test-data/write-test-data.pl)
and cannot be generated with the go tool. These databases are intentionally broken,
and exploited functionality simply not available in the go mmdbwriter:

- MaxMind-DB-test-broken-pointers-24.mmdb
- MaxMind-DB-test-broken-search-tree-24.mmdb
- MaxMind-DB-test-pointer-decoder.mmdb
- GeoIP2-City-Test-Broken-Double-Format.mmdb
- GeoIP2-City-Test-Invalid-Node-Count.mmdb
- maps-with-pointers.raw

## Usage
```
Usage of ./write-test-data:
  -source string
        Source data directory
  -target string
        Destination directory for the generated mmdb files
```

Example:
`./write-test-data --source ../../source-data --target ../../test-data`
