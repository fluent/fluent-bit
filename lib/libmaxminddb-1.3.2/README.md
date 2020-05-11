# About

The libmaxminddb library provides a C library for reading MaxMind DB files,
including the GeoIP2 databases from MaxMind. This is a custom binary format
designed to facilitate fast lookups of IP addresses while allowing for great
flexibility in the type of data associated with an address.

The MaxMind DB format is an open format. The spec is available at
http://maxmind.github.io/MaxMind-DB/. This spec is licensed under the Creative
Commons Attribution-ShareAlike 3.0 Unported License.

See http://dev.maxmind.com/ for more details about MaxMind's GeoIP2 products.

# License

This library is licensed under the Apache License, Version 2.

# Installation

## From a Tarball

This code is known to work with GCC 4.4+ and clang 3.2+. It should also work
on other compilers that supports C99, POSIX.1-2001, and the `-fms-extensions
flag` (or equivalent). The latter is needed to allow an anonymous union in a
structure.

To install this code, run the following commands:

    $ ./configure
    $ make
    $ make check
    $ sudo make install
    $ sudo ldconfig

You can skip the `make check` step but it's always good to know that tests are
passing on your platform.

The `configure` script takes the standard options to set where files are
installed such as `--prefix`, etc. See `./configure --help` for details.

If after installing, you receive an error that `libmaxminddb.so.0` is missing
you may need to add the `lib` directory in your `prefix` to your library path.
On most Linux distributions when using the default prefix (`/usr/local`), you
can do this by running the following commands:

    $ sudo sh -c "echo /usr/local/lib  >> /etc/ld.so.conf.d/local.conf"
    $ ldconfig

## From the Git Repository

To install from Git, you will need automake, autoconf, and libtool installed
in addition to make and a compiler.

Our public git repository is hosted on GitHub at
https://github.com/maxmind/libmaxminddb

You can clone this repository and build it by running:

    $ git clone --recursive https://github.com/maxmind/libmaxminddb

After cloning, run `./bootstrap` from the `libmaxminddb` directory and then
follow the instructions for installing from a tarball as described above.

## On Windows via Visual Studio 2013+

We provide a Visual Studio solution in `projects\VS12`. This can be used to
build both the the library and the tests. Please see the `README.md` file in
the same directory for more information.

## On Ubuntu via PPA

MaxMind provides a PPA for recent version of Ubuntu. To add the PPA to your
APT sources, run:

    $ sudo add-apt-repository ppa:maxmind/ppa

Then install the packages by running:

    $ sudo apt update
    $ sudo apt install libmaxminddb0 libmaxminddb-dev mmdb-bin

## On OS X via Homebrew

If you are on OS X and you have homebrew (see http://brew.sh/) you can install
libmaxminddb via brew.

    $ brew install libmaxminddb

# Bug Reports

Please report bugs by filing an issue with our GitHub issue tracker at
https://github.com/maxmind/libmaxminddb/issues

# Dev Tools

We have a few development tools under the `dev-bin` directory to make
development easier. These are written in Perl or shell. They are:

* `regen-prototypes.pl` - This regenerates the prototypes in the header and
  source files. This helps keep headers and code in sync.
* `uncrustify-all.sh` - This runs `uncrustify` on all the code. It runs
  `regen-prototypes.pl` first. Please run this before submitting patches.
* `valgrind-all.pl` - This runs Valgrind on the tests and `mmdblookup` to
  check for memory leaks.

# Creating a Release Tarball

Use `make safedist` to check the resulting tarball.

# Copyright and License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
