#!/usr/bin/env perl

# depends-hashes.pl
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Purpose
#
# To test the code dependencies on individual hashes in each test suite. This
# is a verification step to ensure we don't ship test suites that do not work
# for some build options.
#
# The process is:
#       for each possible hash
#           build the library and test suites with the hash disabled
#           execute the test suites
#
# And any test suite with the wrong dependencies will fail.
#
# Usage: tests/scripts/depends-hashes.pl
#
# This script should be executed from the root of the project directory.
#
# For best effect, run either with cmake disabled, or cmake enabled in a mode
# that includes -Werror.

use warnings;
use strict;

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $config_h = 'include/mbedtls/config.h';

# as many SSL options depend on specific hashes,
# and SSL is not in the test suites anyways,
# disable it to avoid dependcies issues
my $ssl_sed_cmd = 's/^#define \(MBEDTLS_SSL.*\)/\1/p';
my @ssl = split( /\s+/, `sed -n -e '$ssl_sed_cmd' $config_h` );

# for md we want to catch MD5_C but not MD_C, hence the extra dot
my $mdx_sed_cmd = 's/^#define \(MBEDTLS_MD..*_C\)/\1/p';
my $sha_sed_cmd = 's/^#define \(MBEDTLS_SHA.*_C\)/\1/p';
my @hash_modules = split( /\s+/,
                    `sed -n -e '$mdx_sed_cmd' -e '$sha_sed_cmd' $config_h` );

# there are also negative options for truncated variants, disabled by default
my $sha_trunc_sed_cmd = 's/^\/\/#define \(MBEDTLS_SHA..._NO_.*\)/\1/p';
my @hash_negatives = split( /\s+/,
                    `sed -n -e '$sha_trunc_sed_cmd' $config_h` );

# list hash options with corresponding actions
my @hashes = ((map { "unset $_" } @hash_modules),
              (map { "set $_" } @hash_negatives));

system( "cp $config_h $config_h.bak" ) and die;
sub abort {
    system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
    # use an exit code between 1 and 124 for git bisect (die returns 255)
    warn $_[0];
    exit 1;
}

for my $hash (@hashes) {
    system( "cp $config_h.bak $config_h" ) and die "$config_h not restored\n";
    system( "make clean" ) and die;

    print "\n******************************************\n";
    print "* Testing hash option: $hash\n";
    print "******************************************\n";
    $ENV{MBEDTLS_TEST_CONFIGURATION} = "-$hash";

    system( "scripts/config.py $hash" )
        and abort "Failed to $hash\n";

    for my $opt (@ssl) {
        system( "scripts/config.py unset $opt" )
            and abort "Failed to disable $opt\n";
    }

    system( "CFLAGS='-Werror -Wall -Wextra' make lib" )
        and abort "Failed to build lib: $hash\n";
    system( "cd tests && make" ) and abort "Failed to build tests: $hash\n";
    system( "make test" ) and abort "Failed test suite: $hash\n";
}

system( "mv $config_h.bak $config_h" ) and die "$config_h not restored\n";
system( "make clean" ) and die;
exit 0;
