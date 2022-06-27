#!/usr/bin/env perl

# curves.pl
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
# The purpose of this test script is to validate that the library works
# with any combination of elliptic curves. To this effect, build the library
# and run the test suite with each tested combination of elliptic curves.
#
# Testing all 2^n combinations would be too much, so we only test 2*n:
#
# 1. Test with a single curve, for each curve. This validates that the
#    library works with any curve, and in particular that curve-specific
#    code is guarded by the proper preprocessor conditionals.
# 2. Test with all curves except one, for each curve. This validates that
#    the test cases have correct dependencies. Testing with a single curve
#    doesn't validate this for tests that require more than one curve.

# Usage: tests/scripts/curves.pl
#
# This script should be executed from the root of the project directory.
#
# Only curves that are enabled in config.h will be tested.
#
# For best effect, run either with cmake disabled, or cmake enabled in a mode
# that includes -Werror.

use warnings;
use strict;

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $sed_cmd = 's/^#define \(MBEDTLS_ECP_DP.*_ENABLED\)/\1/p';
my $config_h = 'include/mbedtls/config.h';
my @curves = split( /\s+/, `sed -n -e '$sed_cmd' $config_h` );

# Determine which curves support ECDSA by checking the dependencies of
# ECDSA in check_config.h.
my %curve_supports_ecdsa = ();
{
    local $/ = "";
    local *CHECK_CONFIG;
    open(CHECK_CONFIG, '<', 'include/mbedtls/check_config.h')
        or die "open include/mbedtls/check_config.h: $!";
    while (my $stanza = <CHECK_CONFIG>) {
        if ($stanza =~ /\A#if defined\(MBEDTLS_ECDSA_C\)/) {
            for my $curve ($stanza =~ /(?<=\()MBEDTLS_ECP_DP_\w+_ENABLED(?=\))/g) {
                $curve_supports_ecdsa{$curve} = 1;
            }
            last;
        }
    }
    close(CHECK_CONFIG);
}

system( "cp $config_h $config_h.bak" ) and die;
sub abort {
    system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
    # use an exit code between 1 and 124 for git bisect (die returns 255)
    warn $_[0];
    exit 1;
}

# Disable all the curves. We'll then re-enable them one by one.
for my $curve (@curves) {
    system( "scripts/config.pl unset $curve" )
        and abort "Failed to disable $curve\n";
}
# Depends on a specific curve. Also, ignore error if it wasn't enabled.
system( "scripts/config.pl unset MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED" );

# Test with only $curve enabled, for each $curve.
for my $curve (@curves) {
    system( "make clean" ) and die;

    print "\n******************************************\n";
    print "* Testing with only curve: $curve\n";
    print "******************************************\n";
    $ENV{MBEDTLS_TEST_CONFIGURATION} = "$curve";

    system( "scripts/config.pl set $curve" )
        and abort "Failed to enable $curve\n";

    my $ecdsa = $curve_supports_ecdsa{$curve} ? "set" : "unset";
    for my $dep (qw(MBEDTLS_ECDSA_C
                    MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
                    MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)) {
        system( "scripts/config.pl $ecdsa $dep" )
            and abort "Failed to $ecdsa $dep\n";
    }

    system( "CFLAGS='-Werror -Wall -Wextra' make" )
        and abort "Failed to build: only $curve\n";
    system( "make test" )
        and abort "Failed test suite: only $curve\n";

    system( "scripts/config.pl unset $curve" )
        and abort "Failed to disable $curve\n";
}

system( "cp $config_h.bak $config_h" ) and die "$config_h not restored\n";

# Test with $curve disabled but the others enabled, for each $curve.
for my $curve (@curves) {
    system( "cp $config_h.bak $config_h" ) and die "$config_h not restored\n";
    system( "make clean" ) and die;

    # depends on a specific curve. Also, ignore error if it wasn't enabled
    system( "scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED" );

    print "\n******************************************\n";
    print "* Testing without curve: $curve\n";
    print "******************************************\n";
    $ENV{MBEDTLS_TEST_CONFIGURATION} = "-$curve";

    system( "scripts/config.py unset $curve" )
        and abort "Failed to disable $curve\n";

    system( "CFLAGS='-Werror -Wall -Wextra' make" )
        and abort "Failed to build: all but $curve\n";
    system( "make test" )
        and abort "Failed test suite: all but $curve\n";

}

system( "mv $config_h.bak $config_h" ) and die "$config_h not restored\n";
system( "make clean" ) and die;
exit 0;
