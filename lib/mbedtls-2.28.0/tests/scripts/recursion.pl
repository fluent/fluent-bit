#!/usr/bin/env perl

# Find functions making recursive calls to themselves.
# (Multiple recursion where a() calls b() which calls a() not covered.)
#
# When the recursion depth might depend on data controlled by the attacker in
# an unbounded way, those functions should use interation instead.
#
# Typical usage: scripts/recursion.pl library/*.c
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

use warnings;
use strict;

use utf8;
use open qw(:std utf8);

# exclude functions that are ok:
# - mpi_write_hlp: bounded by size of mbedtls_mpi, a compile-time constant
# - x509_crt_verify_child: bounded by MBEDTLS_X509_MAX_INTERMEDIATE_CA
my $known_ok = qr/mpi_write_hlp|x509_crt_verify_child/;

my $cur_name;
my $inside;
my @funcs;

die "Usage: $0 file.c [...]\n" unless @ARGV;

while (<>)
{
    if( /^[^\/#{}\s]/ && ! /\[.*]/ ) {
        chomp( $cur_name = $_ ) unless $inside;
    } elsif( /^{/ && $cur_name ) {
        $inside = 1;
        $cur_name =~ s/.* ([^ ]*)\(.*/$1/;
    } elsif( /^}/ && $inside ) {
        undef $inside;
        undef $cur_name;
    } elsif( $inside && /\b\Q$cur_name\E\([^)]/ ) {
        push @funcs, $cur_name unless /$known_ok/;
    }
}

print "$_\n" for @funcs;
exit @funcs;
