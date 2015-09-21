#!/usr/bin/perl

use warnings;
use strict;

use utf8;
use open qw(:std utf8);

my @suites = grep { ! /\.(?:c|gcno)$/ } glob 'test_suite_*';
die "$0: no test suite found\n" unless @suites;

# in case test suites are linked dynamically
$ENV{'LD_LIBRARY_PATH'} = '../library';

my $prefix = $^O eq "MSWin32" ? '' : './';

my ($failed_suites, $total_tests_run);
for my $suite (@suites)
{
    print "$suite ", "." x ( 72 - length($suite) - 2 - 4 ), " ";
    my $result = `$prefix$suite`;
    if( $result =~ /PASSED/ ) {
        print "PASS\n";
    } else {
        $failed_suites++;
        print "FAIL\n";
    }
    my ($tests, $skipped) = $result =~ /([0-9]*) tests.*?([0-9]*) skipped/;
    $total_tests_run += $tests - $skipped;
}

print "-" x 72, "\n";
print $failed_suites ? "FAILED" : "PASSED";
printf " (%d suites, %d tests run)\n", scalar @suites, $total_tests_run;
exit( $failed_suites ? 1 : 0 );
