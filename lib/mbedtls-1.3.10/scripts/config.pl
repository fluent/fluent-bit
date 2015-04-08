#!/usr/bin/perl

# Tune the configuration file

use warnings;
use strict;

my $usage = <<EOU;
$0 [-f <file>] unset <name>
$0 [-f <file>] set <name> [<value>]
EOU
# for our eyes only:
# $0 [-f <file>] full

# Things that shouldn't be enabled with "full".
# Notes:
# - POLARSSL_X509_ALLOW_EXTENSIONS_NON_V3 and
#   POLARSSL_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION could be enabled if the
#   respective tests were adapted
my @excluded = qw(
POLARSSL_HAVE_INT8
POLARSSL_HAVE_INT16
POLARSSL_HAVE_SSE2
POLARSSL_PLATFORM_NO_STD_FUNCTIONS
POLARSSL_ECP_DP_M221_ENABLED
POLARSSL_ECP_DP_M383_ENABLED
POLARSSL_ECP_DP_M511_ENABLED
POLARSSL_NO_DEFAULT_ENTROPY_SOURCES
POLARSSL_NO_PLATFORM_ENTROPY
POLARSSL_SSL_HW_RECORD_ACCEL
POLARSSL_SSL_DISABLE_RENEGOTIATION
POLARSSL_X509_ALLOW_EXTENSIONS_NON_V3
POLARSSL_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
POLARSSL_ZLIB_SUPPORT
POLARSSL_PKCS11_C
_ALT\s*$
);

my $config_file = "include/polarssl/config.h";

# get -f option
if (@ARGV >= 2 && $ARGV[0] eq "-f") {
    shift; # -f
    $config_file = shift;

    -f $config_file or die "No such file: $config_file\n";
} else {
    if (! -f $config_file)  {
        chdir '..' or die;
        -d $config_file
            or die "Without -f, must be run from root or scripts\n"
    }
}

# get action
die $usage unless @ARGV;
my $action = shift;

my ($name, $value);
if ($action eq "full") {
    # nothing to do
} elsif ($action eq "unset") {
    die $usage unless @ARGV;
    $name = shift;
} elsif ($action eq "set") {
    die $usage unless @ARGV;
    $name = shift;
    $value = shift if @ARGV;
} else {
    die $usage;
}
die $usage if @ARGV;

open my $config_read, '<', $config_file or die "read $config_file: $!\n";
my @config_lines = <$config_read>;
close $config_read;

my $exclude_re = join '|', @excluded;

open my $config_write, '>', $config_file or die "write $config_file: $!\n";

my $done;
for my $line (@config_lines) {
    if ($action eq "full") {
        if ($line =~ /name SECTION: Module configuration options/) {
            $done = 1;
        }

        if (!$done && $line =~ m!^//\s?#define! && $line !~ /$exclude_re/) {
            $line =~ s!^//!!;
        }
    } elsif ($action eq "unset") {
        if (!$done && $line =~ /^\s*#define\s*$name/) {
            $line = '//' . $line;
            $done = 1;
        }
    } elsif (!$done && $action eq "set") {
        if ($line =~ m!^(?://)?\s*#define\s*$name!) {
            $line = "#define $name";
            $line .= " $value" if defined $value && $value ne "";
            $line .= "\n";
            $done = 1;
        }
    }

    print $config_write $line;
}

close $config_write;

warn "configuration section not found" if ($action eq "full" && !$done);
warn "$name not found" if ($action ne "full" && !$done);

__END__
