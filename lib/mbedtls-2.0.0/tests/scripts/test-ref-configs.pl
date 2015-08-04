#!/usr/bin/perl

# test standard configurations:
# - build
# - run test suite
# - run compat.sh
#
# Usage: tests/scripts/test-ref-configs.pl [config-name [...]]

use warnings;
use strict;

my %configs = (
    'config-mini-tls1_1.h'
        => '-m tls1_1 -f \'^DES-CBC3-SHA$\|^TLS-RSA-WITH-3DES-EDE-CBC-SHA$\'',
    'config-suite-b.h'
        => "-m tls1_2 -f 'ECDHE-ECDSA.*AES.*GCM' -p mbedTLS",
    'config-picocoin.h'
        => 0,
    'config-ccm-psk-tls1_2.h'
        => '-m tls1_2 -f \'^TLS-PSK-WITH-AES-...-CCM-8\'',
);

# If no config-name is provided, use all known configs.
# Otherwise, use the provided names only.
if ($#ARGV >= 0) {
    my %configs_ori = ( %configs );
    %configs = ();

    foreach my $conf_name (@ARGV) {
        if( ! exists $configs_ori{$conf_name} ) {
            die "Unknown configuration: $conf_name\n";
        } else {
            $configs{$conf_name} = $configs_ori{$conf_name};
        }
    }
}

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $config_h = 'include/mbedtls/config.h';

system( "cp $config_h $config_h.bak" ) and die;
sub abort {
    system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
    die $_[0];
}

while( my ($conf, $args) = each %configs ) {
    system( "cp $config_h.bak $config_h" ) and die;
    system( "make clean" ) and die;

    print "\n******************************************\n";
    print "* Testing configuration: $conf\n";
    print "******************************************\n";

    system( "cp configs/$conf $config_h" )
        and abort "Failed to activate $conf\n";

    system( "make" ) and abort "Failed to build: $conf\n";
    system( "make test" ) and abort "Failed test suite: $conf\n";

    if( $args )
    {
        print "\nrunning compat.sh $args\n";
        system( "tests/compat.sh $args" )
            and abort "Failed compat.sh: $conf\n";
    }
    else
    {
        print "\nskipping compat.sh\n";
    }
}

system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
system( "make clean" );
exit 0;
