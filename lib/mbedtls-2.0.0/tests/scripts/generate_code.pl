#!/usr/bin/env perl
#

use strict;

my $suite_dir = shift or die "Missing suite directory";
my $suite_name = shift or die "Missing suite name";
my $data_name = shift or die "Missing data name";
my $test_main_file = do { my $arg = shift; defined($arg) ? $arg :  $suite_dir."/main_test.function" };
my $test_file = $data_name.".c";
my $test_helper_file = $suite_dir."/helpers.function";
my $test_case_file = $suite_dir."/".$suite_name.".function";
my $test_case_data = $suite_dir."/".$data_name.".data";

my $line_separator = $/;
undef $/;

open(TEST_HELPERS, "$test_helper_file") or die "Opening test helpers '$test_helper_file': $!";
my $test_helpers = <TEST_HELPERS>;
close(TEST_HELPERS);

open(TEST_MAIN, "$test_main_file") or die "Opening test main '$test_main_file': $!";
my $test_main = <TEST_MAIN>;
close(TEST_MAIN);

open(TEST_CASES, "$test_case_file") or die "Opening test cases '$test_case_file': $!";
my $test_cases = <TEST_CASES>;
close(TEST_CASES);

open(TEST_DATA, "$test_case_data") or die "Opening test data '$test_case_data': $!";
my $test_data = <TEST_DATA>;
close(TEST_DATA);

my ( $suite_header ) = $test_cases =~ /\/\* BEGIN_HEADER \*\/\n(.*?)\n\/\* END_HEADER \*\//s;
my ( $suite_defines ) = $test_cases =~ /\/\* BEGIN_DEPENDENCIES\n \* (.*?)\n \* END_DEPENDENCIES/s;

my $requirements;
if ($suite_defines =~ /^depends_on:/)
{
    ( $requirements ) = $suite_defines =~ /^depends_on:(.*)$/;
}

my @var_req_arr = split(/:/, $requirements);
my $suite_pre_code;
my $suite_post_code;
my $dispatch_code;
my $mapping_code;
my %mapping_values;

while (@var_req_arr)
{
    my $req = shift @var_req_arr;
    $req =~ s/(!?)(.*)/$1defined($2)/;

    $suite_pre_code .= "#if $req\n";
    $suite_post_code .= "#endif /* $req */\n";
}

$/ = $line_separator;

open(TEST_FILE, ">$test_file") or die "Opening destination file '$test_file': $!";
print TEST_FILE << "END";
#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

$test_helpers

$suite_pre_code
$suite_header
$suite_post_code

END

$test_main =~ s/SUITE_PRE_DEP/$suite_pre_code/;
$test_main =~ s/SUITE_POST_DEP/$suite_post_code/;

while($test_cases =~ /\/\* BEGIN_CASE *([\w:]*) \*\/\n(.*?)\n\/\* END_CASE \*\//msg)
{
    my $function_deps = $1;
    my $function_decl = $2;

    # Sanity checks of function
    if ($function_decl !~ /^void /)
    {
        die "Test function does not have 'void' as return type\n";
    }
    if ($function_decl !~ /^void (\w+)\(\s*(.*?)\s*\)\s*{(.*)}/ms)
    {
        die "Function declaration not in expected format\n";
    }
    my $function_name = $1;
    my $function_params = $2;
    my $function_pre_code;
    my $function_post_code;
    my $param_defs;
    my $param_checks;
    my @dispatch_params;
    my @var_def_arr = split(/,\s*/, $function_params);
    my $i = 1;
    my $mapping_regex = "".$function_name;
    my $mapping_count = 0;

    $function_decl =~ s/^void /void test_suite_/;

    # Add exit label if not present
    if ($function_decl !~ /^exit:$/m)
    {
        $function_decl =~ s/}\s*$/\nexit:\n    return;\n}/;
    }

    if ($function_deps =~ /^depends_on:/)
    {
        ( $function_deps ) = $function_deps =~ /^depends_on:(.*)$/;
    }

    foreach my $req (split(/:/, $function_deps))
    {
        $function_pre_code .= "#ifdef $req\n";
        $function_post_code .= "#endif /* $req */\n";
    }

    foreach my $def (@var_def_arr)
    {
        # Handle the different parameter types
        if( substr($def, 0, 4) eq "int " )
        {
            $param_defs .= "    int param$i;\n";
            $param_checks .= "    if( verify_int( params[$i], &param$i ) != 0 ) return( 2 );\n";
            push @dispatch_params, "param$i";

            $mapping_regex .= ":([\\d\\w |\\+\\-\\(\\)]+)";
            $mapping_count++;
        }
        elsif( substr($def, 0, 6) eq "char *" )
        {
            $param_defs .= "    char *param$i = params[$i];\n";
            $param_checks .= "    if( verify_string( &param$i ) != 0 ) return( 2 );\n";
            push @dispatch_params, "param$i";
            $mapping_regex .= ":[^:\n]+";
        }
        else
        {
            die "Parameter declaration not of supported type (int, char *)\n";
        }
        $i++;

    }

    # Find non-integer values we should map for this function
    if( $mapping_count)
    {
        my @res = $test_data =~ /^$mapping_regex/msg;
        foreach my $value (@res)
        {
            next unless ($value !~ /^\d+$/);
            if ( $mapping_values{$value} ) {
                ${ $mapping_values{$value} }{$function_pre_code} = 1;
            } else {
                $mapping_values{$value} = { $function_pre_code => 1 };
            }
        }
    }

    my $call_params = join ", ", @dispatch_params;
    my $param_count = @var_def_arr + 1;
    $dispatch_code .= << "END";
if( strcmp( params[0], "$function_name" ) == 0 )
{
$function_pre_code
$param_defs
    if( cnt != $param_count )
    {
        mbedtls_fprintf( stderr, "\\nIncorrect argument count (%d != %d)\\n", cnt, $param_count );
        return( 2 );
    }

$param_checks
    test_suite_$function_name( $call_params );
    return ( 0 );
$function_post_code
    return ( 3 );
}
else
END

    my $function_code = $function_pre_code . $function_decl . "\n" . $function_post_code;
    $test_main =~ s/FUNCTION_CODE/$function_code\nFUNCTION_CODE/;
}

# Find specific case dependencies that we should be able to check
# and make check code
my $dep_check_code;

my @res = $test_data =~ /^depends_on:([\w:]+)/msg;
my %case_deps;
foreach my $deps (@res)
{
    foreach my $dep (split(/:/, $deps))
    {
        $case_deps{$dep} = 1;
    }
}
while( my ($key, $value) = each(%case_deps) )
{
    $dep_check_code .= << "END";
    if( strcmp( str, "$key" ) == 0 )
    {
#if defined($key)
        return( 0 );
#else
        return( 1 );
#endif
    }
END
}

# Make mapping code
while( my ($key, $value) = each(%mapping_values) )
{
    my $key_mapping_code = << "END";
    if( strcmp( str, "$key" ) == 0 )
    {
        *value = ( $key );
        return( 0 );
    }
END

    # handle depenencies, unless used at least one without depends
    if ($value->{""}) {
        $mapping_code .= $key_mapping_code;
        next;
    }
    for my $ifdef ( keys %$value ) {
        (my $endif = $ifdef) =~ s!ifdef!endif //!g;
        $mapping_code .= $ifdef . $key_mapping_code . $endif;
    }
}

$dispatch_code =~ s/^(.+)/    $1/mg;

$test_main =~ s/TEST_FILENAME/$test_case_data/;
$test_main =~ s/FUNCTION_CODE//;
$test_main =~ s/DEP_CHECK_CODE/$dep_check_code/;
$test_main =~ s/DISPATCH_FUNCTION/$dispatch_code/;
$test_main =~ s/MAPPING_CODE/$mapping_code/;

print TEST_FILE << "END";
$test_main
END

close(TEST_FILE);
