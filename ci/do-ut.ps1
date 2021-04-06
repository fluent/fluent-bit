cd build

if ( "x64" -eq $env:PLATFORM ) {
    $OPENSSL_DIR = "C:\OpenSSL-v111-Win64"
}
else {
    $OPENSSL_DIR = "C:\OpenSSL-v111-Win32"
}


# CACHE GENERATION
cmake -G "NMake Makefiles" `
                     -D FLB_TESTS_INTERNAL=On `
                     -D OPENSSL_ROOT_DIR=$OPENSSL_DIR `
                     -D FLB_WITHOUT_flb-rt-out_elasticsearch=On `
                     -D FLB_WITHOUT_flb-rt-out_td=On `
                     -D FLB_WITHOUT_flb-rt-out_forward=On `
                     -D FLB_WITHOUT_flb-rt-in_disk=On `
                     -D FLB_WITHOUT_flb-rt-in_proc=On `
                     -D FLB_WITHOUT_flb-it-parser=On `
                     -D FLB_WITHOUT_flb-it-unit_sizes=On `
                     -D FLB_WITHOUT_flb-it-network=On `
                     -D FLB_WITHOUT_flb-it-pack=On `
                     -D FLB_WITHOUT_flb-it-signv4=On `
                     -D FLB_WITHOUT_flb-it-aws_credentials=On `
                     -D FLB_WITHOUT_flb-it-aws_credentials_ec2=On `
                     -D FLB_WITHOUT_flb-it-aws_credentials_http=On `
                     -D FLB_WITHOUT_flb-it-aws_credentials_profile=On `
                     -D FLB_WITHOUT_flb-it-aws_credentials_sts=On `
                     -D FLB_WITHOUT_flb-it-aws_util=On `
                     -D FLB_WITHOUT_flb-it-input_chunk=On `
                     ../

# COMPILE
cmake --build .

# RUNNING TESTS
ctest --build-run-dir $PWD --output-on-failure
