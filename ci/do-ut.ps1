cd build

# CACHE GENERATION
cmake -G "NMake Makefiles" `
                     -D FLB_TESTS_INTERNAL=On `
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
                     ../

# COMPILE
cmake --build .

# RUNNING TESTS
ctest --build-run-dir $PWD --output-on-failure
