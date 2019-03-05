$SKIP_TESTS=@("flb-rt-out_elasticsearch",
              "flb-rt-out_td",
              "flb-rt-out_forward",
              "flb-rt-in_disk",
              "flb-rt-in_proc",
              "flb-it-http_client",
              "flb-it-network",
              "flb-it-pack")

$SKIP=""

foreach ($SKIP_TEST in $SKIP_TESTS) {
    $SKIP += " -DFLB_WITHOUT_${SKIP_TEST}=1"
}

$GLOBAL_OPTS="-DFLB_BACKTRACE=Off -DFLB_SHARED_LIB=Off -DFLB_ALL=On -DFLB_DEBUG=On -DFLB_EXAMPLES=Off"
mkdir build
cd build
Write-Host cmake -G """$ENV:msvc""" -DCMAKE_BUILD_TYPE="$ENV:configuration" $GLOBAL_OPTS -DFLB_TESTS_INTERNAL=On -DCIO_BACKEND_FILESYSTEM=Off $SKIP ../
# Use Start-Process to pass 9 or more arguments
# TODO: Enable -DFLB_TESTS_RUNTIME=On
$build = Start-Process cmake -ArgumentList "-G ""$ENV:msvc"" -DCMAKE_BUILD_TYPE=""$ENV:configuration"" $GLOBAL_OPTS -DFLB_TESTS_INTERNAL=On -DCIO_BACKEND_FILESYSTEM=Off $SKIP ../" -NoNewWindow -PassThru
Wait-Process -InputObject $build
cmake --build .

ctest -C "$ENV:configuration" --build-run-dir $PWD --output-on-failure
