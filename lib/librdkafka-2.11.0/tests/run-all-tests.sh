#!/bin/bash
set -e


# Helper script to run all tests through the CI
# Converts the environment variables to the test arguments
# with the following defaults:
#
# - plaintext connection
# - no authentication
# - KRaft enabled
# - all tests
# - default parallelism
# - no assertions
# - following AK and CP versions

export TEST_KAFKA_GIT_REF=${TEST_KAFKA_GIT_REF:-4.0.0}
export TEST_CP_VERSION=${TEST_CP_VERSION:-7.9.0}

TEST_SSL_ARG=""
TEST_SSL_INTERMEDIATE_CA_ARG=""
TEST_SASL_ARG=""
TEST_KRAFT_ARG="--kraft"
TEST_LOCAL_ARG=""
TEST_CONF_ARG=""
TEST_QUICK_ARG=""
TEST_ASSERT_ARG=""
TEST_PARALLEL_ARG=""
if [ "$TEST_SSL" = "True" ]; then
    TEST_SSL_ARG="--ssl"
fi
if [ "$TEST_SSL" = "True" -a "$TEST_SSL_INTERMEDIATE_CA" = "True" ]; then
    TEST_SSL_ARG="$TEST_SSL_ARG --ssl-intermediate-ca"
fi
if [ ! -z $TEST_SASL ]; then
    TEST_SASL_ARG="--sasl $TEST_SASL"
fi
if [ "$TEST_KRAFT" = "False" ]; then
    TEST_KRAFT_ARG=""
fi
if [ "$TEST_LOCAL" = "Local" ]; then
    TEST_LOCAL_ARG="-l"
fi
if [ "$TEST_LOCAL" = "Non-local" ]; then
    TEST_LOCAL_ARG="-L"
fi
if [ "$TEST_QUICK" = "True" ]; then
    TEST_QUICK_ARG="-Q"
fi
if [ "$TEST_ASSERT" = "True" ]; then
    TEST_ASSERT_ARG="-a"
fi
if [ ! -z $TEST_PARALLEL ]; then
    TEST_PARALLEL_ARG="-p$TEST_PARALLEL"
fi
if [ ! -z $TEST_CONF ]; then
    TEST_CONF_ARG="--conf '$TEST_CONF'"
fi
if [ ! -z $TEST_ENV_VARIABLES ]; then
    IFS=',' read -ra TEST_ENV_VARIABLES_ARRAY <<< "$TEST_ENV_VARIABLES"
    for TEST_ENV_VARIABLE in "${TEST_ENV_VARIABLES_ARRAY[@]}"; do
        export "$TEST_ENV_VARIABLE"
    done
    unset TEST_ENV_VARIABLES_ARRAY
fi

TEST_ARGS="$TEST_PARALLEL_ARG $TEST_ASSERT_ARG $TEST_QUICK_ARG $TEST_LOCAL_ARG $TEST_RUNNER_PARAMETERS $TEST_MODE"
TEST_CONFIGURATION="$TEST_SSL_ARG $TEST_SASL_ARG $TEST_KRAFT_ARG $TEST_CONF_ARG $TEST_TRIVUP_PARAMETERS"

echo "Running tests with:"
echo "kafka branch: $TEST_KAFKA_GIT_REF"
echo "kafka version: $TEST_KAFKA_VERSION"
echo "CP version: $TEST_CP_VERSION"
echo "configuration: $TEST_CONFIGURATION"
echo "arguments: $TEST_ARGS"
(cd tests && python3 -m trivup.clusters.KafkaCluster $TEST_CONFIGURATION \
--version "$TEST_KAFKA_GIT_REF" \
--cpversion "$TEST_CP_VERSION" \
--cmd "python run-test-batches.py $TEST_ARGS")
