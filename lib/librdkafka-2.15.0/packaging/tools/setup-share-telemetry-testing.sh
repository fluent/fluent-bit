#!/bin/bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
VERIFY_DIR=${ROOT}/tests/share_telemetry_verify
WORK_DIR=${VERIFY_DIR}/.work

KAFKA_VERSION=${KAFKA_VERSION:-4.2.0}
KAFKA_DIR=${WORK_DIR}/kafka_2.13-${KAFKA_VERSION}
KAFKA_DATA=${WORK_DIR}/kafka-data
TUTORIALS_REPO=${WORK_DIR}/tutorials
PLUGIN_JAR=${WORK_DIR}/client-telemetry-reporter-plugin.jar

export TELEMETRY_TOPIC=${TELEMETRY_TOPIC:-client-telemetry-metrics}
SUBSCRIPTION_NAME=share-consumer-ci

mkdir -p ${WORK_DIR}

if [ ! -f "${PLUGIN_JAR}" ]; then
    echo "==> Building OTLP reporter plugin"
    if [ ! -d "${TUTORIALS_REPO}" ]; then
        git clone --depth 1 https://github.com/confluentinc/tutorials.git ${TUTORIALS_REPO}
    fi
    sed -i.bak \
        "s|id 'com.github.johnrengelman.shadow' version '8.1.1'|id 'com.gradleup.shadow' version '8.3.6'|" \
        ${TUTORIALS_REPO}/client-telemetry-reporter-plugin/kafka/build.gradle
    (cd ${TUTORIALS_REPO} && ./gradlew --no-daemon clean \
        :client-telemetry-reporter-plugin:kafka:build)
    cp ${TUTORIALS_REPO}/client-telemetry-reporter-plugin/kafka/build/libs/client-telemetry-reporter-plugin.jar \
        ${PLUGIN_JAR}
fi

if [ ! -d "${KAFKA_DIR}" ]; then
    echo "==> Setting up Kafka broker ${KAFKA_VERSION}"
    wget -q https://downloads.apache.org/kafka/${KAFKA_VERSION}/kafka_2.13-${KAFKA_VERSION}.tgz \
        -O ${WORK_DIR}/kafka.tgz
    tar -C ${WORK_DIR} -xzf ${WORK_DIR}/kafka.tgz

    SP=${KAFKA_DIR}/config/server.properties
    sed -i.bak \
        -e 's|^listeners=PLAINTEXT://:9092,CONTROLLER://:9093|listeners=PLAINTEXT://:9092,DOCKER://:19092,CONTROLLER://:9093|' \
        -e 's|^advertised.listeners=PLAINTEXT://localhost:9092,CONTROLLER://localhost:9093|advertised.listeners=PLAINTEXT://localhost:9092,DOCKER://host.docker.internal:19092,CONTROLLER://localhost:9093|' \
        -e 's|^listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,SSL:SSL,SASL_PLAINTEXT:SASL_PLAINTEXT,SASL_SSL:SASL_SSL|listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,DOCKER:PLAINTEXT,SSL:SSL,SASL_PLAINTEXT:SASL_PLAINTEXT,SASL_SSL:SASL_SSL|' \
        -e "s|^log.dirs=/tmp/kraft-combined-logs|log.dirs=${KAFKA_DATA}|" \
        ${SP}
    echo 'metric.reporters=io.confluent.developer.ClientOtlpMetricsReporter' >> ${SP}

    cp ${PLUGIN_JAR} ${KAFKA_DIR}/libs/
fi

echo "==> Formatting fresh broker storage"
rm -rf ${KAFKA_DATA}
mkdir -p ${KAFKA_DATA}
CLUSTER_ID=$(${KAFKA_DIR}/bin/kafka-storage.sh random-uuid)
${KAFKA_DIR}/bin/kafka-storage.sh format --standalone \
    -t ${CLUSTER_ID} -c ${KAFKA_DIR}/config/server.properties

TEST_CONF_BAK=${ROOT}/tests/test.conf.bak.$$
LOG_DIR=${ROOT}/artifacts
cleanup() {
    local rc=$?
    set +e
    mkdir -p ${LOG_DIR}
    docker logs otel-collector > ${LOG_DIR}/otel-collector.log 2>&1 || true
    if [ -f ${KAFKA_DIR}/logs/server.log ]; then
        cp ${KAFKA_DIR}/logs/server.log ${LOG_DIR}/kafka-server.log
    fi
    ${KAFKA_DIR}/bin/kafka-server-stop.sh 2>/dev/null
    docker stop otel-collector 2>/dev/null
    docker rm otel-collector 2>/dev/null
    if [ -f "${TEST_CONF_BAK}" ]; then
        mv ${TEST_CONF_BAK} ${ROOT}/tests/test.conf
    fi
    exit ${rc}
}
trap cleanup EXIT

echo "==> Starting OpenTelemetry Collector"
docker rm -f otel-collector 2>/dev/null || true
docker run -d --name otel-collector \
    --add-host=host.docker.internal:host-gateway \
    -e TELEMETRY_TOPIC=${TELEMETRY_TOPIC} \
    -p 4317:4317 \
    -v ${VERIFY_DIR}/share-otel-collector-config.yaml:/etc/otelcol-contrib/config.yaml \
    otel/opentelemetry-collector-contrib

echo "==> Starting Kafka broker"
OTEL_EXPORTER_OTLP_ENDPOINT=127.0.0.1:4317 \
    ${KAFKA_DIR}/bin/kafka-server-start.sh -daemon \
    ${KAFKA_DIR}/config/server.properties

BROKER_UP=0
for i in $(seq 1 60); do
    if ${KAFKA_DIR}/bin/kafka-broker-api-versions.sh \
        --bootstrap-server localhost:9092 > /dev/null 2>&1; then
        BROKER_UP=1
        break
    fi
    sleep 1
done

if [ ${BROKER_UP} -eq 0 ]; then
    echo "ERROR: Kafka broker did not come up within 60s on localhost:9092"
    echo "  see kafka-server.log (uploaded as artifact) for details"
    exit 1
fi

echo "==> Creating telemetry sink topic and metrics subscription"
${KAFKA_DIR}/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create \
    --topic ${TELEMETRY_TOPIC} --partitions 1 --replication-factor 1 --if-not-exists
${KAFKA_DIR}/bin/kafka-client-metrics.sh --bootstrap-server localhost:9092 --alter \
    --name ${SUBSCRIPTION_NAME} \
    --metrics "org.apache.kafka.consumer.share." \
    --interval 5000

echo "==> Building librdkafka"
(cd ${ROOT} && ./configure --install-deps --enable-werror --enable-devel)
make -j -C ${ROOT}
make -j -C ${ROOT}/tests build

if [ -f ${ROOT}/tests/test.conf ]; then
    cp ${ROOT}/tests/test.conf ${TEST_CONF_BAK}
fi
cat > ${ROOT}/tests/test.conf <<'EOF'
metadata.broker.list=localhost:9092
security.protocol=plaintext
enable.metrics.push=true
EOF

echo "==> Pre-test infra sanity check"
if ! ${KAFKA_DIR}/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
        --describe --topic ${TELEMETRY_TOPIC} > /dev/null 2>&1; then
    echo "ERROR: telemetry topic '${TELEMETRY_TOPIC}' missing or broker unreachable"
    echo "  broker may have died during the build phase"
    echo "  see kafka-server.log / otel-collector.log artifacts"
    exit 1
fi

echo "==> Running share consumer telemetry test (0190)"
(cd ${ROOT}/tests && TESTS=0190 ./run-test.sh)
