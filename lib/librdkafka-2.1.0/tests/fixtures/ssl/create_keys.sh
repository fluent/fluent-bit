#!/bin/sh
set -e
CA_PASSWORD="${CA_PASSWORD:-use_strong_password_ca}"
KEYSTORE_PASSWORD="${KEYSTORE_PASSWORD:-use_strong_password_keystore}"
TRUSTSTORE_PASSWORD="${TRUSTSTORE_PASSWORD:-use_strong_password_truststore}"
OUTPUT_FOLDER=${OUTPUT_FOLDER:-$( dirname "$0" )}
CNS=${@:-client}

cd ${OUTPUT_FOLDER}
CA_ROOT_KEY=caroot.key
CA_ROOT_CRT=caroot.crt

echo "# Generate CA"
openssl req -new -x509 -keyout $CA_ROOT_KEY \
    -out $CA_ROOT_CRT -days 3650 -subj \
    '/CN=caroot/OU=/O=/L=/ST=/C=' -passin "pass:${CA_PASSWORD}" \
    -passout "pass:${CA_PASSWORD}"

for CN in $CNS; do
    KEYSTORE=$CN.keystore.p12
    TRUSTSTORE=$CN.truststore.p12
    SIGNED_CRT=$CN-ca-signed.crt
    CERTIFICATE=$CN.certificate.pem
    KEY=$CN.key
    # Get specific password for this CN
    CN_KEYSTORE_PASSWORD="$(eval echo \$${CN}_KEYSTORE_PASSWORD)"
    if [ -z "$CN_KEYSTORE_PASSWORD" ]; then
        CN_KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD}_$CN
    fi

    echo ${CN_KEYSTORE_PASSWORD}

    echo "# $CN: Generate Keystore"
    keytool -genkey -noprompt \
        -alias $CN \
        -dname "CN=$CN,OU=,O=,L=,S=,C=" \
                        -ext "SAN=dns:$CN,dns:localhost" \
        -keystore $KEYSTORE \
        -keyalg RSA \
        -storepass "${CN_KEYSTORE_PASSWORD}" \
        -storetype pkcs12

    echo "# $CN: Generate Truststore"
    keytool -noprompt -keystore \
        $TRUSTSTORE -alias caroot -import \
        -file $CA_ROOT_CRT -storepass "${TRUSTSTORE_PASSWORD}"

    echo "# $CN: Generate CSR"
    keytool -keystore  $KEYSTORE -alias $CN \
        -certreq -file  $CN.csr -storepass "${CN_KEYSTORE_PASSWORD}" \
        -keypass "${CN_KEYSTORE_PASSWORD}" \
        -ext "SAN=dns:$CN,dns:localhost"

    echo "# $CN: Generate extfile"
    cat << EOF > extfile
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = $CN
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = $CN
DNS.2 = localhost
EOF

    echo "# $CN: Sign the certificate with the CA"
    openssl x509 -req -CA $CA_ROOT_CRT -CAkey $CA_ROOT_KEY \
        -in $CN.csr \
        -out $CN-ca-signed.crt -days 9999 \
        -CAcreateserial -passin "pass:${CA_PASSWORD}" \
        -extensions v3_req -extfile extfile

    echo "# $CN: Import root certificate"
    keytool -noprompt -keystore $KEYSTORE \
        -alias caroot -import -file $CA_ROOT_CRT -storepass "${CN_KEYSTORE_PASSWORD}"

    echo "# $CN: Import signed certificate"
    keytool -noprompt -keystore $KEYSTORE -alias $CN \
        -import -file $SIGNED_CRT -storepass "${CN_KEYSTORE_PASSWORD}" \
        -ext "SAN=dns:$CN,dns:localhost"

    echo "# $CN: Export PEM certificate"
    openssl pkcs12 -in "$KEYSTORE" -out "$CERTIFICATE" \
        -nodes -passin "pass:${CN_KEYSTORE_PASSWORD}"

    echo "# $CN: Export PEM key"
    openssl pkcs12 -in "$KEYSTORE" -out "$KEY" \
        -nocerts -passin "pass:${CN_KEYSTORE_PASSWORD}" \
        -passout "pass:${CN_KEYSTORE_PASSWORD}"
done
