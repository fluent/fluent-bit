#!/bin/sh
set -e
CA_PASSWORD="${CA_PASSWORD:-use_strong_password_ca}"
CA_INTERMEDIATE_PASSWORD="${CA_INTERMEDIATE_PASSWORD:-use_strong_password_intermediate_ca}"
KEYSTORE_PASSWORD="${KEYSTORE_PASSWORD:-use_strong_password_keystore}"
TRUSTSTORE_PASSWORD="${TRUSTSTORE_PASSWORD:-use_strong_password_truststore}"
OUTPUT_FOLDER=${OUTPUT_FOLDER:-$( dirname "$0" )}
CNS=${@:-client}

cd ${OUTPUT_FOLDER}
CA_ROOT_KEY=${CA_ROOT_KEY:-caroot.key}
CA_ROOT_CRT=${CA_ROOT_CRT:-caroot.crt}
CA_INTERMEDIATE_KEY=intermediate.key
CA_INTERMEDIATE_CSR=intermediate.csr
CA_INTERMEDIATE_CRT=intermediate.crt

generate_ca_extfile() {
echo "# $1: Generate extfile"
cat << EOF > extfile
[req]
distinguished_name=dn
[ dn ]
CN=$1
[ ext ]
basicConstraints=CA:TRUE,pathlen:0
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always, issuer:always
keyUsage                = critical, cRLSign, digitalSignature, keyCertSign
extendedKeyUsage        = clientAuth
EOF
}

generate_client_certificate_extfile() {
local CN=$1
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
}

if [ ! -f $CA_ROOT_KEY -o ! -f $CA_ROOT_CRT ]; then
    echo "# Generate CA"
    generate_ca_extfile caroot
    openssl req -new -x509 -config extfile -keyout $CA_ROOT_KEY \
        -out $CA_ROOT_CRT -subj \
        '/CN=caroot/OU=/O=/L=/ST=/C=' -passin "pass:${CA_PASSWORD}" \
        -passout "pass:${CA_PASSWORD}"
fi

echo "# caintermediate: Generate CSR"
openssl req -new -keyout $CA_INTERMEDIATE_KEY \
    -out $CA_INTERMEDIATE_CSR -subj \
    '/CN=caintermediate/OU=/O=/L=/ST=/C=' \
    -passin "pass:${CA_INTERMEDIATE_PASSWORD}" \
    -passout "pass:${CA_INTERMEDIATE_PASSWORD}"

generate_ca_extfile caintermediate

echo "# caintermediate: Sign request"
openssl x509 -req -extfile extfile \
-passin "pass:${CA_PASSWORD}" \
-in "${CA_INTERMEDIATE_CSR}" \
-CA "${CA_ROOT_CRT}" \
-CAkey "${CA_ROOT_KEY}" \
-days 3650 \
-out "${CA_INTERMEDIATE_CRT}"

for CN in $CNS; do
for INTERMEDIATE in true false; do
    INTERMEDIATE_PREFIX=""
    if [ $INTERMEDIATE = "true" ]; then
        INTERMEDIATE_PREFIX=".intermediate"
    fi

    KEYSTORE=${CN}.keystore${INTERMEDIATE_PREFIX}.p12
    TRUSTSTORE=${CN}.truststore${INTERMEDIATE_PREFIX}.p12
    CSR=${CN}${INTERMEDIATE_PREFIX}.csr
    SIGNED_CRT=${CN}-ca-signed${INTERMEDIATE_PREFIX}.crt
    CERTIFICATE=${CN}.certificate${INTERMEDIATE_PREFIX}.pem
    KEY=${CN}${INTERMEDIATE_PREFIX}.key
    # Get specific password for this CN
    CN_KEYSTORE_PASSWORD="$(eval echo \$${CN}_KEYSTORE_PASSWORD)"
    if [ -z "$CN_KEYSTORE_PASSWORD" ]; then
        CN_KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD}_$CN
    fi

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
        -certreq -file $CSR -storepass "${CN_KEYSTORE_PASSWORD}" \
        -keypass "${CN_KEYSTORE_PASSWORD}" \
        -ext "SAN=dns:$CN,dns:localhost"

    generate_client_certificate_extfile $CN

    echo "# $CN: Import root certificate"
    keytool -noprompt -keystore $KEYSTORE \
        -alias caroot -import -file $CA_ROOT_CRT -storepass "${CN_KEYSTORE_PASSWORD}"

    if [ $INTERMEDIATE = "true" ]; then
        echo "# $CN: Sign the certificate with the intermediate CA"
        openssl x509 -req -CA $CA_INTERMEDIATE_CRT -CAkey $CA_INTERMEDIATE_KEY \
            -in $CSR \
            -out $SIGNED_CRT -days 9999 \
            -CAcreateserial -passin "pass:${CA_INTERMEDIATE_PASSWORD}" \
            -extensions v3_req -extfile extfile

        echo "# $CN: Import intermediate CA certificate"
        keytool -noprompt -keystore $KEYSTORE \
            -alias caintermediate -import -file $CA_INTERMEDIATE_CRT \
            -storepass "${CN_KEYSTORE_PASSWORD}"
    else
        echo "# $CN: Sign the certificate with the CA"
        openssl x509 -req -CA $CA_ROOT_CRT -CAkey $CA_ROOT_KEY \
            -in $CSR \
            -out $SIGNED_CRT -days 9999 \
            -CAcreateserial -passin "pass:${CA_PASSWORD}" \
            -extensions v3_req -extfile extfile
    fi

    echo "# $CN: Import signed certificate"
    keytool -noprompt -keystore $KEYSTORE -alias $CN \
        -import -file $SIGNED_CRT -storepass "${CN_KEYSTORE_PASSWORD}" \
        -ext "SAN=dns:$CN,dns:localhost"

    # Delete imported certificates as they were only used to import the 
    # signed certificate.
    keytool -delete -alias caroot -keystore $KEYSTORE \
        -storepass "${CN_KEYSTORE_PASSWORD}"
    if [ $INTERMEDIATE = "true" ]; then
        keytool -delete -alias caintermediate -keystore $KEYSTORE \
            -storepass "${CN_KEYSTORE_PASSWORD}"
    fi

    echo "# $CN: Export PEM certificate"
    openssl pkcs12 -in "$KEYSTORE" -out "$CERTIFICATE" \
        -nokeys -passin "pass:${CN_KEYSTORE_PASSWORD}"

    echo "# $CN: Export PEM key"
    openssl pkcs12 -in "$KEYSTORE" -out "$KEY" \
        -nocerts -passin "pass:${CN_KEYSTORE_PASSWORD}" \
        -passout "pass:${CN_KEYSTORE_PASSWORD}"
done
done
