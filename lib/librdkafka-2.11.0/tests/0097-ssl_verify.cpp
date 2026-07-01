/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019-2022, Magnus Edenhill
 *               2025, Confluent Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <streambuf>
#include "testcpp.h"
#include "tinycthread.h"

namespace TestSSLVerify {

static const std::string envname[RdKafka::CERT__CNT][RdKafka::CERT_ENC__CNT] = {
    /* [RdKafka::CERT_PUBLIC_KEY] = */
    {
        "SSL_pkcs",
        "SSL_pub_der",
        "SSL_pub_pem",
    },
    /* [RdKafka::CERT_PRIVATE_KEY] = */
    {
        "SSL_pkcs",
        "SSL_priv_der",
        "SSL_priv_pem",
    },
    /* [RdKafka::CERT_CA] = */
    {
        "SSL_pkcs",
        "SSL_ca_der",
        "SSL_all_cas_pem" /* Contains multiple CA certs */,
    }};


static std::vector<char> read_file(const std::string path) {
  std::ifstream ifs(path.c_str(), std::ios::binary | std::ios::ate);
  if (ifs.fail())
    Test::Fail("Failed to open " + path + ": " + strerror(errno));
  int size = (int)ifs.tellg();
  ifs.seekg(0, std::ifstream::beg);
  std::vector<char> buffer;
  buffer.resize(size);
  ifs.read(buffer.data(), size);
  ifs.close();
  return buffer;
}


/**
 * @name SslCertVerifyCb verification.
 *
 * Requires security.protocol=*SSL
 */

class TestVerifyCb : public RdKafka::SslCertificateVerifyCb {
 public:
  bool verify_ok;
  int cnt;  //< Verify callbacks triggered.
  mtx_t lock;

  TestVerifyCb(bool verify_ok) : verify_ok(verify_ok), cnt(0) {
    mtx_init(&lock, mtx_plain);
  }

  ~TestVerifyCb() {
    mtx_destroy(&lock);
  }

  bool ssl_cert_verify_cb(const std::string &broker_name,
                          int32_t broker_id,
                          int *x509_error,
                          int depth,
                          const char *buf,
                          size_t size,
                          std::string &errstr) {
    mtx_lock(&lock);

    Test::Say(tostr() << "ssl_cert_verify_cb #" << cnt << ": broker_name="
                      << broker_name << ", broker_id=" << broker_id
                      << ", x509_error=" << *x509_error << ", depth=" << depth
                      << ", buf size=" << size << ", verify_ok=" << verify_ok
                      << "\n");

    cnt++;
    mtx_unlock(&lock);

    if (verify_ok)
      return true;

    errstr      = "This test triggered a verification failure";
    *x509_error = 26; /*X509_V_ERR_INVALID_PURPOSE*/

    return false;
  }
};

/**
 * @name Test event callback.
 */
class TestEventCb : public RdKafka::EventCb {
 public:
  bool should_succeed;

  TestEventCb(bool should_succeed) : should_succeed(should_succeed) {
  }

  void event_cb(RdKafka::Event &event) {
    switch (event.type()) {
    case RdKafka::Event::EVENT_LOG:
      Test::Say("Log: " + event.str() + "\n");
      break;
    case RdKafka::Event::EVENT_ERROR:
      if (should_succeed)
        Test::Fail("Unexpected error event, got: " + event.str());
      else if (event.err() != RdKafka::ERR__SSL &&
               event.err() != RdKafka::ERR__ALL_BROKERS_DOWN)
        Test::Fail(
            "Expected _SSL or _ALL_BROKERS_DOWN error codes"
            ", got: " +
            RdKafka::err2str(event.err()));
      else if (event.err() == RdKafka::ERR__SSL) {
        bool expected = false;
        Test::Say("SSL error: " + event.str() + "\n");
        if (event.str().find("alert number 42") != std::string::npos)
          /* Verify that certificate isn't sent if not trusted
           * by the broker. We should receive 42 (bad_certificate)
           * instead of 46 (certificate_unknown). */
          expected = true;
        else if (event.str().find("broker certificate could not be verified") !=
                 std::string::npos)
          expected = true;

        if (!expected)
          Test::Fail("Unexpected SSL error message, got: " + event.str());
      }
      break;
    default:
      break;
    }
  }
};

/**
 * @brief Set SSL PEM cert/key using configuration property.
 *
 * The cert/key is loadded from environment variables set up by trivup.
 *
 * @param loc_prop ssl.X.location property that will be cleared.
 * @param pem_prop ssl.X.pem property that will be set.
 * @param cert_type Certificate type.
 * @param use_conf_value_file Read the file from existing configuration value,
 *                            instead of the one in the environment variable.
 */
static void conf_location_to_pem(RdKafka::Conf *conf,
                                 std::string loc_prop,
                                 std::string pem_prop,
                                 RdKafka::CertificateType cert_type,
                                 bool use_conf_value_file) {
  std::string loc;

  std::string errstr;
  if (use_conf_value_file && conf->get(loc_prop, loc) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to get " + loc_prop);
  if (conf->set(loc_prop, "", errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to reset " + loc_prop + ": " + errstr);

  if (!use_conf_value_file) {
    const char *p;
    p = test_getenv(envname[cert_type][RdKafka::CERT_ENC_PEM].c_str(), NULL);
    if (!p)
      Test::Fail(
          "Invalid test environment: "
          "Missing " +
          envname[cert_type][RdKafka::CERT_ENC_PEM] +
          " env variable: make sure trivup is up to date");

    loc = p;
  }

  /* Read file */
  std::ifstream ifs(loc.c_str());
  std::string pem((std::istreambuf_iterator<char>(ifs)),
                  std::istreambuf_iterator<char>());

  Test::Say("Read " + loc + " from disk and changed to in-memory " + pem_prop +
            " string\n");

  if (conf->set(pem_prop, pem, errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to set " + pem_prop + ": " + errstr);
}

/**
 * @brief Set SSL cert/key using set_ssl_cert() rather than
 *        config string property \p loc_prop (which will be cleared)
 *
 * @remark Requires a bunch of SSL_.. env vars to point out where
 *         certs are found. These are set up by trivup.
 */
static void conf_location_to_setter(RdKafka::Conf *conf,
                                    std::string loc_prop,
                                    RdKafka::CertificateType cert_type,
                                    RdKafka::CertificateEncoding encoding,
                                    bool use_conf_value_file) {
  std::string loc;
  static const std::string encnames[] = {
      "PKCS#12",
      "DER",
      "PEM",
  };

  /* Clear the config property (e.g., ssl.key.location) */
  std::string errstr;
  if (use_conf_value_file && conf->get(loc_prop, loc) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to get " + loc_prop);
  if (conf->set(loc_prop, "", errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to reset " + loc_prop);

  if (!use_conf_value_file) {
    const char *p;
    p = test_getenv(envname[cert_type][encoding].c_str(), NULL);
    if (!p)
      Test::Fail(
          "Invalid test environment: "
          "Missing " +
          envname[cert_type][encoding] +
          " env variable: make sure trivup is up to date");

    loc = p;
  }

  Test::Say(tostr() << "Reading file as " << encnames[encoding] << " from "
                    << loc << "\n");

  /* Read file */
  std::ifstream ifs(loc.c_str(), std::ios::binary | std::ios::ate);
  if (ifs.fail())
    Test::Fail("Failed to open " + loc + ": " + strerror(errno));
  int size = (int)ifs.tellg();
  ifs.seekg(0, std::ifstream::beg);
  std::vector<char> buffer;
  buffer.resize(size);
  ifs.read(buffer.data(), size);
  ifs.close();

  if (conf->set_ssl_cert(cert_type, encoding, buffer.data(), size, errstr) !=
      RdKafka::Conf::CONF_OK)
    Test::Fail(tostr() << "Failed to set " << loc_prop << " from " << loc
                       << " as cert type " << cert_type << " with encoding "
                       << encoding << ": " << errstr << "\n");
}


typedef enum {
  USE_LOCATION, /* use ssl.X.location */
  USE_CONF,     /* use ssl.X.pem */
  USE_SETTER,   /* use conf->set_ssl_cert(), this supports multiple formats */
} cert_load_t;

static const std::string load_names[] = {
    "location",
    "conf",
    "setter",
};

static bool is_client_auth_required() {
  const char *C_client_auth = test_getenv("SSL_client_auth", "required");
  std::string client_auth(C_client_auth);
  return client_auth == "required";
}

/**
 * @brief Test SSL certificate verification.
 *
 * @param line Test line number.
 * @param verify_ok Expected verification result.
 * @param untrusted_client_key Set up an untrusted client key.
 * @param untrusted_client_key_intermediate_ca The untrusted client key is
 *                                             signed by an intermediate CA.
 * @param load_key How to load the client key.
 * @param key_enc Encoding of the client key.
 * @param load_pub How to load the client public key.
 * @param pub_enc Encoding of the client public key.
 * @param load_ca How to load the CA.
 * @param ca_enc Encoding of the CA.
 */
static void do_test_verify(const int line,
                           bool verify_ok,
                           bool untrusted_client_key,
                           bool untrusted_client_key_intermediate_ca,
                           cert_load_t load_key,
                           RdKafka::CertificateEncoding key_enc,
                           cert_load_t load_pub,
                           RdKafka::CertificateEncoding pub_enc,
                           cert_load_t load_ca,
                           RdKafka::CertificateEncoding ca_enc) {
#define TEST_FIXTURES_FOLDER       "./fixtures"
#define TEST_FIXTURES_SSL_FOLDER   TEST_FIXTURES_FOLDER "/ssl/"
#define TEST_FIXTURES_KEY_PASSWORD "use_strong_password_keystore_client2"

/* Certificate directly signed by the root CA (untrusted) */
#define TEST_CERTIFICATE_LOCATION                                              \
  TEST_FIXTURES_SSL_FOLDER "client2.certificate.pem"
#define TEST_KEY_LOCATION TEST_FIXTURES_SSL_FOLDER "client2.key"

/* Certificate signed by an intermediate CA (untrusted) */
#define TEST_CERTIFICATE_INTERMEDIATE_LOCATION                                 \
  TEST_FIXTURES_SSL_FOLDER "client2.certificate.intermediate.pem"
#define TEST_KEY_INTERMEDIATE_LOCATION                                         \
  TEST_FIXTURES_SSL_FOLDER "client2.intermediate.key"

  std::string errstr, existing_key_password;
  /*
   * Create any type of client
   */
  std::string teststr =
      tostr() << line << ": " << "SSL cert verify: verify_ok=" << verify_ok
              << ", untrusted_client_key=" << untrusted_client_key
              << ", untrusted_client_key_intermediate_ca="
              << untrusted_client_key_intermediate_ca
              << ", load_key=" << load_names[load_key]
              << ", load_pub=" << load_names[load_pub]
              << ", load_ca=" << load_names[load_ca];

  Test::Say(_C_BLU "[ " + teststr + " ]\n" _C_CLR);

  RdKafka::Conf *conf;
  std::string security_protocol;
  Test::conf_init(&conf, NULL, 10);
  if (conf->get("security.protocol", security_protocol) !=
      RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to get security.protocol");
  /* sasl_ssl endpoints don't require
   * SSL authentication even when
   * ssl.client.auth=required */
  bool should_succeed =
      verify_ok && (!untrusted_client_key || !is_client_auth_required() ||
                    security_protocol != "ssl");
  TestEventCb eventCb(should_succeed);

  if (conf->set("event_cb", &eventCb, errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to set event_cb: " + errstr);

  if (untrusted_client_key) {
    /* Set an untrusted certificate, signed by a root CA or by an
     * intermediate CA, and verify client authentication fails. */

    const char *untrusted_key_location = untrusted_client_key_intermediate_ca
                                             ? TEST_KEY_INTERMEDIATE_LOCATION
                                             : TEST_KEY_LOCATION;
    const char *untrusted_certificate_location =
        untrusted_client_key_intermediate_ca
            ? TEST_CERTIFICATE_INTERMEDIATE_LOCATION
            : TEST_CERTIFICATE_LOCATION;

    if (conf->set("ssl.key.location", untrusted_key_location, errstr) !=
        RdKafka::Conf::CONF_OK)
      Test::Fail("Failed to set untrusted ssl.key.location: " + errstr);

    if (conf->get("ssl.key.password", existing_key_password) !=
        RdKafka::Conf::CONF_OK)
      Test::Fail("Failed to get existing ssl.key.password: " + errstr);
    if (conf->set("ssl.key.password", TEST_FIXTURES_KEY_PASSWORD, errstr) !=
        RdKafka::Conf::CONF_OK)
      Test::Fail("Failed to set untrusted ssl.key.password: " + errstr);

    if (conf->set("ssl.certificate.location", untrusted_certificate_location,
                  errstr) != RdKafka::Conf::CONF_OK)
      Test::Fail("Failed to set untrusted ssl.certificate.location: " + errstr);
  }

  std::string val;
  if (conf->get("ssl.key.location", val) != RdKafka::Conf::CONF_OK ||
      val.empty()) {
    Test::Skip("Test requires SSL to be configured\n");
    delete conf;
    return;
  }

  /* Get ssl.key.location, read its contents, and replace with
   * ssl.key.pem. Same with ssl.certificate.location -> ssl.certificate.pem. */
  if (load_key == USE_CONF)
    conf_location_to_pem(conf, "ssl.key.location", "ssl.key.pem",
                         RdKafka::CERT_PRIVATE_KEY, true);
  else if (load_key == USE_SETTER)
    conf_location_to_setter(conf, "ssl.key.location", RdKafka::CERT_PRIVATE_KEY,
                            key_enc, key_enc == RdKafka::CERT_ENC_PEM);

  if (load_pub == USE_CONF)
    conf_location_to_pem(conf, "ssl.certificate.location",
                         "ssl.certificate.pem", RdKafka::CERT_PUBLIC_KEY, true);
  else if (load_pub == USE_SETTER)
    conf_location_to_setter(conf, "ssl.certificate.location",
                            RdKafka::CERT_PUBLIC_KEY, pub_enc,
                            pub_enc == RdKafka::CERT_ENC_PEM);

  if (untrusted_client_key && ca_enc != RdKafka::CERT_ENC_PEM) {
    /* Original password is needed for reading the
     * CA certificate in the PKCS12 keystore. */
    if (conf->set("ssl.key.password", existing_key_password, errstr) !=
        RdKafka::Conf::CONF_OK)
      Test::Fail("Failed to revert to existing ssl.key.password: " + errstr);
  }

  if (load_ca == USE_CONF)
    conf_location_to_pem(conf, "ssl.ca.location", "ssl.ca.pem",
                         RdKafka::CERT_CA, true);
  else if (load_ca == USE_SETTER)
    conf_location_to_setter(conf, "ssl.ca.location", RdKafka::CERT_CA, ca_enc,
                            ca_enc == RdKafka::CERT_ENC_PEM);

  conf->set("debug", "security", errstr);
  TestVerifyCb verifyCb(verify_ok);
  if (conf->set("ssl_cert_verify_cb", &verifyCb, errstr) !=
      RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to set verifyCb: " + errstr);

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create producer: " + errstr);
  delete conf;

  bool run = true;
  for (int i = 0; run && i < 10; i++) {
    p->poll(1000);

    mtx_lock(&verifyCb.lock);
    if ((verify_ok && verifyCb.cnt > 0) || (!verify_ok && verifyCb.cnt > 3))
      run = false;
    mtx_unlock(&verifyCb.lock);
  }

  mtx_lock(&verifyCb.lock);
  if (!verifyCb.cnt)
    Test::Fail("Expected at least one verifyCb invocation");
  mtx_unlock(&verifyCb.lock);

  /* Retrieving the clusterid allows us to easily check if a
   * connection could be made. Match this to the expected outcome of
   * this test. */
  std::string cluster = p->clusterid(1000);

  if (should_succeed == cluster.empty())
    Test::Fail("Expected connection to " +
               (std::string)(should_succeed ? "succeed" : "fail") +
               ", but got clusterid '" + cluster + "'");

  delete p;

  Test::Say(_C_GRN "[ PASSED: " + teststr + " ]\n" _C_CLR);
}


/**
 * @brief Verification that some bad combinations of calls behave as expected.
 *        This is simply to verify #2904.
 */
static void do_test_bad_calls() {
  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

  std::string errstr;

  if (conf->set("enable.ssl.certificate.verification", "false", errstr))
    Test::Fail(errstr);

  if (conf->set("security.protocol", "SSL", errstr))
    Test::Fail(errstr);

  if (conf->set("ssl.key.password", test_getenv("SSL_password", NULL), errstr))
    Test::Fail(errstr);

  std::vector<char> certBuffer = read_file(test_getenv(
      envname[RdKafka::CERT_CA][RdKafka::CERT_ENC_PEM].c_str(), NULL));

  if (conf->set_ssl_cert(RdKafka::CERT_CA, RdKafka::CERT_ENC_PEM,
                         certBuffer.data(), certBuffer.size(), errstr))
    Test::Fail(errstr);

  /* Set public-key as CA (over-writing the previous one) */
  std::vector<char> userBuffer = read_file(test_getenv(
      envname[RdKafka::CERT_PUBLIC_KEY][RdKafka::CERT_ENC_PEM].c_str(), NULL));

  if (conf->set_ssl_cert(RdKafka::CERT_CA, RdKafka::CERT_ENC_PEM,
                         userBuffer.data(), userBuffer.size(), errstr))
    Test::Fail(errstr);

  std::vector<char> keyBuffer = read_file(test_getenv(
      envname[RdKafka::CERT_PRIVATE_KEY][RdKafka::CERT_ENC_PEM].c_str(), NULL));

  if (conf->set_ssl_cert(RdKafka::CERT_PRIVATE_KEY, RdKafka::CERT_ENC_PEM,
                         keyBuffer.data(), keyBuffer.size(), errstr))
    Test::Fail(errstr);

  // Create Kafka producer
  RdKafka::Producer *producer = RdKafka::Producer::create(conf, errstr);
  delete conf;
  if (producer)
    Test::Fail("Expected producer creation to fail");

  if (errstr.find("Private key check failed") == std::string::npos)
    Test::Fail("Expected 'Private key check failed' error, not " + errstr);

  Test::Say("Producer creation failed expectedly: " + errstr + "\n");
}

}  // namespace TestSSLVerify

using namespace TestSSLVerify;

extern "C" {

/**
 * @brief Test SSL certificate verification with various
 *        key types and trusted or untrusted client certificates.
 *
 * @remark This tests can be run with a root CA signed certificate
 *         when trivup is started with "--ssl" only,
 *         or with an intermediate CA signed certificate,
 *         when trivup is started with:
 *         --conf='{"ssl_intermediate_ca": true}'
 *         or with "ssl.client.auth=requested" when started with:
 *         --conf='{"ssl_client_auth": "requested"}'
 *         or a combination of both.
 */
int main_0097_ssl_verify(int argc, char **argv) {
  int untrusted_client_key, untrusted_client_key_intermediate_ca;
  if (!test_check_builtin("ssl")) {
    Test::Skip("Test requires SSL support\n");
    return 0;
  }

  if (!test_getenv("SSL_pkcs", NULL)) {
    Test::Skip("Test requires SSL_* env-vars set up by trivup\n");
    return 0;
  }


  do_test_bad_calls();

  for (untrusted_client_key = 0; untrusted_client_key <= 1;
       untrusted_client_key++) {
    for (untrusted_client_key_intermediate_ca = 0;
         untrusted_client_key_intermediate_ca <= untrusted_client_key;
         untrusted_client_key_intermediate_ca++) {
      do_test_verify(__LINE__, true /*verify ok*/, untrusted_client_key,
                     untrusted_client_key_intermediate_ca, USE_LOCATION,
                     RdKafka::CERT_ENC_PEM, USE_LOCATION, RdKafka::CERT_ENC_PEM,
                     USE_LOCATION, RdKafka::CERT_ENC_PEM);
      do_test_verify(__LINE__, false /*verify not ok*/, untrusted_client_key,
                     untrusted_client_key_intermediate_ca, USE_LOCATION,
                     RdKafka::CERT_ENC_PEM, USE_LOCATION, RdKafka::CERT_ENC_PEM,
                     USE_LOCATION, RdKafka::CERT_ENC_PEM);

      /* Verify various priv and pub key and CA input formats */
      do_test_verify(__LINE__, true /*verify ok*/, untrusted_client_key,
                     untrusted_client_key_intermediate_ca, USE_CONF,
                     RdKafka::CERT_ENC_PEM, USE_CONF, RdKafka::CERT_ENC_PEM,
                     USE_LOCATION, RdKafka::CERT_ENC_PEM);
      do_test_verify(__LINE__, true /*verify ok*/, untrusted_client_key,
                     untrusted_client_key_intermediate_ca, USE_CONF,
                     RdKafka::CERT_ENC_PEM, USE_CONF, RdKafka::CERT_ENC_PEM,
                     USE_CONF, RdKafka::CERT_ENC_PEM);
      do_test_verify(__LINE__, true /*verify ok*/, untrusted_client_key,
                     untrusted_client_key_intermediate_ca, USE_SETTER,
                     RdKafka::CERT_ENC_PEM, USE_SETTER, RdKafka::CERT_ENC_PEM,
                     USE_SETTER, RdKafka::CERT_ENC_PKCS12);
    }
  }

  if (test_getenv("SSL_intermediate_pub_pem", NULL) == NULL) {
    Test::Say("Running root CA only tests\n");
    /* DER format can contain only a single certificate so it's
     * not suited for sending the complete chain of trust
     * corresponding to the private key,
     * that is necessary when using an intermediate CA. */
    do_test_verify(__LINE__, true /*verify ok*/, false, false, USE_LOCATION,
                   RdKafka::CERT_ENC_PEM, USE_SETTER, RdKafka::CERT_ENC_DER,
                   USE_SETTER, RdKafka::CERT_ENC_DER);
    do_test_verify(__LINE__, true /*verify ok*/, false, false, USE_LOCATION,
                   RdKafka::CERT_ENC_PEM, USE_SETTER, RdKafka::CERT_ENC_DER,
                   USE_SETTER,
                   RdKafka::CERT_ENC_PEM); /* env: SSL_all_cas_pem */
    do_test_verify(__LINE__, true /*verify ok*/, false, false, USE_LOCATION,
                   RdKafka::CERT_ENC_PEM, USE_SETTER, RdKafka::CERT_ENC_DER,
                   USE_CONF, RdKafka::CERT_ENC_PEM); /* env: SSL_all_cas_pem */
    Test::Say("Finished running root CA only tests\n");
  }

  do_test_verify(__LINE__, true /*verify ok*/, false, false, USE_SETTER,
                 RdKafka::CERT_ENC_PKCS12, USE_SETTER, RdKafka::CERT_ENC_PKCS12,
                 USE_SETTER, RdKafka::CERT_ENC_PKCS12);

  return 0;
}


int main_0097_ssl_verify_local(int argc, char **argv) {
  if (!test_check_builtin("ssl")) {
    Test::Skip("Test requires SSL support\n");
    return 0;
  }


  /* Check that creating a client with an invalid PEM string fails. */
  const std::string props[] = {"ssl.ca.pem", "ssl.key.pem",
                               "ssl.certificate.pem", ""};

  for (int i = 0; props[i] != ""; i++) {
    RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

    std::string errstr;

    if (conf->set("security.protocol", "SSL", errstr))
      Test::Fail(errstr);
    conf->set("debug", "security", errstr);
    if (conf->set(props[i], "this is \n not a \t PEM!", errstr))
      Test::Fail("Setting " + props[i] +
                 " to junk should work, "
                 "expecting failure on client creation");

    RdKafka::Producer *producer = RdKafka::Producer::create(conf, errstr);
    delete conf;
    if (producer)
      Test::Fail("Expected producer creation to fail with " + props[i] +
                 " set to junk");
    else
      Test::Say("Failed to create producer with junk " + props[i] +
                " (as expected): " + errstr + "\n");
  }

  return 0;
}
}
