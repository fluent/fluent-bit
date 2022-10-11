/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019, Magnus Edenhill
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

static const std::string envname[RdKafka::CERT__CNT][RdKafka::CERT_ENC__CNT] = {
    /* [RdKafka::CERT_PUBLIC_KEY] = */
    {
        "RDK_SSL_pkcs",
        "RDK_SSL_pub_der",
        "RDK_SSL_pub_pem",
    },
    /* [RdKafka::CERT_PRIVATE_KEY] = */
    {
        "RDK_SSL_pkcs",
        "RDK_SSL_priv_der",
        "RDK_SSL_priv_pem",
    },
    /* [RdKafka::CERT_CA] = */
    {
        "RDK_SSL_pkcs",
        "RDK_SSL_ca_der",
        "RDK_SSL_ca_pem",
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


static void conf_location_to_pem(RdKafka::Conf *conf,
                                 std::string loc_prop,
                                 std::string pem_prop) {
  std::string loc;


  if (conf->get(loc_prop, loc) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to get " + loc_prop);

  std::string errstr;
  if (conf->set(loc_prop, "", errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to reset " + loc_prop + ": " + errstr);

  /* Read file */
  std::ifstream ifs(loc.c_str());
  std::string pem((std::istreambuf_iterator<char>(ifs)),
                  std::istreambuf_iterator<char>());

  Test::Say("Read " + loc_prop + "=" + loc +
            " from disk and changed to in-memory " + pem_prop + "\n");

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
                                    RdKafka::CertificateEncoding encoding) {
  std::string loc;
  static const std::string encnames[] = {
      "PKCS#12",
      "DER",
      "PEM",
  };

  /* Clear the config property (e.g., ssl.key.location) */
  std::string errstr;
  if (conf->set(loc_prop, "", errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to reset " + loc_prop);

  const char *p;
  p = test_getenv(envname[cert_type][encoding].c_str(), NULL);
  if (!p)
    Test::Fail(
        "Invalid test environment: "
        "Missing " +
        envname[cert_type][encoding] +
        " env variable: make sure trivup is up to date");

  loc = p;

  Test::Say(tostr() << "Reading " << loc_prop << " file " << loc << " as "
                    << encnames[encoding] << "\n");

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
    Test::Fail(tostr() << "Failed to set cert from " << loc << " as cert type "
                       << cert_type << " with encoding " << encoding << ": "
                       << errstr << "\n");
}


typedef enum {
  USE_LOCATION, /* use ssl.key.location */
  USE_CONF,     /* use ssl.key.pem */
  USE_SETTER,   /* use conf->set_ssl_cert(), this supports multiple formats */
} cert_load_t;

static const std::string load_names[] = {
    "location",
    "conf",
    "setter",
};


static void do_test_verify(const int line,
                           bool verify_ok,
                           cert_load_t load_key,
                           RdKafka::CertificateEncoding key_enc,
                           cert_load_t load_pub,
                           RdKafka::CertificateEncoding pub_enc,
                           cert_load_t load_ca,
                           RdKafka::CertificateEncoding ca_enc) {
  /*
   * Create any type of client
   */
  std::string teststr = tostr() << line << ": "
                                << "SSL cert verify: verify_ok=" << verify_ok
                                << ", load_key=" << load_names[load_key]
                                << ", load_pub=" << load_names[load_pub]
                                << ", load_ca=" << load_names[load_ca];

  Test::Say(_C_BLU "[ " + teststr + " ]\n" _C_CLR);

  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 10);

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
    conf_location_to_pem(conf, "ssl.key.location", "ssl.key.pem");
  else if (load_key == USE_SETTER)
    conf_location_to_setter(conf, "ssl.key.location", RdKafka::CERT_PRIVATE_KEY,
                            key_enc);

  if (load_pub == USE_CONF)
    conf_location_to_pem(conf, "ssl.certificate.location",
                         "ssl.certificate.pem");
  else if (load_pub == USE_SETTER)
    conf_location_to_setter(conf, "ssl.certificate.location",
                            RdKafka::CERT_PUBLIC_KEY, pub_enc);

  if (load_ca == USE_CONF)
    conf_location_to_pem(conf, "ssl.ca.location", "ssl.ca.pem");
  else if (load_ca == USE_SETTER)
    conf_location_to_setter(conf, "ssl.ca.location", RdKafka::CERT_CA, ca_enc);


  std::string errstr;
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

  if (verify_ok == cluster.empty())
    Test::Fail("Expected connection to " +
               (std::string)(verify_ok ? "succeed" : "fail") +
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

  if (conf->set("ssl.key.password", test_getenv("RDK_SSL_password", NULL),
                errstr))
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

extern "C" {
int main_0097_ssl_verify(int argc, char **argv) {
  if (!test_check_builtin("ssl")) {
    Test::Skip("Test requires SSL support\n");
    return 0;
  }

  if (!test_getenv("RDK_SSL_pkcs", NULL)) {
    Test::Skip("Test requires SSL_* env-vars set up by trivup\n");
    return 0;
  }


  do_test_bad_calls();

  do_test_verify(__LINE__, true, USE_LOCATION, RdKafka::CERT_ENC_PEM,
                 USE_LOCATION, RdKafka::CERT_ENC_PEM, USE_LOCATION,
                 RdKafka::CERT_ENC_PEM);
  do_test_verify(__LINE__, false, USE_LOCATION, RdKafka::CERT_ENC_PEM,
                 USE_LOCATION, RdKafka::CERT_ENC_PEM, USE_LOCATION,
                 RdKafka::CERT_ENC_PEM);

  /* Verify various priv and pub key and CA input formats */
  do_test_verify(__LINE__, true, USE_CONF, RdKafka::CERT_ENC_PEM, USE_CONF,
                 RdKafka::CERT_ENC_PEM, USE_LOCATION, RdKafka::CERT_ENC_PEM);
  do_test_verify(__LINE__, true, USE_CONF, RdKafka::CERT_ENC_PEM, USE_CONF,
                 RdKafka::CERT_ENC_PEM, USE_CONF, RdKafka::CERT_ENC_PEM);
  do_test_verify(__LINE__, true, USE_SETTER, RdKafka::CERT_ENC_PEM, USE_SETTER,
                 RdKafka::CERT_ENC_PEM, USE_SETTER, RdKafka::CERT_ENC_PKCS12);
  do_test_verify(__LINE__, true, USE_LOCATION, RdKafka::CERT_ENC_PEM,
                 USE_SETTER, RdKafka::CERT_ENC_DER, USE_SETTER,
                 RdKafka::CERT_ENC_DER);
  do_test_verify(__LINE__, true, USE_SETTER, RdKafka::CERT_ENC_PKCS12,
                 USE_SETTER, RdKafka::CERT_ENC_PKCS12, USE_SETTER,
                 RdKafka::CERT_ENC_PKCS12);

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
