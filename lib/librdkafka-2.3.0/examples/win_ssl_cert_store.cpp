/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019-2022, Magnus Edenhill
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

/**
 * Example of utilizing the Windows Certificate store with SSL.
 */

#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <csignal>
#include <cstring>
#include <sstream>

#include "../win32/wingetopt.h"
#include <windows.h>
#include <wincrypt.h>

/*
 * Typically include path in a real application would be
 * #include <librdkafka/rdkafkacpp.h>
 */
#include "rdkafkacpp.h"



class ExampleStoreRetriever {
 public:
  ExampleStoreRetriever(std::string const &subject, std::string const &pass) :
      m_cert_subject(subject),
      m_password(pass),
      m_cert_store(NULL),
      m_cert_ctx(NULL) {
    load_certificate();
  }

  ~ExampleStoreRetriever() {
    if (m_cert_ctx)
      CertFreeCertificateContext(m_cert_ctx);

    if (m_cert_store)
      CertCloseStore(m_cert_store, 0);
  }

  /* @returns the public key in DER format */
  const std::vector<unsigned char> get_public_key() {
    std::vector<unsigned char> buf((size_t)m_cert_ctx->cbCertEncoded);
    buf.assign((const char *)m_cert_ctx->pbCertEncoded,
               (const char *)m_cert_ctx->pbCertEncoded +
                   (size_t)m_cert_ctx->cbCertEncoded);
    return buf;
  }

  /* @returns the private key in PCKS#12 format */
  const std::vector<unsigned char> get_private_key() {
    ssize_t ret = 0;
    /*
     * In order to export the private key the certificate
     * must first be marked as exportable.
     *
     * Steps to export the certificate
     * 1) Create an in-memory cert store
     * 2) Add the certificate to the store
     * 3) Export the private key from the in-memory store
     */

    /* Create an in-memory cert store */
    HCERTSTORE hMemStore =
        CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, 0, NULL);
    if (!hMemStore)
      throw "Failed to create in-memory cert store: " +
          GetErrorMsg(GetLastError());

    /* Add certificate to store */
    if (!CertAddCertificateContextToStore(hMemStore, m_cert_ctx,
                                          CERT_STORE_ADD_USE_EXISTING, NULL))
      throw "Failed to add certificate to store: " +
          GetErrorMsg(GetLastError());

    /*
     * Export private key from cert
     */
    CRYPT_DATA_BLOB db = {NULL};

    std::wstring w_password(m_password.begin(), m_password.end());

    /* Acquire output size */
    if (!PFXExportCertStoreEx(hMemStore, &db, w_password.c_str(), NULL,
                              EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY |
                                  REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
      throw "Failed to export private key: " + GetErrorMsg(GetLastError());

    std::vector<unsigned char> buf;

    buf.resize(db.cbData);
    db.pbData = &buf[0];

    /* Extract key */
    if (!PFXExportCertStoreEx(hMemStore, &db, w_password.c_str(), NULL,
                              EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY |
                                  REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
      throw "Failed to export private key (PFX): " +
          GetErrorMsg(GetLastError());

    CertCloseStore(hMemStore, 0);

    buf.resize(db.cbData);

    return buf;
  }

 private:
  void load_certificate() {
    if (m_cert_ctx)
      return;

    m_cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL,
                                 CERT_SYSTEM_STORE_CURRENT_USER, L"My");
    if (!m_cert_store)
      throw "Failed to open cert store: " + GetErrorMsg(GetLastError());

    m_cert_ctx = CertFindCertificateInStore(
        m_cert_store, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR,
        /* should probally do a better std::string to std::wstring conversion */
        std::wstring(m_cert_subject.begin(), m_cert_subject.end()).c_str(),
        NULL);
    if (!m_cert_ctx) {
      CertCloseStore(m_cert_store, 0);
      m_cert_store = NULL;
      throw "Certificate " + m_cert_subject +
          " not found in cert store: " + GetErrorMsg(GetLastError());
    }
  }

  std::string GetErrorMsg(unsigned long error) {
    char *message = NULL;
    size_t ret    = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, nullptr,
        error, 0, (char *)&message, 0, nullptr);
    if (ret == 0) {
      std::stringstream ss;

      ss << std::string("could not format message for ") << error;
      return ss.str();
    } else {
      std::string result(message, ret);
      LocalFree(message);
      return result;
    }
  }

 private:
  std::string m_cert_subject;
  std::string m_password;
  PCCERT_CONTEXT m_cert_ctx;
  HCERTSTORE m_cert_store;
};


class PrintingSSLVerifyCb : public RdKafka::SslCertificateVerifyCb {
  /* This SSL cert verification callback simply prints the certificates
   * in the certificate chain.
   * It provides no validation, everything is ok. */
 public:
  bool ssl_cert_verify_cb(const std::string &broker_name,
                          int32_t broker_id,
                          int *x509_error,
                          int depth,
                          const char *buf,
                          size_t size,
                          std::string &errstr) {
    PCCERT_CONTEXT ctx = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (const uint8_t *)buf,
        static_cast<unsigned long>(size));

    if (!ctx)
      std::cerr << "Failed to parse certificate" << std::endl;

    char subject[256] = "n/a";
    char issuer[256]  = "n/a";

    CertGetNameStringA(ctx, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, subject,
                       sizeof(subject));

    CertGetNameStringA(ctx, CERT_NAME_FRIENDLY_DISPLAY_TYPE,
                       CERT_NAME_ISSUER_FLAG, NULL, issuer, sizeof(issuer));

    std::cerr << "Broker " << broker_name << " (" << broker_id << "): "
              << "certificate depth " << depth << ", X509 error " << *x509_error
              << ", subject " << subject << ", issuer " << issuer << std::endl;

    if (ctx)
      CertFreeCertificateContext(ctx);

    return true;
  }
};


/**
 * @brief Print the brokers in the cluster.
 */
static void print_brokers(RdKafka::Handle *handle,
                          const RdKafka::Metadata *md) {
  std::cout << md->brokers()->size() << " broker(s) in cluster "
            << handle->clusterid(0) << std::endl;

  /* Iterate brokers */
  RdKafka::Metadata::BrokerMetadataIterator ib;
  for (ib = md->brokers()->begin(); ib != md->brokers()->end(); ++ib)
    std::cout << "  broker " << (*ib)->id() << " at " << (*ib)->host() << ":"
              << (*ib)->port() << std::endl;
}


int main(int argc, char **argv) {
  std::string brokers;
  std::string errstr;
  std::string cert_subject;
  std::string priv_key_pass;

  /*
   * Create configuration objects
   */
  RdKafka::Conf *conf  = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
  RdKafka::Conf *tconf = RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC);

  int opt;
  while ((opt = getopt(argc, argv, "b:d:X:s:p:")) != -1) {
    switch (opt) {
    case 'b':
      brokers = optarg;
      break;
    case 'd':
      if (conf->set("debug", optarg, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
      }
      break;
    case 'X': {
      char *name, *val;

      name = optarg;
      if (!(val = strchr(name, '='))) {
        std::cerr << "%% Expected -X property=value, not " << name << std::endl;
        exit(1);
      }

      *val = '\0';
      val++;

      if (conf->set(name, val, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
      }
    } break;

    case 's':
      cert_subject = optarg;
      break;

    case 'p':
      priv_key_pass = optarg;
      if (conf->set("ssl.key.password", optarg, errstr) !=
          RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
      }

      break;

    default:
      goto usage;
    }
  }

  if (brokers.empty() || optind != argc) {
  usage:
    std::string features;
    conf->get("builtin.features", features);
    fprintf(stderr,
            "Usage: %s [options] -b <brokers> -s <cert-subject> -p "
            "<priv-key-password>\n"
            "\n"
            "Windows Certificate Store integration example.\n"
            "Use certlm.msc or mmc to view your certificates.\n"
            "\n"
            "librdkafka version %s (0x%08x, builtin.features \"%s\")\n"
            "\n"
            " Options:\n"
            "  -b <brokers>    Broker address\n"
            "  -s <cert>       The subject name of the client's SSL "
            "certificate to use\n"
            "  -p <pass>       The private key password\n"
            "  -d [facs..]     Enable debugging contexts: %s\n"
            "  -X <prop=name>  Set arbitrary librdkafka "
            "configuration property\n"
            "\n",
            argv[0], RdKafka::version_str().c_str(), RdKafka::version(),
            features.c_str(), RdKafka::get_debug_contexts().c_str());
    exit(1);
  }

  if (!cert_subject.empty()) {
    try {
      /* Load certificates from the Windows store */
      ExampleStoreRetriever certStore(cert_subject, priv_key_pass);

      std::vector<unsigned char> pubkey, privkey;

      pubkey  = certStore.get_public_key();
      privkey = certStore.get_private_key();

      if (conf->set_ssl_cert(RdKafka::CERT_PUBLIC_KEY, RdKafka::CERT_ENC_DER,
                             &pubkey[0], pubkey.size(),
                             errstr) != RdKafka::Conf::CONF_OK)
        throw "Failed to set public key: " + errstr;

      if (conf->set_ssl_cert(RdKafka::CERT_PRIVATE_KEY,
                             RdKafka::CERT_ENC_PKCS12, &privkey[0],
                             privkey.size(), errstr) != RdKafka::Conf::CONF_OK)
        throw "Failed to set private key: " + errstr;

    } catch (const std::string &ex) {
      std::cerr << ex << std::endl;
      exit(1);
    }
  }


  /*
   * Set configuration properties
   */
  conf->set("bootstrap.servers", brokers, errstr);

  /* We use the Certificiate verification callback to print the
   * certificate chains being used. */
  PrintingSSLVerifyCb ssl_verify_cb;

  if (conf->set("ssl_cert_verify_cb", &ssl_verify_cb, errstr) !=
      RdKafka::Conf::CONF_OK) {
    std::cerr << errstr << std::endl;
    exit(1);
  }

  /* Create any type of client, producering being the cheapest. */
  RdKafka::Producer *producer = RdKafka::Producer::create(conf, errstr);
  if (!producer) {
    std::cerr << "Failed to create producer: " << errstr << std::endl;
    exit(1);
  }

  RdKafka::Metadata *metadata;

  /* Fetch metadata */
  RdKafka::ErrorCode err = producer->metadata(false, NULL, &metadata, 5000);
  if (err != RdKafka::ERR_NO_ERROR) {
    std::cerr << "%% Failed to acquire metadata: " << RdKafka::err2str(err)
              << std::endl;
    exit(1);
  }

  print_brokers(producer, metadata);

  delete metadata;
  delete producer;

  return 0;
}
