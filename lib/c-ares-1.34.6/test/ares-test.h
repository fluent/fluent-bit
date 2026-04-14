/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
// -*- mode: c++ -*-
#ifndef ARES_TEST_H
#define ARES_TEST_H

#include "ares_setup.h"
#include "dns-proto.h"
// Include ares internal file for DNS protocol constants
#include "ares_nameser.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#if defined(HAVE_USER_NAMESPACE) && defined(HAVE_UTS_NAMESPACE)
#  define HAVE_CONTAINER
#endif

#include <functional>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>
#include <chrono>

#if defined(HAVE_CLOSESOCKET)
#  define sclose(x) closesocket(x)
#elif defined(HAVE_CLOSESOCKET_CAMEL)
#  define sclose(x) CloseSocket(x)
#elif defined(HAVE_CLOSE_S)
#  define sclose(x) close_s(x)
#else
#  define sclose(x) close(x)
#endif

#ifndef HAVE_WRITEV
extern "C" {
/* Structure for scatter/gather I/O. */
struct iovec {
  void  *iov_base; /* Pointer to data. */
  size_t iov_len;  /* Length of data.  */
};
};
#endif

namespace ares {

typedef unsigned char byte;

namespace test {

extern bool                                    verbose;
extern unsigned short                          mock_port;
extern const std::vector<int>                  both_families;
extern const std::vector<int>                  ipv4_family;
extern const std::vector<int>                  ipv6_family;

extern const std::vector<std::pair<int, bool>> both_families_both_modes;
extern const std::vector<std::pair<int, bool>> ipv4_family_both_modes;
extern const std::vector<std::pair<int, bool>> ipv6_family_both_modes;

extern const std::vector<std::tuple<ares_evsys_t, int, bool>>
  all_evsys_ipv4_family_both_modes;
extern const std::vector<std::tuple<ares_evsys_t, int, bool>>
  all_evsys_ipv6_family_both_modes;
extern const std::vector<std::tuple<ares_evsys_t, int, bool>>
  all_evsys_both_families_both_modes;

extern const std::vector<std::tuple<ares_evsys_t, int>> all_evsys_ipv4_family;
extern const std::vector<std::tuple<ares_evsys_t, int>> all_evsys_ipv6_family;
extern const std::vector<std::tuple<ares_evsys_t, int>> all_evsys_both_families;

// Which parameters to use in tests
extern std::vector<int>                                 families;
extern std::vector<std::tuple<ares_evsys_t, int>>       evsys_families;
extern std::vector<std::pair<int, bool>>                families_modes;
extern std::vector<std::tuple<ares_evsys_t, int, bool>> evsys_families_modes;

// Hopefully a more accurate sleep than sleep_for()
void                    ares_sleep_time(unsigned int ms);

// Process all pending work on ares-owned file descriptors, plus
// optionally the given set-of-FDs + work function.
void                    ProcessWork(ares_channel_t                          *channel,
                                    std::function<std::set<ares_socket_t>()> get_extrafds,
                                    std::function<void(ares_socket_t)>       process_extra,
                                    unsigned int                             cancel_ms = 0);
std::set<ares_socket_t> NoExtraFDs();

const char             *af_tostr(int af);
const char             *mode_tostr(bool mode);
std::string
  PrintFamilyMode(const testing::TestParamInfo<std::pair<int, bool>> &info);
std::string PrintFamily(const testing::TestParamInfo<int> &info);

// Test fixture that ensures library initialization, and allows
// memory allocations to be failed.
class LibraryTest : public ::testing::Test {
public:
  LibraryTest()
  {
    EXPECT_EQ(ARES_SUCCESS, ares_library_init_mem(
                              ARES_LIB_INIT_ALL, &LibraryTest::amalloc,
                              &LibraryTest::afree, &LibraryTest::arealloc));
  }

  ~LibraryTest()
  {
    ares_library_cleanup();
    ClearFails();
  }

  // Set the n-th malloc call (of any size) from the library to fail.
  // (nth == 1 means the next call)
  static void  SetAllocFail(int nth);
  // Set the next malloc call for the given size to fail.
  static void  SetAllocSizeFail(size_t size);
  // Remove any pending alloc failures.
  static void  ClearFails();

  static void *amalloc(size_t size);
  static void *arealloc(void *ptr, size_t size);
  static void  afree(void *ptr);

  static void SetFailSend(void);
  static ares_ssize_t ares_sendv_fail(ares_socket_t socket, const struct iovec *vec, int len,
                                      void *user_data);


private:
  static bool                  ShouldAllocFail(size_t size);
  static unsigned long long    fails_;
  static std::map<size_t, int> size_fails_;
  static std::mutex            lock_;
  static bool                  failsend_;
};

// Test fixture that uses a default channel.
class DefaultChannelTest : public LibraryTest {
public:
  DefaultChannelTest() : channel_(nullptr)
  {
    /* Enable query cache for live tests */
    struct ares_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.qcache_max_ttl = 300;
    int optmask         = ARES_OPT_QUERY_CACHE;
    EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel_, &opts, optmask));
    EXPECT_NE(nullptr, channel_);
  }

  ~DefaultChannelTest()
  {
    ares_destroy(channel_);
    channel_ = nullptr;
  }

  // Process all pending work on ares-owned file descriptors.
  void Process(unsigned int cancel_ms = 0);

protected:
  ares_channel_t *channel_;
};

// Test fixture that uses a file-only channel.
class FileChannelTest : public LibraryTest {
public:
  FileChannelTest() : channel_(nullptr)
  {
    struct ares_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.lookups = strdup("f");
    int optmask  = ARES_OPT_LOOKUPS;
    EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel_, &opts, optmask));
    EXPECT_NE(nullptr, channel_);
    free(opts.lookups);
  }

  ~FileChannelTest()
  {
    ares_destroy(channel_);
    channel_ = nullptr;
  }

  // Process all pending work on ares-owned file descriptors.
  void Process(unsigned int cancel_ms = 0);

protected:
  ares_channel_t *channel_;
};

// Test fixture that uses a default channel with the specified lookup mode.
class DefaultChannelModeTest
  : public LibraryTest,
    public ::testing::WithParamInterface<std::string> {
public:
  DefaultChannelModeTest() : channel_(nullptr)
  {
    struct ares_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.lookups = strdup(GetParam().c_str());
    int optmask  = ARES_OPT_LOOKUPS;
    EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel_, &opts, optmask));
    EXPECT_NE(nullptr, channel_);
    free(opts.lookups);
  }

  ~DefaultChannelModeTest()
  {
    ares_destroy(channel_);
    channel_ = nullptr;
  }

  // Process all pending work on ares-owned file descriptors.
  void Process(unsigned int cancel_ms = 0);

protected:
  ares_channel_t *channel_;
};

// Mock DNS server to allow responses to be scripted by tests.
class MockServer {
public:
  MockServer(int family, unsigned short port);
  ~MockServer();

  // Mock method indicating the processing of a particular <name, RRtype>
  // request.
  MOCK_METHOD2(OnRequest, void(const std::string &name, int rrtype));

  // Set the reply to be sent next; the query ID field will be overwritten
  // with the value from the request.
  void SetReplyData(const std::vector<byte> &reply)
  {
    exact_reply_ = reply;
    reply_       = nullptr;
  }

  void SetReply(const DNSPacket *reply)
  {
    reply_ = reply;
    exact_reply_.clear();
  }

  // Set the reply to be sent next as well as the request (in string form) that
  // the server should expect to receive; the query ID field in the reply will
  // be overwritten with the value from the request.
  void SetReplyExpRequest(const DNSPacket *reply, const std::string &request)
  {
    expected_request_ = request;
    reply_            = reply;
  }

  void SetReplyQID(int qid)
  {
    qid_ = qid;
  }

  void Disconnect()
  {
    reply_ = nullptr;
    exact_reply_.clear();
    for (ares_socket_t fd : connfds_) {
      sclose(fd);
    }
    connfds_.clear();
    free(tcp_data_);
    tcp_data_     = NULL;
    tcp_data_len_ = 0;
  }

  // The set of file descriptors that the server handles.
  std::set<ares_socket_t> fds() const;

  // Process activity on a file descriptor.
  void                    ProcessFD(ares_socket_t fd);

  // Ports the server is responding to
  unsigned short          udpport() const
  {
    return udpport_;
  }

  unsigned short tcpport() const
  {
    return tcpport_;
  }

private:
  void           ProcessRequest(ares_socket_t fd, struct sockaddr_storage *addr,
                                ares_socklen_t addrlen, const std::vector<byte> &req,
                                const std::string &reqstr, int qid, const char *name,
                                int rrtype);
  void           ProcessPacket(ares_socket_t fd, struct sockaddr_storage *addr,
                               ares_socklen_t addrlen, byte *data, int len);
  unsigned short udpport_;
  unsigned short tcpport_;
  ares_socket_t  udpfd_;
  ares_socket_t  tcpfd_;
  std::set<ares_socket_t> connfds_;
  std::vector<byte>       exact_reply_;
  const DNSPacket        *reply_;
  std::string             expected_request_;
  int                     qid_;
  unsigned char          *tcp_data_;
  size_t                  tcp_data_len_;
};

// Test fixture that uses a mock DNS server.
class MockChannelOptsTest : public LibraryTest {
public:
  MockChannelOptsTest(int count, int family, bool force_tcp,
                      bool honor_sysconfig, struct ares_options *givenopts,
                      int optmask);
  ~MockChannelOptsTest();

  // Process all pending work on ares-owned and mock-server-owned file
  // descriptors.
  void ProcessAltChannel(ares_channel_t *chan, unsigned int cancel_ms = 0);
  void Process(unsigned int cancel_ms = 0);

protected:
  // NiceMockServer doesn't complain about uninteresting calls.
  typedef testing::NiceMock<MockServer>                NiceMockServer;
  typedef std::vector<std::unique_ptr<NiceMockServer>> NiceMockServers;

  std::set<ares_socket_t>                              fds() const;
  void                   ProcessFD(ares_socket_t fd);

  static NiceMockServers BuildServers(int count, int family,
                                      unsigned short base_port);

  NiceMockServers        servers_;
  // Convenience reference to first server.
  NiceMockServer        &server_;
  ares_channel_t        *channel_;
};

class MockChannelTest
  : public MockChannelOptsTest,
    public ::testing::WithParamInterface<std::pair<int, bool>> {
public:
  MockChannelTest()
    : MockChannelOptsTest(1, GetParam().first, GetParam().second, false,
                          nullptr, 0)
  {
  }
};

class MockUDPChannelTest : public MockChannelOptsTest,
                           public ::testing::WithParamInterface<int> {
public:
  MockUDPChannelTest()
    : MockChannelOptsTest(1, GetParam(), false, false, nullptr, 0)
  {
  }
};

class MockTCPChannelTest : public MockChannelOptsTest,
                           public ::testing::WithParamInterface<int> {
public:
  MockTCPChannelTest()
    : MockChannelOptsTest(1, GetParam(), true, false, nullptr, 0)
  {
  }
};

class MockEventThreadOptsTest : public MockChannelOptsTest {
public:
  MockEventThreadOptsTest(int count, ares_evsys_t evsys, int family,
                          bool force_tcp, struct ares_options *givenopts,
                          int optmask)
    : MockChannelOptsTest(count, family, force_tcp, false,
                          FillOptionsET(&evopts_, givenopts, evsys),
                          optmask | ARES_OPT_EVENT_THREAD)
  {
  }

  ~MockEventThreadOptsTest()
  {
  }

  static struct ares_options *FillOptionsET(struct ares_options *opts,
                                            struct ares_options *givenopts,
                                            ares_evsys_t         evsys)
  {
    if (givenopts) {
      memcpy(opts, givenopts, sizeof(*opts));
    } else {
      memset(opts, 0, sizeof(*opts));
    }
    opts->evsys = evsys;
    return opts;
  }

  void Process(unsigned int cancel_ms = 0);

private:
  struct ares_options evopts_;
};

class MockEventThreadTest
  : public MockEventThreadOptsTest,
    public ::testing::WithParamInterface<std::tuple<ares_evsys_t, int, bool>> {
public:
  MockEventThreadTest()
    : MockEventThreadOptsTest(1, std::get<0>(GetParam()),
                              std::get<1>(GetParam()), std::get<2>(GetParam()),
                              nullptr, 0)
  {
  }
};

class MockUDPEventThreadTest
  : public MockEventThreadOptsTest,
    public ::testing::WithParamInterface<std::tuple<ares_evsys_t, int>> {
public:
  MockUDPEventThreadTest()
    : MockEventThreadOptsTest(1, std::get<0>(GetParam()),
                              std::get<1>(GetParam()), false, nullptr, 0)
  {
  }
};

class MockTCPEventThreadTest
  : public MockEventThreadOptsTest,
    public ::testing::WithParamInterface<std::tuple<ares_evsys_t, int>> {
public:
  MockTCPEventThreadTest()
    : MockEventThreadOptsTest(1, std::get<0>(GetParam()),
                              std::get<1>(GetParam()), true, nullptr, 0)
  {
  }
};

// gMock action to set the reply for a mock server.
ACTION_P2(SetReplyData, mockserver, data)
{
  mockserver->SetReplyData(data);
}

ACTION_P2(SetReplyAndFailSend, mockserver, reply)
{
  mockserver->SetReply(reply);
  LibraryTest::SetFailSend();
}

ACTION_P2(SetReply, mockserver, reply)
{
  mockserver->SetReply(reply);
}

// gMock action to set the reply for a mock server, as well as the request (in
// string form) that the server should expect to receive.
ACTION_P3(SetReplyExpRequest, mockserver, reply, request)
{
  mockserver->SetReplyExpRequest(reply, request);
}

ACTION_P2(SetReplyQID, mockserver, qid)
{
  mockserver->SetReplyQID(qid);
}

// gMock action to cancel a channel.
ACTION_P2(CancelChannel, mockserver, channel)
{
  ares_cancel(channel);
}

// gMock action to disconnect all connections.
ACTION_P(Disconnect, mockserver)
{
  mockserver->Disconnect();
}

// C++ wrapper for struct hostent.
struct HostEnt {
  HostEnt() : addrtype_(-1)
  {
  }

  HostEnt(const struct hostent *hostent);
  std::string              name_;
  std::vector<std::string> aliases_;
  int                      addrtype_;  // AF_INET or AF_INET6
  std::vector<std::string> addrs_;
};

std::ostream &operator<<(std::ostream &os, const HostEnt &result);

// Structure that describes the result of an ares_host_callback invocation.
struct HostResult {
  HostResult() : done_(false), status_(0), timeouts_(0)
  {
  }

  // Whether the callback has been invoked.
  bool    done_;
  // Explicitly provided result information.
  int     status_;
  int     timeouts_;
  // Contents of the hostent structure, if provided.
  HostEnt host_;
};

std::ostream &operator<<(std::ostream &os, const HostResult &result);

// C++ wrapper for ares_dns_record_t.
struct AresDnsRecord {
  ~AresDnsRecord()
  {
    ares_dns_record_destroy(dnsrec_);
    dnsrec_ = NULL;
  }

  AresDnsRecord() : dnsrec_(NULL)
  {
  }

  void SetDnsRecord(const ares_dns_record_t *dnsrec)
  {
    if (dnsrec_ != NULL) {
      ares_dns_record_destroy(dnsrec_);
    }
    if (dnsrec == NULL) {
      return;
    }
    dnsrec_ = ares_dns_record_duplicate(dnsrec);
  }

  ares_dns_record_t *dnsrec_ = NULL;
};

std::ostream &operator<<(std::ostream &os, const AresDnsRecord &result);

// Structure that describes the result of an ares_host_callback invocation.
struct QueryResult {
  QueryResult() : done_(false), status_(ARES_SUCCESS), timeouts_(0)
  {
  }

  // Whether the callback has been invoked.
  bool          done_;
  // Explicitly provided result information.
  ares_status_t status_;
  size_t        timeouts_;
  // Contents of the ares_dns_record_t structure if provided
  AresDnsRecord dnsrec_;
};

std::ostream &operator<<(std::ostream &os, const QueryResult &result);

// Structure that describes the result of an ares_callback invocation.
struct SearchResult {
  // Whether the callback has been invoked.
  bool              done_;
  // Explicitly provided result information.
  int               status_;
  int               timeouts_;
  std::vector<byte> data_;
};

std::ostream &operator<<(std::ostream &os, const SearchResult &result);

// Structure that describes the result of an ares_nameinfo_callback invocation.
struct NameInfoResult {
  // Whether the callback has been invoked.
  bool        done_;
  // Explicitly provided result information.
  int         status_;
  int         timeouts_;
  std::string node_;
  std::string service_;
};

std::ostream &operator<<(std::ostream &os, const NameInfoResult &result);

struct AddrInfoDeleter {
  void operator()(ares_addrinfo *ptr)
  {
    if (ptr) {
      ares_freeaddrinfo(ptr);
    }
  }
};

// C++ wrapper for struct ares_addrinfo.
using AddrInfo = std::unique_ptr<ares_addrinfo, AddrInfoDeleter>;

std::ostream &operator<<(std::ostream &os, const AddrInfo &result);

// Structure that describes the result of an ares_addrinfo_callback invocation.
struct AddrInfoResult {
  AddrInfoResult() : done_(false), status_(-1), timeouts_(0)
  {
  }

  // Whether the callback has been invoked.
  bool     done_;
  // Explicitly provided result information.
  int      status_;
  int      timeouts_;
  // Contents of the ares_addrinfo structure, if provided.
  AddrInfo ai_;
};

std::ostream &operator<<(std::ostream &os, const AddrInfoResult &result);

// Standard implementation of ares callbacks that fill out the corresponding
// structures.
void          HostCallback(void *data, int status, int timeouts,
                           struct hostent *hostent);
void          QueryCallback(void *data, ares_status_t status, size_t timeouts,
                            const ares_dns_record_t *dnsrec);
void SearchCallback(void *data, int status, int timeouts, unsigned char *abuf,
                    int alen);
void SearchCallbackDnsRec(void *data, ares_status_t status, size_t timeouts,
                          const ares_dns_record_t *dnsrec);
void NameInfoCallback(void *data, int status, int timeouts, char *node,
                      char *service);
void AddrInfoCallback(void *data, int status, int timeouts,
                      struct ares_addrinfo *res);

// Retrieve the name servers used by a channel.
std::string GetNameServers(ares_channel_t *channel);

// RAII class to temporarily create a directory of a given name.
class TransientDir {
public:
  TransientDir(const std::string &dirname);
  ~TransientDir();

private:
  std::string dirname_;
};

// C++ wrapper around tempnam()
std::string TempNam(const char *dir, const char *prefix);

// RAII class to temporarily create file of a given name and contents.
class TransientFile {
public:
  TransientFile(const std::string &filename, const std::string &contents);
  ~TransientFile();

protected:
  std::string filename_;
};

// RAII class for a temporary file with the given contents.
class TempFile : public TransientFile {
public:
  TempFile(const std::string &contents);

  const char *filename() const
  {
    return filename_.c_str();
  }
};

#ifdef _WIN32
extern "C" {

static int setenv(const char *name, const char *value, int overwrite)
{
  char  *buffer;
  size_t buf_size;

  if (name == NULL) {
    return -1;
  }

  if (value == NULL) {
    value = ""; /* For unset */
  }

  if (!overwrite && getenv(name) != NULL) {
    return -1;
  }

  buf_size = strlen(name) + strlen(value) + 1 /* = */ + 1 /* NULL */;
  buffer   = (char *)malloc(buf_size);
  _snprintf(buffer, buf_size, "%s=%s", name, value);
  _putenv(buffer);
  free(buffer);
  return 0;
}

static int unsetenv(const char *name)
{
  return setenv(name, NULL, 1);
}

} /* extern "C" */
#endif

// RAII class for a temporary environment variable value.
class EnvValue {
public:
  EnvValue(const char *name, const char *value) : name_(name), restore_(false)
  {
    char *original = getenv(name);
    if (original) {
      restore_  = true;
      original_ = original;
    }
    setenv(name_.c_str(), value, 1);
  }

  ~EnvValue()
  {
    if (restore_) {
      setenv(name_.c_str(), original_.c_str(), 1);
    } else {
      unsetenv(name_.c_str());
    }
  }

private:
  std::string name_;
  bool        restore_;
  std::string original_;
};


#ifdef HAVE_CONTAINER
// Linux-specific functionality for running code in a container, implemented
// in ares-test-ns.cc
typedef std::function<int(void)>                         VoidToIntFn;
typedef std::vector<std::pair<std::string, std::string>> NameContentList;

class ContainerFilesystem {
public:
  ContainerFilesystem(NameContentList files, const std::string &mountpt);
  ~ContainerFilesystem();

  std::string root() const
  {
    return rootdir_;
  }

  std::string mountpt() const
  {
    return mountpt_;
  }

private:
  void                   EnsureDirExists(const std::string &dir);
  std::string            rootdir_;
  std::string            mountpt_;
  std::list<std::string> dirs_;
  std::vector<std::unique_ptr<TransientFile>> files_;
};

int RunInContainer(ContainerFilesystem *fs, const std::string &hostname,
                   const std::string &domainname, VoidToIntFn fn);

#  define ICLASS_NAME(casename, testname) Contained##casename##_##testname
#  define CONTAINED_TEST_F(casename, testname, hostname, domainname, files)   \
    class ICLASS_NAME(casename, testname) : public casename {                 \
    public:                                                                   \
      ICLASS_NAME(casename, testname)()                                       \
      {                                                                       \
      }                                                                       \
      static int InnerTestBody();                                             \
    };                                                                        \
    TEST_F(ICLASS_NAME(casename, testname), _)                                \
    {                                                                         \
      ContainerFilesystem chroot(files, "..");                                \
      VoidToIntFn         fn(ICLASS_NAME(casename, testname)::InnerTestBody); \
      EXPECT_EQ(0, RunInContainer(&chroot, hostname, domainname, fn));        \
    }                                                                         \
    int ICLASS_NAME(casename, testname)::InnerTestBody()


/* Derived from googletest/include/gtest/gtest-param-test.h, specifically the
 * TEST_P() macro, and some fixes to try to be compatible with different
 * versions. */
#  ifndef GTEST_ATTRIBUTE_UNUSED_
#    define GTEST_ATTRIBUTE_UNUSED_
#  endif
#  ifndef GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED
#    define GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED
#  endif
#  define CONTAINED_TEST_P(test_suite_name, test_name, hostname, domainname, \
                           files)                                            \
    class GTEST_TEST_CLASS_NAME_(test_suite_name, test_name)                 \
      : public test_suite_name {                                             \
    public:                                                                  \
      GTEST_TEST_CLASS_NAME_(test_suite_name, test_name)()                   \
      {                                                                      \
      }                                                                      \
      int  InnerTestBody();                                                  \
      void TestBody()                                                        \
      {                                                                      \
        ContainerFilesystem chroot(files, "..");                             \
        VoidToIntFn         fn = [this](void) -> int {                       \
          ares_reinit(this->channel_);                               \
          ares_sleep_time(100);                                      \
          return this->InnerTestBody();                              \
        };                                                                   \
        EXPECT_EQ(0, RunInContainer(&chroot, hostname, domainname, fn));     \
      }                                                                      \
                                                                             \
    private:                                                                 \
      static int AddToRegistry()                                             \
      {                                                                      \
        ::testing::UnitTest::GetInstance()                                   \
          ->parameterized_test_registry()                                    \
          .GetTestSuitePatternHolder<test_suite_name>(                       \
            GTEST_STRINGIFY_(test_suite_name),                               \
            ::testing::internal::CodeLocation(__FILE__, __LINE__))           \
          ->AddTestPattern(                                                  \
            GTEST_STRINGIFY_(test_suite_name), GTEST_STRINGIFY_(test_name),  \
            new ::testing::internal::TestMetaFactory<GTEST_TEST_CLASS_NAME_( \
              test_suite_name, test_name)>(),                                \
            ::testing::internal::CodeLocation(__FILE__, __LINE__));          \
        return 0;                                                            \
      }                                                                      \
      GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED static int                       \
        gtest_registering_dummy_ GTEST_ATTRIBUTE_UNUSED_;                    \
    };                                                                       \
    int GTEST_TEST_CLASS_NAME_(test_suite_name,                              \
                               test_name)::gtest_registering_dummy_ =        \
      GTEST_TEST_CLASS_NAME_(test_suite_name, test_name)::AddToRegistry();   \
    int GTEST_TEST_CLASS_NAME_(test_suite_name, test_name)::InnerTestBody()

#endif

/* Assigns virtual IO functions to a channel. These functions simply call
 * the actual system functions.
 */
class VirtualizeIO {
public:
  VirtualizeIO(ares_channel);
  ~VirtualizeIO();

  static const ares_socket_functions default_functions;

private:
  ares_channel_t *channel_;
};

/*
 * Slightly white-box macro to generate two runs for a given test case:
 * One with no modifications, and one with all IO functions set to use
 * the virtual io structure.
 * Since no magic socket setup or anything is done in the latter case
 * this should probably only be used for test with very vanilla IO
 * requirements.
 */
#define VCLASS_NAME(casename, testname) Virt##casename##_##testname
#define VIRT_NONVIRT_TEST_F(casename, testname)                    \
  class VCLASS_NAME(casename, testname) : public casename {        \
  public:                                                          \
    VCLASS_NAME(casename, testname)()                              \
    {                                                              \
    }                                                              \
    void InnerTestBody();                                          \
  };                                                               \
  GTEST_TEST_(casename, testname, VCLASS_NAME(casename, testname), \
              ::testing::internal::GetTypeId<casename>())          \
  {                                                                \
    InnerTestBody();                                               \
  }                                                                \
  GTEST_TEST_(casename, testname##_virtualized,                    \
              VCLASS_NAME(casename, testname),                     \
              ::testing::internal::GetTypeId<casename>())          \
  {                                                                \
    VirtualizeIO vio(channel_);                                    \
    InnerTestBody();                                               \
  }                                                                \
  void VCLASS_NAME(casename, testname)::InnerTestBody()

}  // namespace test
}  // namespace ares

#endif
