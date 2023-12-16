/*
 * Copyright (C) The c-ares project
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef ARES_TEST_AI_H
#define ARES_TEST_AI_H

#include <utility>
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "ares-test.h"

namespace ares {
namespace test {

class MockChannelTestAI
  : public MockChannelOptsTest,
    public ::testing::WithParamInterface<std::pair<int, bool>> {
public:
  MockChannelTestAI()
    : MockChannelOptsTest(1, GetParam().first, GetParam().second, nullptr, 0)
  {
  }
};

class MockUDPChannelTestAI : public MockChannelOptsTest,
                             public ::testing::WithParamInterface<int> {
public:
  MockUDPChannelTestAI() : MockChannelOptsTest(1, GetParam(), false, nullptr, 0)
  {
  }
};

class MockTCPChannelTestAI : public MockChannelOptsTest,
                             public ::testing::WithParamInterface<int> {
public:
  MockTCPChannelTestAI() : MockChannelOptsTest(1, GetParam(), true, nullptr, 0)
  {
  }
};

// Test fixture that uses a default channel.
class DefaultChannelTestAI : public LibraryTest {
public:
  DefaultChannelTestAI() : channel_(nullptr)
  {
    EXPECT_EQ(ARES_SUCCESS, ares_init(&channel_));
    EXPECT_NE(nullptr, channel_);
  }

  ~DefaultChannelTestAI()
  {
    ares_destroy(channel_);
    channel_ = nullptr;
  }

  // Process all pending work on ares-owned file descriptors.
  void Process();

protected:
  ares_channel_t *channel_;
};

}  // namespace test
}  // namespace ares

#endif
