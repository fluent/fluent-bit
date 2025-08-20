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
    : MockChannelOptsTest(1, GetParam().first, GetParam().second, false,
                          nullptr, 0)
  {
  }
};

class MockUDPChannelTestAI : public MockChannelOptsTest,
                             public ::testing::WithParamInterface<int> {
public:
  MockUDPChannelTestAI()
    : MockChannelOptsTest(1, GetParam(), false, false, nullptr, 0)
  {
  }
};

class MockTCPChannelTestAI : public MockChannelOptsTest,
                             public ::testing::WithParamInterface<int> {
public:
  MockTCPChannelTestAI()
    : MockChannelOptsTest(1, GetParam(), true, false, nullptr, 0)
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
