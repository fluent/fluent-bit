// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include "../../../implementation/utility/include/bithelper.hpp"

#include <vsomeip/defines.hpp>

TEST(byte_operations, MACRO_VSOMEIP_BYTES_TO_WORD)
{
    uint8_t payload[8] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};

    uint16_t its_service = vsomeip_v3::bithelper::read_uint16_be(payload+VSOMEIP_SERVICE_POS_MIN);
    uint16_t its_method  = vsomeip_v3::bithelper::read_uint16_be(payload+VSOMEIP_METHOD_POS_MIN);

    EXPECT_EQ(its_service, 0x1112);
    EXPECT_EQ(its_method,  0x1314);
}

TEST(byte_operations, MACRO_VSOMEIP_BYTES_TO_LONG)
{
    uint8_t payload[8] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};

    uint32_t its_data = vsomeip_v3::bithelper::read_uint32_be(payload+2);
    EXPECT_EQ(its_data, 0x13141516);

    uint32_t its_data2 = vsomeip_v3::bithelper::read_uint32_le(payload+2);
    EXPECT_EQ(its_data2, 0x16151413);
}

TEST(byte_operations, MACRO_VSOMEIP_BYTES_TO_LONG_LONG)
{
    uint8_t payload[8] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};

    uint64_t its_data = vsomeip_v3::bithelper::read_uint64_be(payload);
    EXPECT_EQ(its_data, 0x1112131415161718);
}

TEST(byte_operations, MACRO_VSOMEIP_WORDS_TO_LONG) {
    uint16_t serviceid = 0x1111;
    uint16_t methodid  = 0x2222;

    const uint8_t request_message[] = {static_cast<uint8_t>((serviceid & 0xFF00) >> 8),
                                       static_cast<uint8_t>( serviceid & 0x00FF),
                                       static_cast<uint8_t>((methodid  & 0xFF00) >> 8),
                                       static_cast<uint8_t>( methodid  & 0x00FF)};
    uint32_t header_method = vsomeip_v3::bithelper::read_uint32_be(request_message);

    EXPECT_EQ(header_method, 0x11112222);
}

TEST(byte_operations, MACRO_VSOMEIP_WORD_BYTEx) {
    uint16_t clientid = 0x1234;
    uint8_t client[sizeof(clientid)] = {0};

    vsomeip_v3::bithelper::write_uint16_be(clientid, client);
    EXPECT_EQ(client[0], 0x12);
    EXPECT_EQ(client[1], 0x34);

    vsomeip_v3::bithelper::write_uint16_le(clientid, client);
    EXPECT_EQ(client[0], 0x34);
    EXPECT_EQ(client[1], 0x12);
}

TEST(byte_operations, MACRO_VSOMEIP_LONG_BYTEx) {
    uint32_t payload = 0x12345678;
    uint8_t data[sizeof(payload)] = {0};

    vsomeip_v3::bithelper::write_uint32_be(payload, data);
    EXPECT_EQ(data[0], 0x12);
    EXPECT_EQ(data[1], 0x34);
    EXPECT_EQ(data[2], 0x56);
    EXPECT_EQ(data[3], 0x78);

    vsomeip_v3::bithelper::write_uint32_le(payload, data);
    EXPECT_EQ(data[0], 0x78);
    EXPECT_EQ(data[1], 0x56);
    EXPECT_EQ(data[2], 0x34);
    EXPECT_EQ(data[3], 0x12);
}

TEST(byte_operations, MACRO_VSOMEIP_LONG_LONG_BYTEx) {
    uint64_t payload = 0x1214161821232527;
    uint8_t data[sizeof(payload)] = {0};

    vsomeip_v3::bithelper::write_uint64_be(payload, data);
    EXPECT_EQ(data[0], 0x12);
    EXPECT_EQ(data[1], 0x14);
    EXPECT_EQ(data[2], 0x16);
    EXPECT_EQ(data[3], 0x18);
    EXPECT_EQ(data[4], 0x21);
    EXPECT_EQ(data[5], 0x23);
    EXPECT_EQ(data[6], 0x25);
    EXPECT_EQ(data[7], 0x27);

    vsomeip_v3::bithelper::write_uint64_le(payload, data);
    EXPECT_EQ(data[0], 0x27);
    EXPECT_EQ(data[1], 0x25);
    EXPECT_EQ(data[2], 0x23);
    EXPECT_EQ(data[3], 0x21);
    EXPECT_EQ(data[4], 0x18);
    EXPECT_EQ(data[5], 0x16);
    EXPECT_EQ(data[6], 0x14);
    EXPECT_EQ(data[7], 0x12);

}

TEST(byte_operations, MACRO_VSOMEIP_LONG_WORDx) {
    uint32_t payload = 0x12345678;
    uint8_t data[sizeof(payload)] = {0};

    vsomeip_v3::bithelper::write_uint32_le(payload, data);
    EXPECT_EQ(data[0], 0x78);
    EXPECT_EQ(data[1], 0x56);
    EXPECT_EQ(data[2], 0x34);
    EXPECT_EQ(data[3], 0x12);
}

TEST(byte_operations, TestUint16) {
    uint8_t input[] = {0xab, 0xcd};
    EXPECT_EQ(0xabcd, vsomeip_v3::bithelper::read_uint16_be(input));

    uint8_t output[sizeof(input)] = {0};
    vsomeip_v3::bithelper::write_uint16_be(0x1234, output);
    EXPECT_EQ(0x12, output[0]);
    EXPECT_EQ(0x34, output[1]);
}

TEST(byte_operations, TestUint32_BigEndian) {
    uint8_t input[] = {0x12, 0x34, 0x56, 0x78};
    EXPECT_EQ(0x12345678U, vsomeip_v3::bithelper::read_uint32_be(input));

    uint8_t output[sizeof(uint32_t)] = {0};
    vsomeip_v3::bithelper::write_uint32_be(0xabcd1234, output);
    EXPECT_EQ(0xab, output[0]);
    EXPECT_EQ(0xcd, output[1]);
    EXPECT_EQ(0x12, output[2]);
    EXPECT_EQ(0x34, output[3]);
}

TEST(byte_operations, TestUint32_LittleEndian) {
    uint8_t input[] = {0x12, 0x34, 0x56, 0x78};
    EXPECT_EQ(0x78563412U, vsomeip_v3::bithelper::read_uint32_le(input));

    uint8_t output[sizeof(uint32_t)] = {0};
    vsomeip_v3::bithelper::write_uint32_le(0xabcd1234, output);
    EXPECT_EQ(0xab, output[3]);
    EXPECT_EQ(0xcd, output[2]);
    EXPECT_EQ(0x12, output[1]);
    EXPECT_EQ(0x34, output[0]);
}

TEST(byte_operations, TestUint64) {
    uint8_t input[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef};
    EXPECT_EQ(0x1234567890ABCDEFULL, vsomeip_v3::bithelper::read_uint64_be(input));

    uint8_t output[sizeof(input)] = {0};
    vsomeip_v3::bithelper::write_uint64_be(0x1234567890ABCDEFULL, output);
    EXPECT_EQ(0x12, output[0]);
    EXPECT_EQ(0x34, output[1]);
    EXPECT_EQ(0x56, output[2]);
    EXPECT_EQ(0x78, output[3]);
    EXPECT_EQ(0x90, output[4]);
    EXPECT_EQ(0xab, output[5]);
    EXPECT_EQ(0xcd, output[6]);
    EXPECT_EQ(0xef, output[7]);
}
