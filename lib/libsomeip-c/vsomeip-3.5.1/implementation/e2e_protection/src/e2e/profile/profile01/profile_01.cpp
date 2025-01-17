// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../../../../include/e2e/profile/profile01/profile_01.hpp"
#include "../../../../include/crc/crc.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile01 {

uint8_t profile_01::compute_crc(const profile_config &_config, const e2e_buffer &_buffer) {
    uint8_t computed_crc = 0xFF;
    e2e_buffer data_id_buffer; //(_data, _data+_size);
    data_id_buffer.push_back((uint8_t) (_config.data_id_ >> 8)); // insert MSB
    data_id_buffer.push_back((uint8_t) _config.data_id_);        // insert LSB

    switch (_config.data_id_mode_) {
        case p01_data_id_mode::E2E_P01_DATAID_BOTH: // CRC over 2 bytes
            /*
             * Two bytes are included in the CRC (double ID configuration) This is used in E2E variant 1A.
             */
            // CRC = Crc_CalculateCRC8(Config->DataID, 1, 0xFF, FALSE)
            computed_crc = e2e_crc::calculate_profile_01(buffer_view(data_id_buffer, 1, 2), 0xFF); //CRC over low byte of Data ID (LSB)

            // CRC = Crc_CalculateCRC8(Config->DataID >> 8,  1, CRC, FALSE)
            computed_crc = e2e_crc::calculate_profile_01(buffer_view(data_id_buffer, 0, 1), computed_crc); //CRC over high byte of Data ID (MSB)

            break;
        case p01_data_id_mode::E2E_P01_DATAID_LOW: // CRC over low byte only
            /*
             * Only the low byte is included, the high byte is never used.
             * This is applicable if the IDs in a particular system are 8 bits
             */
            // CRC = Crc_CalculateCRC8(Config->DataID, 1, 0xFF, FALSE)
            computed_crc = e2e_crc::calculate_profile_01(buffer_view(data_id_buffer, 1, 2), 0xFF); //CRC over low byte of Data ID (LSB)
            break;

        case p01_data_id_mode::E2E_P01_DATAID_ALT:
            /* One of the two bytes byte is included, alternating high and low byte,
             * depending on parity of the counter (alternating ID configuration).
             * For an even counter, the low byte is included.
             * For an odd counter, the high byte is included.
             * This is used in E2E variant 1B.
             *
            if( counter % 2 == 0) {
                 // CRC = Crc_CalculateCRC8(Config->DataID, 1, 0xFF, FALSE)
                computed_crc = crc::e2e_crc::calculate_profile_01(buffer::buffer_view(data_id_buffer, 1, 2), 0xFF); //CRC over low byte of Data ID (LSB)
            } else {
                //  CRC = Crc_CalculateCRC8(Config->DataID >> 8,  1, 0xFF, FALSE)
                computed_crc = crc::e2e_crc::calculate_profile_01(buffer::buffer_view(data_id_buffer, 0, 1), 0xFF); //CRC over high byte of Data ID (MSB)
            }
            */
            break;

        case p01_data_id_mode::E2E_P01_DATAID_NIBBLE:
            /*
             * The low byte is included in the implicit CRC calculation,
             * the low nibble of the high byte is transmitted along with
             * the data (i.e. it is explicitly included), the high nibble of
             * the high byte is not used. This is applicable for the IDs
             * up to 12 bits. This is used in E2E variant 1C.
             */
            // CRC = Crc_CalculateCRC8(Config->DataID, 1, 0xFF, FALSE)
            computed_crc = e2e_crc::calculate_profile_01(buffer_view(data_id_buffer, 1, 2), 0xFF); //CRC over low byte of Data ID (LSB)

            // CRC = Crc_CalculateCRC8 (0, 1, CRC, FALSE)
            data_id_buffer.clear();
            data_id_buffer.push_back(0x00);
            computed_crc = e2e_crc::calculate_profile_01(buffer_view(data_id_buffer, 0, 1), computed_crc); // CRC with 0x00
            break;

        default:
            break;
    }

    // Compute CRC over the area before the CRC (if CRC is not the first byte)
    if (_config.crc_offset_ >= 1) {
        // CRC = Crc_CalculateCRC8 (Data, (Config->CRCOffset / 8), CRC, FALSE)
        computed_crc = e2e_crc::calculate_profile_01(buffer_view(_buffer, 0, _config.crc_offset_), computed_crc);
    }

    // Compute the area after CRC, if  CRC is not the last byte. Start with  the byte after CRC, finish with the last byte of Data.
    if ((_config.crc_offset_) < (_config.data_length_ / 8) - 1) {
        // CRC = Crc_CalculateCRC8 (& Data[Config->CRCOffset/8 + 1], (Config->DataLength / 8 - Config->CRCOffset / 8 - 1), CRC, FALSE)
        computed_crc = e2e_crc::calculate_profile_01(buffer_view(_buffer, static_cast<size_t>(_config.crc_offset_ + 1), _buffer.size()), computed_crc);
    }

    // CRC = CRC ^ 0xFF
    // To negate the last XOR 0xFF operation done on computed CRC by the last CalculateCRC8(), there is a XORing doneexternally by E2E Library
    computed_crc = computed_crc ^ 0xFFU;
    return computed_crc;
}

/** @req [SWS_E2E_00356] */
bool profile_01::is_buffer_length_valid(const profile_config &_config, const e2e_buffer &_buffer) {
    return (((_config.data_length_ / 8) + 1U <= _buffer.size())
            && _config.crc_offset_ <= _buffer.size()
            && _config.counter_offset_ / 8 <= _buffer.size()
            && _config.data_id_nibble_offset_ / 8 <= _buffer.size());
}

} // namespace profile01
} // namespace e2e
} // namespace vsomeip_v3
