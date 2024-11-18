// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_UNKOWN_OPTION_IMPL_HPP_
#define VSOMEIP_V3_SD_UNKOWN_OPTION_IMPL_HPP_

#include <vector>

#include "option_impl.hpp"

namespace vsomeip_v3 {
namespace sd {

/// @brief An SD Endpoint Option of unknown type.
///
/// It is meant to allow the deserialization of an option even if its type is unknown.
class unknown_option_impl : public option_impl
{
public:
    /// @brief Constructor.
    unknown_option_impl() = default;

    /// @brief Destructor.
    ~unknown_option_impl() = default;

    /// @brief Reads the option from the deserializer.
    ///
    /// @param _from The deserializer that contains the option.
    /// @return Whether the deserialization was successful.
    virtual bool deserialize(deserializer* _from) override;

    /// @brief The payload of the option as an array of bytes.
    /// @return A reference to the payload.
    const std::vector<uint8_t>& get_payload() const;

private:
    /// @brief The payload of the option as an array of bytes.
    std::vector<uint8_t> payload_;
};

} // namespace sd
} // namespace vsomeip_v3

#endif
