// Copyright (C) 2016-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CRITICALSECTION_HPP
#define VSOMEIP_V3_CRITICALSECTION_HPP

#include <memory>
#include <mutex>

namespace vsomeip_v3 {

#ifdef _WIN32

    // Windows: CriticalSection uses win32 CRITICAL_SECTION.
    // Interface mimics std::mutex so we can use it in
    // conjunction with std::unique_lock.
    class CriticalSection final {
    public:
        CriticalSection();
        ~CriticalSection();

        // prevent copying
        CriticalSection(const CriticalSection&) = delete;
        CriticalSection& operator=(const CriticalSection&) = delete;

        void lock();
        void unlock();
        bool try_lock();

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

#else

    // Linux: CriticalSection is a type alias for std::mutex.
    using CriticalSection = std::mutex;

#endif

} // namespace vsomeip_v3

#endif //VSOMEIP_V3_CRITICALSECTION_HPP
