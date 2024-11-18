// Copyright (C) 2016-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#include "../include/criticalsection.hpp"

#ifdef _WIN32

#include <Windows.h>

namespace vsomeip_v3 {

    struct CriticalSection::Impl final {
        CRITICAL_SECTION m_criticalSection;
    };


    CriticalSection::CriticalSection()
    : m_impl(new CriticalSection::Impl()) {
        InitializeCriticalSection(&m_impl->m_criticalSection);
    }

    CriticalSection::~CriticalSection() {
        DeleteCriticalSection(&m_impl->m_criticalSection);
    }

    void CriticalSection::lock() {
        EnterCriticalSection(&m_impl->m_criticalSection);
    }

    bool CriticalSection::try_lock() {
        return (TryEnterCriticalSection(&m_impl->m_criticalSection) != 0);
    }

    void CriticalSection::unlock(){
        LeaveCriticalSection(&m_impl->m_criticalSection);
    }

} // namespace vsomeip_v3

#endif
