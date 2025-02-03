// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef __EXPORT__HPP__
#define __EXPORT__HPP__

#if _WIN32
    #define VSOMEIP_EXPORT __declspec(dllexport)
    #define VSOMEIP_EXPORT_CLASS_EXPLICIT

    #if VSOMEIP_DLL_COMPILATION
        #define VSOMEIP_IMPORT_EXPORT __declspec(dllexport)
    #else
        #define VSOMEIP_IMPORT_EXPORT __declspec(dllimport)
    #endif

    #if VSOMEIP_DLL_COMPILATION_CONFIG
        #define VSOMEIP_IMPORT_EXPORT_CONFIG __declspec(dllexport)
    #else
        #define VSOMEIP_IMPORT_EXPORT_CONFIG __declspec(dllimport)
    #endif
#else
    #define VSOMEIP_EXPORT
    #define VSOMEIP_IMPORT_EXPORT
    #define VSOMEIP_IMPORT_EXPORT_CONFIG
#endif

#endif
