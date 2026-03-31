/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CProfiles
 *  =========
 *  Copyright (C) 2024 The CProfiles Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <time.h>
#include "cprof_tests.h"
#include <cprofiles/cprof_decode_opentelemetry.h>
#include <cprofiles/cprof_encode_opentelemetry.h>
#include <cfl/cfl.h>
#include <opentelemetry/proto/collector/profiles/v1development/profiles_service.pb-c.h>

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

/*
 * Build a minimal cprof (resource_profiles -> scope_profiles -> profile with one sample)
 * so we can test OTLP encode then decode round-trip without depending on old wire data.
 */
static struct cprof *create_minimal_cprof(void)
{
    struct cprof                        *cprof;
    struct cprof_resource_profiles     *resource_profiles;
    struct cprof_resource              *resource;
    struct cprof_scope_profiles        *scope_profiles;
    struct cprof_profile               *profile;
    struct cprof_sample                *sample;
    struct cfl_kvlist                  *attrs;
    size_t                              id;
    int                                 ret;

    cprof = cprof_create();
    if (cprof == NULL) {
        return NULL;
    }

    resource_profiles = cprof_resource_profiles_create("");
    if (resource_profiles == NULL) {
        cprof_destroy(cprof);
        return NULL;
    }

    attrs = cfl_kvlist_create();
    if (attrs == NULL) {
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    resource = cprof_resource_create(attrs);
    if (resource == NULL) {
        cfl_kvlist_destroy(attrs);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    resource_profiles->resource = resource;

    scope_profiles = cprof_scope_profiles_create(resource_profiles, "");
    if (scope_profiles == NULL) {
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    scope_profiles->scope = cprof_instrumentation_scope_create("", "", NULL, 0);
    if (scope_profiles->scope == NULL) {
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }

    profile = cprof_profile_create();
    if (profile == NULL) {
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    profile->time_nanos = 1000000000ULL;
    profile->duration_nanos = 100000000ULL;

    cprof_sample_type_str_create(profile, "count", "", CPROF_AGGREGATION_TEMPORALITY_CUMULATIVE);
    id = cprof_profile_string_add(profile, "main", -1);
    if (id == 0) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }

    sample = cprof_sample_create(profile);
    if (sample == NULL) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    ret = cprof_sample_add_location_index(sample, id);
    if (ret != 0) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    ret = cprof_sample_add_value(sample, 1);
    if (ret != 0) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }

    cfl_list_add(&profile->_head, &scope_profiles->profiles);

    ret = cprof_resource_profiles_add(cprof, resource_profiles);
    if (ret != 0) {
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }

    return cprof;
}

/*
unsigned char encoded_packet[] = {  0x0A, 0x9F, 0x11, 0x0A, 0x72, 0x0A, 0x0E, 0x0A, 0x07, 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x69, 0x64, 0x12, 0x03, 0x0A, 0x01, 0x30, 0x0A, 0x16, 0x0A, 0x07, 0x68, 0x6F, 0x73, 0x74, 0x2E, \
                                    0x69, 0x70, 0x12, 0x0B, 0x0A, 0x09, 0x31, 0x32, 0x37, 0x2E, 0x30, 0x2E, 0x30, 0x2E, 0x31, 0x0A, 0x1B, 0x0A, 0x09, 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x6E, 0x61, 0x6D, 0x65, 0x12, 0x0E, \
                                    0x0A, 0x0C, 0x6C, 0x69, 0x6D, 0x61, 0x2D, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x0A, 0x15, 0x0A, 0x0F, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2E, 0x76, 0x65, 0x72, 0x73, \
                                    0x69, 0x6F, 0x6E, 0x12, 0x02, 0x0A, 0x00, 0x0A, 0x14, 0x0A, 0x09, 0x6F, 0x73, 0x2E, 0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x12, 0x07, 0x0A, 0x05, 0x36, 0x2E, 0x35, 0x2E, 0x30, 0x12, \
                                    0xA8, 0x10, 0x0A, 0x00, 0x12, 0xA3, 0x10, 0x0A, 0x10, 0xA4, 0x58, 0x33, 0xE6, 0x18, 0xE6, 0x34, 0x8D, 0xD6, 0xFE, 0x00, 0x58, 0x56, 0xF5, 0xA7, 0x54, 0x11, 0x69, 0x39, 0xAC, 0x2C, \
                                    0x53, 0xC7, 0x04, 0x18, 0x19, 0x69, 0x39, 0xAC, 0x2C, 0x53, 0xC7, 0x04, 0x18, 0x42, 0xFC, 0x0F, 0x0A, 0x04, 0x08, 0x01, 0x10, 0x02, 0x12, 0x16, 0x12, 0x01, 0x01, 0x40, 0x05, 0x48, \
                                    0x05, 0x52, 0x02, 0x01, 0x02, 0x6A, 0x09, 0xF6, 0xEA, 0xCA, 0xD2, 0xAC, 0xEA, 0xB1, 0x82, 0x18, 0x12, 0x18, 0x12, 0x01, 0x01, 0x38, 0x05, 0x40, 0x0E, 0x48, 0x07, 0x52, 0x02, 0x06, \
                                    0x07, 0x6A, 0x09, 0xA8, 0xD3, 0xE3, 0x8E, 0xB1, 0xEA, 0xB1, 0x82, 0x18, 0x12, 0x18, 0x12, 0x01, 0x01, 0x38, 0x13, 0x40, 0x12, 0x48, 0x09, 0x52, 0x02, 0x09, 0x0A, 0x6A, 0x09, 0xE9, \
                                    0xF2, 0xB0, 0xE5, 0xB2, 0xEA, 0xB1, 0x82, 0x18, 0x1A, 0x04, 0x30, 0x06, 0x58, 0x01, 0x1A, 0x10, 0x10, 0x80, 0x80, 0x80, 0x02, 0x18, 0x80, 0x80, 0xF4, 0x08, 0x28, 0x08, 0x62, 0x02, \
                                    0x04, 0x05, 0x1A, 0x0E, 0x10, 0x80, 0x80, 0x04, 0x18, 0x80, 0xC0, 0xFB, 0x07, 0x28, 0x0A, 0x62, 0x01, 0x08, 0x22, 0x0B, 0x18, 0xDB, 0xC1, 0x43, 0x22, 0x02, 0x08, 0x01, 0x3A, 0x01, \
                                    0x00, 0x22, 0x0C, 0x18, 0xC7, 0x8B, 0xD2, 0x0A, 0x22, 0x02, 0x08, 0x02, 0x3A, 0x01, 0x00, 0x22, 0x0B, 0x18, 0xB7, 0x94, 0x3A, 0x22, 0x02, 0x08, 0x03, 0x3A, 0x01, 0x00, 0x22, 0x0B, \
                                    0x18, 0xF7, 0x96, 0x3D, 0x22, 0x02, 0x08, 0x04, 0x3A, 0x01, 0x00, 0x22, 0x0B, 0x18, 0x87, 0xFA, 0x01, 0x22, 0x02, 0x08, 0x05, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xC3, 0xD6, 0xA1, \
                                    0x02, 0x22, 0x02, 0x08, 0x06, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xBB, 0xB5, 0xB3, 0x02, 0x22, 0x02, 0x08, 0x07, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xE7, 0xB7, 0xB3, 0x02, 0x22, \
                                    0x02, 0x08, 0x08, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0x93, 0xD5, 0xB9, 0x01, 0x22, 0x02, 0x08, 0x09, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xD7, 0x8C, 0xB8, 0x01, 0x22, 0x02, 0x08, \
                                    0x0A, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0x97, 0x93, 0xBA, 0x01, 0x22, 0x02, 0x08, 0x0B, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0x9F, 0xA8, 0xBA, 0x01, 0x22, 0x02, 0x08, 0x0C, 0x3A, \
                                    0x01, 0x00, 0x22, 0x0B, 0x18, 0xEB, 0xFA, 0x08, 0x22, 0x02, 0x08, 0x0D, 0x3A, 0x01, 0x00, 0x22, 0x0B, 0x18, 0xD3, 0xFE, 0x08, 0x22, 0x02, 0x08, 0x0E, 0x3A, 0x01, 0x00, 0x22, 0x0B, \
                                    0x18, 0xB7, 0xFF, 0x08, 0x22, 0x02, 0x08, 0x0F, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xA7, 0xBD, 0xCF, 0x0A, 0x22, 0x02, 0x08, 0x10, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xCF, 0xCA, \
                                    0xCF, 0x0A, 0x22, 0x02, 0x08, 0x11, 0x3A, 0x01, 0x00, 0x22, 0x0A, 0x18, 0xC7, 0x3C, 0x22, 0x02, 0x08, 0x12, 0x3A, 0x01, 0x00, 0x22, 0x0A, 0x10, 0x01, 0x18, 0x9F, 0xA6, 0x81, 0x02, \
                                    0x3A, 0x01, 0x03, 0x22, 0x0C, 0x18, 0x9F, 0xCD, 0xA9, 0x02, 0x22, 0x02, 0x08, 0x13, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xC3, 0xDF, 0xAC, 0x02, 0x22, 0x02, 0x08, 0x14, 0x3A, 0x01, \
                                    0x00, 0x22, 0x0C, 0x18, 0xB3, 0x9F, 0xAD, 0x02, 0x22, 0x02, 0x08, 0x15, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0x9B, 0xE1, 0xA0, 0x02, 0x22, 0x02, 0x08, 0x16, 0x3A, 0x01, 0x00, 0x22, \
                                    0x0C, 0x18, 0xCB, 0xE8, 0x86, 0x09, 0x22, 0x02, 0x08, 0x17, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xEB, 0xE3, 0x87, 0x09, 0x22, 0x02, 0x08, 0x18, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, \
                                    0xFB, 0xAE, 0xFE, 0x09, 0x22, 0x02, 0x08, 0x19, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xE7, 0xB0, 0xFE, 0x09, 0x22, 0x02, 0x08, 0x1A, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xEF, 0x90, \
                                    0x85, 0x09, 0x22, 0x02, 0x08, 0x1B, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xF7, 0xF3, 0x85, 0x09, 0x22, 0x02, 0x08, 0x1C, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xCB, 0xF5, 0x85, 0x09, \
                                    0x22, 0x02, 0x08, 0x1D, 0x3A, 0x01, 0x00, 0x22, 0x0B, 0x18, 0xEB, 0xFA, 0x08, 0x22, 0x02, 0x08, 0x0D, 0x3A, 0x01, 0x00, 0x22, 0x0B, 0x18, 0xD3, 0xFE, 0x08, 0x22, 0x02, 0x08, 0x0E, \
                                    0x3A, 0x01, 0x00, 0x22, 0x0B, 0x18, 0xB7, 0xFF, 0x08, 0x22, 0x02, 0x08, 0x0F, 0x3A, 0x01, 0x00, 0x22, 0x0C, 0x18, 0xA7, 0xBD, 0xCF, 0x0A, 0x22, 0x02, 0x08, 0x10, 0x3A, 0x01, 0x00, \
                                    0x22, 0x0C, 0x18, 0xCF, 0xCA, 0xCF, 0x0A, 0x22, 0x02, 0x08, 0x11, 0x3A, 0x01, 0x00, 0x22, 0x0A, 0x18, 0xC7, 0x3C, 0x22, 0x02, 0x08, 0x12, 0x3A, 0x01, 0x00, 0x22, 0x09, 0x10, 0x02, \
                                    0x18, 0xAF, 0xBF, 0x05, 0x3A, 0x01, 0x03, 0x2A, 0x00, 0x2A, 0x02, 0x10, 0x18, 0x2A, 0x02, 0x10, 0x10, 0x2A, 0x02, 0x10, 0x24, 0x2A, 0x02, 0x10, 0x19, 0x2A, 0x02, 0x10, 0x21, 0x2A, \
                                    0x02, 0x10, 0x1A, 0x2A, 0x02, 0x10, 0x25, 0x2A, 0x02, 0x10, 0x0B, 0x2A, 0x02, 0x10, 0x26, 0x2A, 0x02, 0x10, 0x11, 0x2A, 0x02, 0x10, 0x14, 0x2A, 0x02, 0x10, 0x15, 0x2A, 0x02, 0x10, \
                                    0x12, 0x2A, 0x02, 0x10, 0x22, 0x2A, 0x02, 0x10, 0x16, 0x2A, 0x02, 0x10, 0x0E, 0x2A, 0x02, 0x10, 0x1B, 0x2A, 0x02, 0x10, 0x1E, 0x2A, 0x02, 0x10, 0x17, 0x2A, 0x02, 0x10, 0x27, 0x2A, \
                                    0x02, 0x10, 0x0C, 0x2A, 0x02, 0x10, 0x13, 0x2A, 0x02, 0x10, 0x1F, 0x2A, 0x02, 0x10, 0x23, 0x2A, 0x02, 0x10, 0x0F, 0x2A, 0x02, 0x10, 0x1C, 0x2A, 0x02, 0x10, 0x0D, 0x2A, 0x02, 0x10, \
                                    0x20, 0x2A, 0x02, 0x10, 0x1D, 0x32, 0x00, 0x32, 0x07, 0x73, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x73, 0x32, 0x05, 0x63, 0x6F, 0x75, 0x6E, 0x74, 0x32, 0x03, 0x63, 0x70, 0x75, 0x32, 0x0B, \
                                    0x6E, 0x61, 0x6E, 0x6F, 0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64, 0x73, 0x32, 0x16, 0x41, 0x54, 0x73, 0x51, 0x46, 0x31, 0x72, 0x72, 0x49, 0x63, 0x30, 0x35, 0x74, 0x65, 0x6A, 0x66, 0x79, \
                                    0x65, 0x73, 0x5A, 0x52, 0x77, 0x32, 0x20, 0x62, 0x61, 0x31, 0x63, 0x39, 0x61, 0x35, 0x61, 0x38, 0x32, 0x35, 0x36, 0x61, 0x36, 0x65, 0x66, 0x33, 0x65, 0x36, 0x36, 0x33, 0x63, 0x63, \
                                    0x37, 0x33, 0x31, 0x36, 0x38, 0x30, 0x33, 0x64, 0x39, 0x32, 0x16, 0x7A, 0x6A, 0x32, 0x51, 0x75, 0x43, 0x52, 0x61, 0x70, 0x75, 0x6E, 0x30, 0x32, 0x73, 0x79, 0x68, 0x6C, 0x41, 0x48, \
                                    0x71, 0x54, 0x77, 0x32, 0x0D, 0x65, 0x62, 0x70, 0x66, 0x2D, 0x70, 0x72, 0x6F, 0x66, 0x69, 0x6C, 0x65, 0x72, 0x32, 0x16, 0x36, 0x34, 0x41, 0x49, 0x75, 0x76, 0x39, 0x69, 0x70, 0x47, \
                                    0x42, 0x41, 0x41, 0x64, 0x30, 0x52, 0x5A, 0x6D, 0x76, 0x4C, 0x4C, 0x77, 0x32, 0x0A, 0x63, 0x6F, 0x6E, 0x74, 0x61, 0x69, 0x6E, 0x65, 0x72, 0x64, 0x32, 0x13, 0x5F, 0x5F, 0x63, 0x68, \
                                    0x65, 0x63, 0x6B, 0x5F, 0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x5F, 0x73, 0x69, 0x7A, 0x65, 0x32, 0x11, 0x6F, 0x62, 0x6A, 0x5F, 0x63, 0x67, 0x72, 0x6F, 0x75, 0x70, 0x5F, 0x63, 0x68, \
                                    0x61, 0x72, 0x67, 0x65, 0x32, 0x0D, 0x5F, 0x5F, 0x73, 0x6F, 0x63, 0x6B, 0x5F, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x32, 0x07, 0x65, 0x6C, 0x30, 0x5F, 0x73, 0x76, 0x63, 0x32, 0x0C, \
                                    0x75, 0x6E, 0x69, 0x78, 0x5F, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x31, 0x32, 0x08, 0x73, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6C, 0x65, 0x32, 0x10, 0x62, 0x70, 0x66, 0x5F, 0x6D, 0x61, \
                                    0x70, 0x5F, 0x64, 0x6F, 0x5F, 0x62, 0x61, 0x74, 0x63, 0x68, 0x32, 0x0E, 0x69, 0x6E, 0x76, 0x6F, 0x6B, 0x65, 0x5F, 0x73, 0x79, 0x73, 0x63, 0x61, 0x6C, 0x6C, 0x32, 0x10, 0x6B, 0x6D, \
                                    0x65, 0x6D, 0x5F, 0x63, 0x61, 0x63, 0x68, 0x65, 0x5F, 0x61, 0x6C, 0x6C, 0x6F, 0x63, 0x32, 0x09, 0x5F, 0x5F, 0x73, 0x79, 0x73, 0x5F, 0x62, 0x70, 0x66, 0x32, 0x0F, 0x5F, 0x5F, 0x61, \
                                    0x72, 0x6D, 0x36, 0x34, 0x5F, 0x73, 0x79, 0x73, 0x5F, 0x62, 0x70, 0x66, 0x32, 0x0A, 0x64, 0x6F, 0x5F, 0x65, 0x6C, 0x30, 0x5F, 0x73, 0x76, 0x63, 0x32, 0x19, 0x70, 0x72, 0x6F, 0x70, \
                                    0x61, 0x67, 0x61, 0x74, 0x65, 0x5F, 0x70, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5F, 0x75, 0x73, 0x61, 0x67, 0x65, 0x32, 0x19, 0x66, 0x69, 0x6E, 0x69, 0x73, 0x68, 0x5F, \
                                    0x74, 0x61, 0x73, 0x6B, 0x5F, 0x73, 0x77, 0x69, 0x74, 0x63, 0x68, 0x2E, 0x69, 0x73, 0x72, 0x61, 0x2E, 0x30, 0x32, 0x07, 0x6B, 0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x32, 0x13, 0x5F, \
                                    0x5F, 0x63, 0x68, 0x65, 0x63, 0x6B, 0x5F, 0x68, 0x65, 0x61, 0x70, 0x5F, 0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x32, 0x14, 0x65, 0x6C, 0x30, 0x74, 0x5F, 0x36, 0x34, 0x5F, 0x73, 0x79, \
                                    0x6E, 0x63, 0x5F, 0x68, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x72, 0x32, 0x0B, 0x75, 0x6E, 0x69, 0x78, 0x5F, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x32, 0x12, 0x5F, 0x5F, 0x61, 0x72, 0x6D, \
                                    0x36, 0x34, 0x5F, 0x73, 0x79, 0x73, 0x5F, 0x73, 0x6F, 0x63, 0x6B, 0x65, 0x74, 0x32, 0x0C, 0x65, 0x6C, 0x30, 0x74, 0x5F, 0x36, 0x34, 0x5F, 0x73, 0x79, 0x6E, 0x63, 0x32, 0x0D, 0x73, \
                                    0x6B, 0x5F, 0x70, 0x72, 0x6F, 0x74, 0x5F, 0x61, 0x6C, 0x6C, 0x6F, 0x63, 0x32, 0x0C, 0x5F, 0x5F, 0x73, 0x79, 0x73, 0x5F, 0x73, 0x6F, 0x63, 0x6B, 0x65, 0x74, 0x32, 0x0D, 0x72, 0x65, \
                                    0x74, 0x5F, 0x66, 0x72, 0x6F, 0x6D, 0x5F, 0x66, 0x6F, 0x72, 0x6B, 0x32, 0x1A, 0x65, 0x6C, 0x30, 0x5F, 0x73, 0x76, 0x63, 0x5F, 0x63, 0x6F, 0x6D, 0x6D, 0x6F, 0x6E, 0x2E, 0x63, 0x6F, \
                                    0x6E, 0x73, 0x74, 0x70, 0x72, 0x6F, 0x70, 0x2E, 0x30, 0x32, 0x08, 0x73, 0x6B, 0x5F, 0x61, 0x6C, 0x6C, 0x6F, 0x63, 0x32, 0x0D, 0x77, 0x6F, 0x72, 0x6B, 0x65, 0x72, 0x5F, 0x74, 0x68, \
                                    0x72, 0x65, 0x61, 0x64, 0x32, 0x1A, 0x5F, 0x5F, 0x63, 0x68, 0x65, 0x63, 0x6B, 0x5F, 0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x5F, 0x73, 0x69, 0x7A, 0x65, 0x2E, 0x70, 0x61, 0x72, 0x74, \
                                    0x2E, 0x30, 0x32, 0x18, 0x67, 0x65, 0x6E, 0x65, 0x72, 0x69, 0x63, 0x5F, 0x6D, 0x61, 0x70, 0x5F, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5F, 0x62, 0x61, 0x74, 0x63, 0x68, 0x32, 0x10, \
                                    0x74, 0x72, 0x79, 0x5F, 0x63, 0x68, 0x61, 0x72, 0x67, 0x65, 0x5F, 0x6D, 0x65, 0x6D, 0x63, 0x67, 0x48, 0xE9, 0xF2, 0xB0, 0xE5, 0xB2, 0xEA, 0xB1, 0x82, 0x18, 0x5A, 0x04, 0x08, 0x03, \
                                    0x10, 0x04, 0x60, 0x80, 0xE1, 0xEB, 0x17, 0x7A, 0x25, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, \
                                    0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x82, 0x01, 0x1E, 0x0A, 0x12, 0x70, 0x72, 0x6F, 0x66, 0x69, 0x6C, 0x65, 0x2E, 0x66, \
                                    0x72, 0x61, 0x6D, 0x65, 0x2E, 0x74, 0x79, 0x70, 0x65, 0x12, 0x08, 0x0A, 0x06, 0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x82, 0x01, 0x13, 0x0A, 0x0C, 0x63, 0x6F, 0x6E, 0x74, 0x61, 0x69, \
                                    0x6E, 0x65, 0x72, 0x2E, 0x69, 0x64, 0x12, 0x03, 0x0A, 0x01, 0x2F, 0x82, 0x01, 0x1C, 0x0A, 0x0B, 0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x2E, 0x6E, 0x61, 0x6D, 0x65, 0x12, 0x0D, 0x0A, \
                                    0x0B, 0x6B, 0x77, 0x6F, 0x72, 0x6B, 0x65, 0x72, 0x2F, 0x36, 0x3A, 0x31, 0x82, 0x01, 0x1E, 0x0A, 0x12, 0x70, 0x72, 0x6F, 0x66, 0x69, 0x6C, 0x65, 0x2E, 0x66, 0x72, 0x61, 0x6D, 0x65, \
                                    0x2E, 0x74, 0x79, 0x70, 0x65, 0x12, 0x08, 0x0A, 0x06, 0x6E, 0x61, 0x74, 0x69, 0x76, 0x65, 0x82, 0x01, 0x4D, 0x0A, 0x1F, 0x70, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x2E, 0x65, 0x78, \
                                    0x65, 0x63, 0x75, 0x74, 0x61, 0x62, 0x6C, 0x65, 0x2E, 0x62, 0x75, 0x69, 0x6C, 0x64, 0x5F, 0x69, 0x64, 0x2E, 0x67, 0x6E, 0x75, 0x12, 0x2A, 0x0A, 0x28, 0x33, 0x34, 0x31, 0x39, 0x61, \
                                    0x33, 0x65, 0x66, 0x30, 0x30, 0x31, 0x35, 0x34, 0x35, 0x64, 0x38, 0x65, 0x65, 0x39, 0x66, 0x63, 0x64, 0x34, 0x62, 0x31, 0x38, 0x64, 0x34, 0x63, 0x65, 0x31, 0x37, 0x32, 0x30, 0x35, \
                                    0x37, 0x65, 0x33, 0x33, 0x39, 0x82, 0x01, 0x4B, 0x0A, 0x25, 0x70, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x2E, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x61, 0x62, 0x6C, 0x65, 0x2E, 0x62, \
                                    0x75, 0x69, 0x6C, 0x64, 0x5F, 0x69, 0x64, 0x2E, 0x70, 0x72, 0x6F, 0x66, 0x69, 0x6C, 0x69, 0x6E, 0x67, 0x12, 0x22, 0x0A, 0x20, 0x37, 0x30, 0x35, 0x62, 0x64, 0x66, 0x31, 0x34, 0x39, \
                                    0x38, 0x30, 0x66, 0x32, 0x63, 0x32, 0x32, 0x64, 0x63, 0x34, 0x64, 0x65, 0x32, 0x65, 0x36, 0x35, 0x37, 0x36, 0x65, 0x64, 0x66, 0x66, 0x38, 0x82, 0x01, 0x3C, 0x0A, 0x0C, 0x63, 0x6F, \
                                    0x6E, 0x74, 0x61, 0x69, 0x6E, 0x65, 0x72, 0x2E, 0x69, 0x64, 0x12, 0x2C, 0x0A, 0x2A, 0x2F, 0x75, 0x73, 0x65, 0x72, 0x2E, 0x73, 0x6C, 0x69, 0x63, 0x65, 0x2F, 0x75, 0x73, 0x65, 0x72, \
                                    0x2D, 0x35, 0x30, 0x31, 0x2E, 0x73, 0x6C, 0x69, 0x63, 0x65, 0x2F, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6F, 0x6E, 0x2D, 0x32, 0x2E, 0x73, 0x63, 0x6F, 0x70, 0x65, 0x82, 0x01, 0x1E, 0x0A, \
                                    0x0B, 0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x2E, 0x6E, 0x61, 0x6D, 0x65, 0x12, 0x0F, 0x0A, 0x0D, 0x65, 0x62, 0x70, 0x66, 0x2D, 0x70, 0x72, 0x6F, 0x66, 0x69, 0x6C, 0x65, 0x72, 0x82, \
                                    0x01, 0x4B, 0x0A, 0x25, 0x70, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x2E, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x61, 0x62, 0x6C, 0x65, 0x2E, 0x62, 0x75, 0x69, 0x6C, 0x64, 0x5F, 0x69, \
                                    0x64, 0x2E, 0x70, 0x72, 0x6F, 0x66, 0x69, 0x6C, 0x69, 0x6E, 0x67, 0x12, 0x22, 0x0A, 0x20, 0x64, 0x37, 0x38, 0x30, 0x31, 0x36, 0x30, 0x34, 0x65, 0x38, 0x62, 0x38, 0x39, 0x64, 0x64, \
                                    0x61, 0x63, 0x66, 0x65, 0x31, 0x39, 0x38, 0x39, 0x39, 0x64, 0x36, 0x62, 0x61, 0x33, 0x35, 0x36, 0x34, 0x82, 0x01, 0x5A, 0x0A, 0x0C, 0x63, 0x6F, 0x6E, 0x74, 0x61, 0x69, 0x6E, 0x65, \
                                    0x72, 0x2E, 0x69, 0x64, 0x12, 0x4A, 0x0A, 0x48, 0x2F, 0x75, 0x73, 0x65, 0x72, 0x2E, 0x73, 0x6C, 0x69, 0x63, 0x65, 0x2F, 0x75, 0x73, 0x65, 0x72, 0x2D, 0x35, 0x30, 0x31, 0x2E, 0x73, \
                                    0x6C, 0x69, 0x63, 0x65, 0x2F, 0x75, 0x73, 0x65, 0x72, 0x40, 0x35, 0x30, 0x31, 0x2E, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2F, 0x61, 0x70, 0x70, 0x2E, 0x73, 0x6C, 0x69, 0x63, \
                                    0x65, 0x2F, 0x63, 0x6F, 0x6E, 0x74, 0x61, 0x69, 0x6E, 0x65, 0x72, 0x64, 0x2E, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x82, 0x01, 0x1B, 0x0A, 0x0B, 0x74, 0x68, 0x72, 0x65, 0x61, \
                                    0x64, 0x2E, 0x6E, 0x61, 0x6D, 0x65, 0x12, 0x0C, 0x0A, 0x0A, 0x63, 0x6F, 0x6E, 0x74, 0x61, 0x69, 0x6E, 0x65, 0x72, 0x64
                                };
*/


/* Encode minimal cprof to OTLP and check success. */
static void test_encoder()
{
    cfl_sds_t     otlp_result;
    struct cprof *context;
    int           result;

    context = create_minimal_cprof();
    TEST_CHECK(context != NULL);
    if (context == NULL) {
        return;
    }

    result = cprof_encode_opentelemetry_create(&otlp_result, context);
    TEST_CHECK(result == CPROF_ENCODE_OPENTELEMETRY_SUCCESS);

    if (result == CPROF_ENCODE_OPENTELEMETRY_SUCCESS && otlp_result != NULL) {
        cprof_encode_opentelemetry_destroy(otlp_result);
    }
    cprof_destroy(context);
}

/* Round-trip: encode minimal cprof to OTLP, decode it back, assert decode success. */
static void test_decoder()
{
    cfl_sds_t     otlp_result;
    struct cprof *encoded_context;
    struct cprof *decoded_context;
    int           result;
    size_t        offset;

    encoded_context = create_minimal_cprof();
    TEST_CHECK(encoded_context != NULL);
    if (encoded_context == NULL) {
        return;
    }

    result = cprof_encode_opentelemetry_create(&otlp_result, encoded_context);
    TEST_CHECK(result == CPROF_ENCODE_OPENTELEMETRY_SUCCESS);
    cprof_destroy(encoded_context);
    if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS || otlp_result == NULL) {
        return;
    }

    offset = 0;
    decoded_context = NULL;
    result = cprof_decode_opentelemetry_create(&decoded_context,
                                               (unsigned char *) otlp_result,
                                               cfl_sds_len(otlp_result),
                                               &offset);
    TEST_CHECK(result == CPROF_DECODE_OPENTELEMETRY_SUCCESS);

    if (result == CPROF_DECODE_OPENTELEMETRY_SUCCESS && decoded_context != NULL) {
        cprof_decode_opentelemetry_destroy(decoded_context);
    }
    cprof_encode_opentelemetry_destroy(otlp_result);
}

/*
 * Build a cprof with dictionary tables populated: one mapping, one function,
 * one location (with one line), one sample referencing that location, and
 * optionally one link. Exercises mapping_table, function_table, location_table,
 * stack_table (with real location indices), and link_table.
 */
static struct cprof *create_cprof_with_dictionary_tables(void)
{
    struct cprof                  *cprof;
    struct cprof_resource_profiles *resource_profiles;
    struct cprof_resource         *resource;
    struct cprof_scope_profiles   *scope_profiles;
    struct cprof_profile          *profile;
    struct cprof_sample           *sample;
    struct cprof_mapping          *mapping;
    struct cprof_function         *func;
    struct cprof_location         *loc;
    struct cprof_line             *line;
    struct cprof_link             *link;
    struct cfl_kvlist             *attrs;
    size_t                         id_bin;
    size_t                         id_foo;
    int                            ret;

    cprof = cprof_create();
    if (cprof == NULL) {
        return NULL;
    }

    resource_profiles = cprof_resource_profiles_create("");
    if (resource_profiles == NULL) {
        cprof_destroy(cprof);
        return NULL;
    }

    attrs = cfl_kvlist_create();
    if (attrs == NULL) {
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    resource = cprof_resource_create(attrs);
    if (resource == NULL) {
        cfl_kvlist_destroy(attrs);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    resource_profiles->resource = resource;

    scope_profiles = cprof_scope_profiles_create(resource_profiles, "");
    if (scope_profiles == NULL) {
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    scope_profiles->scope = cprof_instrumentation_scope_create("", "", NULL, 0);
    if (scope_profiles->scope == NULL) {
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }

    profile = cprof_profile_create();
    if (profile == NULL) {
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    profile->time_nanos = 2000000000ULL;
    profile->duration_nanos = 200000000ULL;

    cprof_sample_type_str_create(profile, "count", "", CPROF_AGGREGATION_TEMPORALITY_CUMULATIVE);
    id_bin = cprof_profile_string_add(profile, "/bin/app", -1);
    id_foo = cprof_profile_string_add(profile, "foo", -1);
    if (id_bin == 0 || id_foo == 0) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }

    /* One mapping (dict mapping_table will have zero + this). */
    mapping = cprof_mapping_create(profile);
    if (mapping == NULL) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    mapping->memory_start = 0x1000ULL;
    mapping->memory_limit = 0x2000ULL;
    mapping->file_offset = 0;
    mapping->filename = (int64_t)id_bin;

    /* One function (dict function_table will have zero + this). */
    func = cprof_function_create(profile);
    if (func == NULL) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    func->name = (int64_t)id_foo;
    func->system_name = (int64_t)id_foo;
    func->filename = 0;
    func->start_line = 10;

    /* One location with one line (dict location_table will have zero + this). */
    loc = cprof_location_create(profile);
    if (loc == NULL) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    loc->mapping_index = 0;
    loc->address = 0x1000ULL;
    line = cprof_line_create(loc);
    if (line == NULL) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    line->function_index = 0;
    line->line = 10;
    line->column = 0;

    /* One link (dict link_table will have zero + this). */
    link = cprof_link_create(profile);
    if (link == NULL) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    link->trace_id[0] = 0x01;
    link->trace_id[15] = 0x0f;
    link->span_id[0] = 0xaa;
    link->span_id[7] = 0xbb;

    /* Sample with location_index 0 (first location) and link 0. */
    sample = cprof_sample_create(profile);
    if (sample == NULL) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    ret = cprof_sample_add_location_index(sample, 0);
    if (ret != 0) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    ret = cprof_sample_add_value(sample, 42);
    if (ret != 0) {
        cprof_profile_destroy(profile);
        cprof_scope_profiles_destroy(scope_profiles);
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }
    sample->link = 0; /* index into profile->link_table (first link). */

    cfl_list_add(&profile->_head, &scope_profiles->profiles);

    ret = cprof_resource_profiles_add(cprof, resource_profiles);
    if (ret != 0) {
        cprof_resource_profiles_destroy(resource_profiles);
        cprof_destroy(cprof);
        return NULL;
    }

    return cprof;
}

static cfl_sds_t pack_export_service_request(
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *request)
{
    cfl_sds_t packed;
    size_t    packed_size;

    packed_size =
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__get_packed_size(
            request);

    packed = cfl_sds_create_size(packed_size);
    if (packed == NULL) {
        return NULL;
    }

    cfl_sds_set_len(
        packed,
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__pack(
            request, (uint8_t *) packed));

    return packed;
}

static int decode_export_service_request(
    struct cprof **decoded_context,
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *request)
{
    cfl_sds_t packed;
    size_t    offset;
    int       result;

    packed = pack_export_service_request(request);
    if (packed == NULL) {
        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    offset = 0;
    result = cprof_decode_opentelemetry_create(decoded_context,
                                               (unsigned char *) packed,
                                               cfl_sds_len(packed),
                                               &offset);

    cfl_sds_destroy(packed);

    return result;
}

static Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *
create_unpacked_dictionary_request(void)
{
    cfl_sds_t                                                                  otlp_result;
    struct cprof                                                              *context;
    int                                                                        result;
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *request;

    context = create_cprof_with_dictionary_tables();
    if (context == NULL) {
        return NULL;
    }

    result = cprof_encode_opentelemetry_create(&otlp_result, context);
    cprof_destroy(context);
    if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS || otlp_result == NULL) {
        return NULL;
    }

    request = opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__unpack(
        NULL,
        cfl_sds_len(otlp_result),
        (const unsigned char *) otlp_result);

    cprof_encode_opentelemetry_destroy(otlp_result);

    return request;
}

/* Encode cprof with full dictionary (mappings, functions, locations, links) and check success. */
static void test_encoder_dictionary_tables()
{
    cfl_sds_t     otlp_result;
    struct cprof *context;
    int           result;

    context = create_cprof_with_dictionary_tables();
    TEST_CHECK(context != NULL);
    if (context == NULL) {
        return;
    }

    result = cprof_encode_opentelemetry_create(&otlp_result, context);
    TEST_CHECK(result == CPROF_ENCODE_OPENTELEMETRY_SUCCESS);

    if (result == CPROF_ENCODE_OPENTELEMETRY_SUCCESS && otlp_result != NULL) {
        cprof_encode_opentelemetry_destroy(otlp_result);
    }
    cprof_destroy(context);
}

/*
 * Verify decoded cprof matches the structure produced by create_cprof_with_dictionary_tables.
 * Decoder may emit dictionary sentinel at index 0 plus our entry, so we require at least 1
 * and find the entry matching our data. This guards against breaking changes in encode/decode.
 */
static void verify_decoded_cprof_dictionary_tables(struct cprof *decoded)
{
    struct cprof_resource_profiles     *rp;
    struct cprof_scope_profiles        *sp;
    struct cprof_profile               *profile;
    struct cprof_mapping               *mapping;
    struct cprof_function              *func;
    struct cprof_location             *loc;
    struct cprof_line                 *line;
    struct cprof_link                 *link;
    struct cprof_sample               *sample;
    struct cfl_list                   *rp_iter;
    struct cfl_list                   *sp_iter;
    struct cfl_list                   *prof_iter;
    struct cfl_list                   *map_iter;
    struct cfl_list                   *func_iter;
    struct cfl_list                   *loc_iter;
    struct cfl_list                   *line_iter;
    struct cfl_list                   *link_iter;
    struct cfl_list                   *sample_iter;
    size_t                              i;
    int                                 found_bin_app;
    int                                 found_foo;
    int                                 found_mapping;
    int                                 found_function;
    int                                 found_location;
    int                                 found_link;

    TEST_CHECK(decoded != NULL);
    if (decoded == NULL) {
        return;
    }

    TEST_CHECK(cfl_list_size(&decoded->profiles) == 1);
    if (cfl_list_size(&decoded->profiles) != 1) {
        return;
    }

    rp_iter = decoded->profiles.next;
    rp = cfl_list_entry(rp_iter, struct cprof_resource_profiles, _head);
    TEST_CHECK(cfl_list_size(&rp->scope_profiles) == 1);
    if (cfl_list_size(&rp->scope_profiles) != 1) {
        return;
    }

    sp_iter = rp->scope_profiles.next;
    sp = cfl_list_entry(sp_iter, struct cprof_scope_profiles, _head);
    TEST_CHECK(cfl_list_size(&sp->profiles) == 1);
    if (cfl_list_size(&sp->profiles) != 1) {
        return;
    }

    prof_iter = sp->profiles.next;
    profile = cfl_list_entry(prof_iter, struct cprof_profile, _head);

    /* Profile metadata */
    TEST_CHECK(profile->time_nanos == 2000000000ULL);
    TEST_CHECK(profile->duration_nanos == 200000000ULL);

    /* At least one mapping; find one with memory_start=0x1000, filename "/bin/app" */
    TEST_CHECK(cfl_list_size(&profile->mappings) >= 1);
    found_mapping = 0;
    for (map_iter = profile->mappings.next; map_iter != &profile->mappings; map_iter = map_iter->next) {
        mapping = cfl_list_entry(map_iter, struct cprof_mapping, _head);
        if (mapping->memory_start == 0x1000ULL && mapping->memory_limit == 0x2000ULL &&
            mapping->file_offset == 0) {
            if (mapping->filename >= 0 && (size_t)mapping->filename < profile->string_table_count &&
                profile->string_table[mapping->filename] != NULL &&
                strcmp(profile->string_table[mapping->filename], "/bin/app") == 0) {
                found_mapping = 1;
                break;
            }
        }
    }
    TEST_CHECK(found_mapping && "decoded profile must have mapping with /bin/app");

    /* At least one function; find one with start_line=10, name "foo" */
    TEST_CHECK(cfl_list_size(&profile->functions) >= 1);
    found_function = 0;
    for (func_iter = profile->functions.next; func_iter != &profile->functions; func_iter = func_iter->next) {
        func = cfl_list_entry(func_iter, struct cprof_function, _head);
        if (func->start_line == 10) {
            if (func->name >= 0 && (size_t)func->name < profile->string_table_count &&
                profile->string_table[func->name] != NULL &&
                strcmp(profile->string_table[func->name], "foo") == 0) {
                found_function = 1;
                break;
            }
        }
    }
    TEST_CHECK(found_function && "decoded profile must have function \"foo\" with start_line 10");

    /* At least one location; find one with address=0x1000, one line with line=10 */
    TEST_CHECK(cfl_list_size(&profile->locations) >= 1);
    found_location = 0;
    for (loc_iter = profile->locations.next; loc_iter != &profile->locations; loc_iter = loc_iter->next) {
        loc = cfl_list_entry(loc_iter, struct cprof_location, _head);
        if (loc->address == 0x1000ULL && cfl_list_size(&loc->lines) >= 1) {
            line_iter = loc->lines.next;
            line = cfl_list_entry(line_iter, struct cprof_line, _head);
            if (line->line == 10) {
                found_location = 1;
                break;
            }
        }
    }
    TEST_CHECK(found_location && "decoded profile must have location at 0x1000 with line 10");

    /* At least one link; find one with trace_id[0]=0x01, span_id[0]=0xaa */
    TEST_CHECK(cfl_list_size(&profile->link_table) >= 1);
    found_link = 0;
    for (link_iter = profile->link_table.next; link_iter != &profile->link_table; link_iter = link_iter->next) {
        link = cfl_list_entry(link_iter, struct cprof_link, _head);
        if (link->trace_id[0] == 0x01 && link->trace_id[15] == 0x0f &&
            link->span_id[0] == (uint8_t)0xaa && link->span_id[7] == (uint8_t)0xbb) {
            found_link = 1;
            break;
        }
    }
    TEST_CHECK(found_link && "decoded profile must have link with expected trace_id/span_id");

    /* Exactly one sample: value 42, at least one location_index, link index 0 or matching link */
    TEST_CHECK(cfl_list_size(&profile->samples) == 1);
    if (cfl_list_size(&profile->samples) == 1) {
        size_t location_table_size;
        size_t location_index;

        sample_iter = profile->samples.next;
        sample = cfl_list_entry(sample_iter, struct cprof_sample, _head);
        TEST_CHECK(sample->value_count == 1);
        if (sample->value_count >= 1 && sample->values != NULL) {
            TEST_CHECK(sample->values[0] == 42);
        }
        TEST_CHECK(sample->location_index_count >= 1 && "sample must have at least one location_index");
        if (sample->location_index_count >= 1 && sample->location_index != NULL) {
            location_table_size = cfl_list_size(&profile->locations);
            location_index = sample->location_index[0];

            TEST_CHECK(location_index < location_table_size &&
                       "sample must reference a valid decoded location");
            if (location_index < location_table_size) {
                loc_iter = profile->locations.next;
                for (i = 0; i < location_index && loc_iter != &profile->locations; i++) {
                    loc_iter = loc_iter->next;
                }

                if (loc_iter != &profile->locations) {
                    loc = cfl_list_entry(loc_iter, struct cprof_location, _head);
                    TEST_CHECK(loc->address == 0x1000ULL &&
                               "sample must reference decoded location at 0x1000");
                }
            }
        }
        /* sample must reference a link; decoder may use dict index 0 or 1 (sentinel vs first real link) */
        TEST_CHECK(cfl_list_size(&profile->link_table) > 0 && "profile must have links");
        if ((size_t)sample->link < cfl_list_size(&profile->link_table)) {
            link_iter = profile->link_table.next;
            for (i = 0; i < (size_t)sample->link && link_iter != &profile->link_table; i++) {
                link_iter = link_iter->next;
            }
            if (link_iter != &profile->link_table) {
                link = cfl_list_entry(link_iter, struct cprof_link, _head);
                TEST_CHECK(link->trace_id[0] == 0x01 && link->trace_id[15] == 0x0f &&
                          link->span_id[0] == (uint8_t)0xaa && link->span_id[7] == (uint8_t)0xbb &&
                          "sample must reference link with expected trace_id/span_id");
            }
        }
    }

    /* String table must contain "/bin/app" and "foo" (decoder may reorder) */
    found_bin_app = 0;
    found_foo = 0;
    for (i = 0; i < profile->string_table_count && profile->string_table != NULL; i++) {
        if (profile->string_table[i] != NULL) {
            if (strcmp(profile->string_table[i], "/bin/app") == 0) {
                found_bin_app = 1;
            }
            if (strcmp(profile->string_table[i], "foo") == 0) {
                found_foo = 1;
            }
        }
    }
    TEST_CHECK(found_bin_app && "string_table must contain \"/bin/app\"");
    TEST_CHECK(found_foo && "string_table must contain \"foo\"");
}

/*
 * Encode cprof with dictionary, unpack the wire buffer, and assert the request
 * contains a non-NULL dictionary with expected table counts. Catches encoder
 * regressions (e.g. dictionary no longer emitted).
 */
static void test_wire_format_dictionary_present()
{
    cfl_sds_t                                                                  otlp_result;
    struct cprof                                                              *context;
    int                                                                        result;
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *req;

    context = create_cprof_with_dictionary_tables();
    TEST_CHECK(context != NULL);
    if (context == NULL) {
        return;
    }

    result = cprof_encode_opentelemetry_create(&otlp_result, context);
    TEST_CHECK(result == CPROF_ENCODE_OPENTELEMETRY_SUCCESS);
    cprof_destroy(context);
    if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS || otlp_result == NULL) {
        return;
    }

    req = opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__unpack(
            NULL,
            cfl_sds_len(otlp_result),
            (const unsigned char *) otlp_result);

    TEST_CHECK(req != NULL && "unpack of encoded buffer must succeed");
    if (req != NULL) {
        TEST_CHECK(req->dictionary != NULL && "encoded request must contain dictionary");
        if (req->dictionary != NULL) {
            TEST_CHECK(req->dictionary->n_string_table >= 2 && "dictionary must have string table (e.g. \"/bin/app\", \"foo\")");
            TEST_CHECK(req->dictionary->n_mapping_table >= 1 && "dictionary must have at least one mapping");
            TEST_CHECK(req->dictionary->n_function_table >= 1 && "dictionary must have at least one function");
            TEST_CHECK(req->dictionary->n_location_table >= 1 && "dictionary must have at least one location");
            TEST_CHECK(req->dictionary->n_link_table >= 1 && "dictionary must have at least one link");
            TEST_CHECK(req->dictionary->n_stack_table >= 1 && "dictionary must have at least one stack");
        }
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(req, NULL);
    }

    cprof_encode_opentelemetry_destroy(otlp_result);
}

/* Round-trip cprof with full dictionary tables; decode must succeed and match structure. */
static void test_decoder_dictionary_tables()
{
    cfl_sds_t     otlp_result;
    struct cprof *encoded_context;
    struct cprof *decoded_context;
    int           result;
    size_t        offset;

    encoded_context = create_cprof_with_dictionary_tables();
    TEST_CHECK(encoded_context != NULL);
    if (encoded_context == NULL) {
        return;
    }

    result = cprof_encode_opentelemetry_create(&otlp_result, encoded_context);
    TEST_CHECK(result == CPROF_ENCODE_OPENTELEMETRY_SUCCESS);
    cprof_destroy(encoded_context);
    if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS || otlp_result == NULL) {
        return;
    }

    offset = 0;
    decoded_context = NULL;
    result = cprof_decode_opentelemetry_create(&decoded_context,
                                               (unsigned char *) otlp_result,
                                               cfl_sds_len(otlp_result),
                                               &offset);
    TEST_CHECK(result == CPROF_DECODE_OPENTELEMETRY_SUCCESS);

    if (result == CPROF_DECODE_OPENTELEMETRY_SUCCESS && decoded_context != NULL) {
        verify_decoded_cprof_dictionary_tables(decoded_context);
        cprof_decode_opentelemetry_destroy(decoded_context);
    }
    cprof_encode_opentelemetry_destroy(otlp_result);
}

static void test_decoder_dictionary_string_references()
{
    int result;
    struct cprof *decoded_context;
    struct cprof_resource_profiles *resource_profiles_context;
    struct cprof_scope_profiles *scope_profiles_context;
    struct cprof_profile *profile_context;
    struct cfl_variant *resource_attribute_value;
    struct cfl_variant *scope_attribute_value;
    struct cfl_variant *attribute_value;
    struct cfl_list *iterator;

    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest request =
        OPENTELEMETRY__PROTO__COLLECTOR__PROFILES__V1DEVELOPMENT__EXPORT_PROFILES_SERVICE_REQUEST__INIT;
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary dictionary =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__PROFILES_DICTIONARY__INIT;
    Opentelemetry__Proto__Profiles__V1development__ResourceProfiles resource_profiles =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__RESOURCE_PROFILES__INIT;
    Opentelemetry__Proto__Profiles__V1development__ScopeProfiles scope_profiles =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__SCOPE_PROFILES__INIT;
    Opentelemetry__Proto__Resource__V1__Resource resource =
        OPENTELEMETRY__PROTO__RESOURCE__V1__RESOURCE__INIT;
    Opentelemetry__Proto__Common__V1__InstrumentationScope scope =
        OPENTELEMETRY__PROTO__COMMON__V1__INSTRUMENTATION_SCOPE__INIT;
    Opentelemetry__Proto__Profiles__V1development__Profile profile =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__PROFILE__INIT;
    Opentelemetry__Proto__Profiles__V1development__KeyValueAndUnit attribute_entry =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__KEY_VALUE_AND_UNIT__INIT;
    Opentelemetry__Proto__Common__V1__AnyValue attribute_value_ref =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__KeyValue resource_attribute =
        OPENTELEMETRY__PROTO__COMMON__V1__KEY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__AnyValue resource_attribute_value_ref =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__KeyValue scope_attribute =
        OPENTELEMETRY__PROTO__COMMON__V1__KEY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__AnyValue scope_attribute_value_ref =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__INIT;
    char *string_table_entries[] = {
        "",
        "attr.key",
        "attr.value"
    };
    Opentelemetry__Proto__Profiles__V1development__KeyValueAndUnit *attribute_table_entries[] = {
        &attribute_entry
    };
    int32_t profile_attribute_indices[] = {
        0
    };
    Opentelemetry__Proto__Profiles__V1development__Profile *profiles[] = {
        &profile
    };
    Opentelemetry__Proto__Profiles__V1development__ScopeProfiles *scope_profiles_entries[] = {
        &scope_profiles
    };
    Opentelemetry__Proto__Profiles__V1development__ResourceProfiles *resource_profiles_entries[] = {
        &resource_profiles
    };
    Opentelemetry__Proto__Common__V1__KeyValue *resource_attributes[] = {
        &resource_attribute
    };
    Opentelemetry__Proto__Common__V1__KeyValue *scope_attributes[] = {
        &scope_attribute
    };

    attribute_value_ref.value_case =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE_STRINDEX;
    attribute_value_ref.string_value_strindex = 2;

    resource_attribute_value_ref.value_case =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE_STRINDEX;
    resource_attribute_value_ref.string_value_strindex = 2;

    scope_attribute_value_ref.value_case =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE_STRINDEX;
    scope_attribute_value_ref.string_value_strindex = 2;

    attribute_entry.key_strindex = 1;
    attribute_entry.value = &attribute_value_ref;

    resource_attribute.key_strindex = 1;
    resource_attribute.value = &resource_attribute_value_ref;

    scope_attribute.key_strindex = 1;
    scope_attribute.value = &scope_attribute_value_ref;

    dictionary.string_table = string_table_entries;
    dictionary.n_string_table = sizeof(string_table_entries) / sizeof(string_table_entries[0]);
    dictionary.attribute_table = attribute_table_entries;
    dictionary.n_attribute_table = sizeof(attribute_table_entries) / sizeof(attribute_table_entries[0]);

    resource.attributes = resource_attributes;
    resource.n_attributes = sizeof(resource_attributes) / sizeof(resource_attributes[0]);

    scope.attributes = scope_attributes;
    scope.n_attributes = sizeof(scope_attributes) / sizeof(scope_attributes[0]);

    profile.time_unix_nano = 1000;
    profile.duration_nano = 100;
    profile.attribute_indices = profile_attribute_indices;
    profile.n_attribute_indices = sizeof(profile_attribute_indices) / sizeof(profile_attribute_indices[0]);

    scope_profiles.scope = &scope;
    scope_profiles.profiles = profiles;
    scope_profiles.n_profiles = sizeof(profiles) / sizeof(profiles[0]);

    resource_profiles.resource = &resource;
    resource_profiles.scope_profiles = scope_profiles_entries;
    resource_profiles.n_scope_profiles = sizeof(scope_profiles_entries) / sizeof(scope_profiles_entries[0]);

    request.dictionary = &dictionary;
    request.resource_profiles = resource_profiles_entries;
    request.n_resource_profiles = sizeof(resource_profiles_entries) / sizeof(resource_profiles_entries[0]);

    decoded_context = NULL;
    result = decode_export_service_request(&decoded_context, &request);
    TEST_CHECK(result == CPROF_DECODE_OPENTELEMETRY_SUCCESS);
    TEST_CHECK(decoded_context != NULL);

    if (result == CPROF_DECODE_OPENTELEMETRY_SUCCESS && decoded_context != NULL) {
        TEST_CHECK(cfl_list_size(&decoded_context->profiles) == 1);
        if (cfl_list_size(&decoded_context->profiles) != 1) {
            cprof_decode_opentelemetry_destroy(decoded_context);
            return;
        }

        iterator = decoded_context->profiles.next;
        resource_profiles_context = cfl_list_entry(iterator, struct cprof_resource_profiles, _head);

        resource_attribute_value = cfl_kvlist_fetch(resource_profiles_context->resource->attributes, "attr.key");
        TEST_CHECK(resource_attribute_value != NULL);
        if (resource_attribute_value != NULL) {
            TEST_CHECK(resource_attribute_value->type == CFL_VARIANT_STRING);
            if (resource_attribute_value->type == CFL_VARIANT_STRING) {
                TEST_CHECK(strcmp(resource_attribute_value->data.as_string, "attr.value") == 0);
            }
        }

        TEST_CHECK(cfl_list_size(&resource_profiles_context->scope_profiles) == 1);
        if (cfl_list_size(&resource_profiles_context->scope_profiles) != 1) {
            cprof_decode_opentelemetry_destroy(decoded_context);
            return;
        }
        iterator = resource_profiles_context->scope_profiles.next;
        scope_profiles_context = cfl_list_entry(iterator, struct cprof_scope_profiles, _head);

        scope_attribute_value = cfl_kvlist_fetch(scope_profiles_context->scope->attributes, "attr.key");
        TEST_CHECK(scope_attribute_value != NULL);
        if (scope_attribute_value != NULL) {
            TEST_CHECK(scope_attribute_value->type == CFL_VARIANT_STRING);
            if (scope_attribute_value->type == CFL_VARIANT_STRING) {
                TEST_CHECK(strcmp(scope_attribute_value->data.as_string, "attr.value") == 0);
            }
        }

        TEST_CHECK(cfl_list_size(&scope_profiles_context->profiles) == 1);
        if (cfl_list_size(&scope_profiles_context->profiles) != 1) {
            cprof_decode_opentelemetry_destroy(decoded_context);
            return;
        }
        iterator = scope_profiles_context->profiles.next;
        profile_context = cfl_list_entry(iterator, struct cprof_profile, _head);

        attribute_value = cfl_kvlist_fetch(profile_context->attributes, "attr.key");
        TEST_CHECK(attribute_value != NULL);
        if (attribute_value != NULL) {
            TEST_CHECK(attribute_value->type == CFL_VARIANT_STRING);
            if (attribute_value->type == CFL_VARIANT_STRING) {
                TEST_CHECK(strcmp(attribute_value->data.as_string, "attr.value") == 0);
            }
        }

        cprof_decode_opentelemetry_destroy(decoded_context);
    }
}

static void test_decoder_dictionary_nested_string_references()
{
    int result;
    struct cprof *decoded_context;
    struct cprof_resource_profiles *resource_profiles_context;
    struct cprof_scope_profiles *scope_profiles_context;
    struct cfl_variant *resource_attribute_value;
    struct cfl_variant *scope_attribute_value;
    struct cfl_variant *array_entry;
    struct cfl_variant *nested_value;
    struct cfl_list *iterator;

    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest request =
        OPENTELEMETRY__PROTO__COLLECTOR__PROFILES__V1DEVELOPMENT__EXPORT_PROFILES_SERVICE_REQUEST__INIT;
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary dictionary =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__PROFILES_DICTIONARY__INIT;
    Opentelemetry__Proto__Profiles__V1development__ResourceProfiles resource_profiles =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__RESOURCE_PROFILES__INIT;
    Opentelemetry__Proto__Profiles__V1development__ScopeProfiles scope_profiles =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__SCOPE_PROFILES__INIT;
    Opentelemetry__Proto__Resource__V1__Resource resource =
        OPENTELEMETRY__PROTO__RESOURCE__V1__RESOURCE__INIT;
    Opentelemetry__Proto__Common__V1__InstrumentationScope scope =
        OPENTELEMETRY__PROTO__COMMON__V1__INSTRUMENTATION_SCOPE__INIT;
    Opentelemetry__Proto__Profiles__V1development__Profile profile =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__PROFILE__INIT;
    Opentelemetry__Proto__Common__V1__KeyValue resource_attribute =
        OPENTELEMETRY__PROTO__COMMON__V1__KEY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__AnyValue resource_attribute_value_ref =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__KeyValueList resource_kvlist =
        OPENTELEMETRY__PROTO__COMMON__V1__KEY_VALUE_LIST__INIT;
    Opentelemetry__Proto__Common__V1__KeyValue resource_nested_entry =
        OPENTELEMETRY__PROTO__COMMON__V1__KEY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__AnyValue resource_nested_value =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__KeyValue scope_attribute =
        OPENTELEMETRY__PROTO__COMMON__V1__KEY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__AnyValue scope_attribute_value_ref =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__ArrayValue scope_array =
        OPENTELEMETRY__PROTO__COMMON__V1__ARRAY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__AnyValue scope_array_string_entry =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__AnyValue scope_array_kvlist_entry =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__KeyValueList scope_kvlist =
        OPENTELEMETRY__PROTO__COMMON__V1__KEY_VALUE_LIST__INIT;
    Opentelemetry__Proto__Common__V1__KeyValue scope_nested_entry =
        OPENTELEMETRY__PROTO__COMMON__V1__KEY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__AnyValue scope_nested_value =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__INIT;
    char *string_table_entries[] = {
        "",
        "outer.key",
        "array.value",
        "inner.key",
        "inner.value"
    };
    Opentelemetry__Proto__Profiles__V1development__Profile *profiles[] = {
        &profile
    };
    Opentelemetry__Proto__Profiles__V1development__ScopeProfiles *scope_profiles_entries[] = {
        &scope_profiles
    };
    Opentelemetry__Proto__Profiles__V1development__ResourceProfiles *resource_profiles_entries[] = {
        &resource_profiles
    };
    Opentelemetry__Proto__Common__V1__KeyValue *resource_attributes[] = {
        &resource_attribute
    };
    Opentelemetry__Proto__Common__V1__KeyValue *scope_attributes[] = {
        &scope_attribute
    };
    Opentelemetry__Proto__Common__V1__KeyValue *resource_kvlist_entries[] = {
        &resource_nested_entry
    };
    Opentelemetry__Proto__Common__V1__KeyValue *scope_kvlist_entries[] = {
        &scope_nested_entry
    };
    Opentelemetry__Proto__Common__V1__AnyValue *scope_array_entries[] = {
        &scope_array_string_entry,
        &scope_array_kvlist_entry
    };

    resource_nested_value.value_case =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE_STRINDEX;
    resource_nested_value.string_value_strindex = 4;
    resource_nested_entry.key_strindex = 3;
    resource_nested_entry.value = &resource_nested_value;
    resource_kvlist.values = resource_kvlist_entries;
    resource_kvlist.n_values = sizeof(resource_kvlist_entries) / sizeof(resource_kvlist_entries[0]);
    resource_attribute_value_ref.value_case =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE;
    resource_attribute_value_ref.kvlist_value = &resource_kvlist;
    resource_attribute.key_strindex = 1;
    resource_attribute.value = &resource_attribute_value_ref;

    scope_array_string_entry.value_case =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE_STRINDEX;
    scope_array_string_entry.string_value_strindex = 2;
    scope_nested_value.value_case =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE_STRINDEX;
    scope_nested_value.string_value_strindex = 4;
    scope_nested_entry.key_strindex = 3;
    scope_nested_entry.value = &scope_nested_value;
    scope_kvlist.values = scope_kvlist_entries;
    scope_kvlist.n_values = sizeof(scope_kvlist_entries) / sizeof(scope_kvlist_entries[0]);
    scope_array_kvlist_entry.value_case =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE;
    scope_array_kvlist_entry.kvlist_value = &scope_kvlist;
    scope_array.values = scope_array_entries;
    scope_array.n_values = sizeof(scope_array_entries) / sizeof(scope_array_entries[0]);
    scope_attribute_value_ref.value_case =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE;
    scope_attribute_value_ref.array_value = &scope_array;
    scope_attribute.key_strindex = 1;
    scope_attribute.value = &scope_attribute_value_ref;

    dictionary.string_table = string_table_entries;
    dictionary.n_string_table = sizeof(string_table_entries) / sizeof(string_table_entries[0]);

    resource.attributes = resource_attributes;
    resource.n_attributes = sizeof(resource_attributes) / sizeof(resource_attributes[0]);

    scope.attributes = scope_attributes;
    scope.n_attributes = sizeof(scope_attributes) / sizeof(scope_attributes[0]);

    profile.time_unix_nano = 1000;
    profile.duration_nano = 100;

    scope_profiles.scope = &scope;
    scope_profiles.profiles = profiles;
    scope_profiles.n_profiles = sizeof(profiles) / sizeof(profiles[0]);

    resource_profiles.resource = &resource;
    resource_profiles.scope_profiles = scope_profiles_entries;
    resource_profiles.n_scope_profiles = sizeof(scope_profiles_entries) / sizeof(scope_profiles_entries[0]);

    request.dictionary = &dictionary;
    request.resource_profiles = resource_profiles_entries;
    request.n_resource_profiles = sizeof(resource_profiles_entries) / sizeof(resource_profiles_entries[0]);

    decoded_context = NULL;
    result = decode_export_service_request(&decoded_context, &request);
    TEST_CHECK(result == CPROF_DECODE_OPENTELEMETRY_SUCCESS);
    TEST_CHECK(decoded_context != NULL);

    if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS || decoded_context == NULL) {
        return;
    }

    iterator = decoded_context->profiles.next;
    resource_profiles_context = cfl_list_entry(iterator, struct cprof_resource_profiles, _head);

    resource_attribute_value = cfl_kvlist_fetch(resource_profiles_context->resource->attributes, "outer.key");
    TEST_CHECK(resource_attribute_value != NULL);
    if (resource_attribute_value != NULL) {
        TEST_CHECK(resource_attribute_value->type == CFL_VARIANT_KVLIST);
        if (resource_attribute_value->type == CFL_VARIANT_KVLIST) {
            nested_value = cfl_kvlist_fetch(resource_attribute_value->data.as_kvlist, "inner.key");
            TEST_CHECK(nested_value != NULL);
            if (nested_value != NULL) {
                TEST_CHECK(nested_value->type == CFL_VARIANT_STRING);
                if (nested_value->type == CFL_VARIANT_STRING) {
                    TEST_CHECK(strcmp(nested_value->data.as_string, "inner.value") == 0);
                }
            }
        }
    }

    iterator = resource_profiles_context->scope_profiles.next;
    scope_profiles_context = cfl_list_entry(iterator, struct cprof_scope_profiles, _head);

    scope_attribute_value = cfl_kvlist_fetch(scope_profiles_context->scope->attributes, "outer.key");
    TEST_CHECK(scope_attribute_value != NULL);
    if (scope_attribute_value != NULL) {
        TEST_CHECK(scope_attribute_value->type == CFL_VARIANT_ARRAY);
        if (scope_attribute_value->type == CFL_VARIANT_ARRAY) {
            TEST_CHECK(cfl_array_size(scope_attribute_value->data.as_array) == 2);

            array_entry = cfl_array_fetch_by_index(scope_attribute_value->data.as_array, 0);
            TEST_CHECK(array_entry != NULL);
            if (array_entry != NULL) {
                TEST_CHECK(array_entry->type == CFL_VARIANT_STRING);
                if (array_entry->type == CFL_VARIANT_STRING) {
                    TEST_CHECK(strcmp(array_entry->data.as_string, "array.value") == 0);
                }
            }

            array_entry = cfl_array_fetch_by_index(scope_attribute_value->data.as_array, 1);
            TEST_CHECK(array_entry != NULL);
            if (array_entry != NULL) {
                TEST_CHECK(array_entry->type == CFL_VARIANT_KVLIST);
                if (array_entry->type == CFL_VARIANT_KVLIST) {
                    nested_value = cfl_kvlist_fetch(array_entry->data.as_kvlist, "inner.key");
                    TEST_CHECK(nested_value != NULL);
                    if (nested_value != NULL) {
                        TEST_CHECK(nested_value->type == CFL_VARIANT_STRING);
                        if (nested_value->type == CFL_VARIANT_STRING) {
                            TEST_CHECK(strcmp(nested_value->data.as_string, "inner.value") == 0);
                        }
                    }
                }
            }
        }
    }

    cprof_decode_opentelemetry_destroy(decoded_context);
}

static void test_decoder_rejects_missing_string_table_for_resource_attributes()
{
    int result;
    struct cprof *decoded_context;

    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest request =
        OPENTELEMETRY__PROTO__COLLECTOR__PROFILES__V1DEVELOPMENT__EXPORT_PROFILES_SERVICE_REQUEST__INIT;
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary dictionary =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__PROFILES_DICTIONARY__INIT;
    Opentelemetry__Proto__Profiles__V1development__ResourceProfiles resource_profiles =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__RESOURCE_PROFILES__INIT;
    Opentelemetry__Proto__Profiles__V1development__ScopeProfiles scope_profiles =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__SCOPE_PROFILES__INIT;
    Opentelemetry__Proto__Resource__V1__Resource resource =
        OPENTELEMETRY__PROTO__RESOURCE__V1__RESOURCE__INIT;
    Opentelemetry__Proto__Profiles__V1development__Profile profile =
        OPENTELEMETRY__PROTO__PROFILES__V1DEVELOPMENT__PROFILE__INIT;
    Opentelemetry__Proto__Common__V1__KeyValue resource_attribute =
        OPENTELEMETRY__PROTO__COMMON__V1__KEY_VALUE__INIT;
    Opentelemetry__Proto__Common__V1__AnyValue resource_attribute_value_ref =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__INIT;
    Opentelemetry__Proto__Profiles__V1development__Profile *profiles[] = {
        &profile
    };
    Opentelemetry__Proto__Profiles__V1development__ScopeProfiles *scope_profiles_entries[] = {
        &scope_profiles
    };
    Opentelemetry__Proto__Profiles__V1development__ResourceProfiles *resource_profiles_entries[] = {
        &resource_profiles
    };
    Opentelemetry__Proto__Common__V1__KeyValue *resource_attributes[] = {
        &resource_attribute
    };

    resource_attribute_value_ref.value_case =
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE_STRINDEX;
    resource_attribute_value_ref.string_value_strindex = 1;
    resource_attribute.key_strindex = 1;
    resource_attribute.value = &resource_attribute_value_ref;

    resource.attributes = resource_attributes;
    resource.n_attributes = sizeof(resource_attributes) / sizeof(resource_attributes[0]);

    profile.time_unix_nano = 1000;
    profile.duration_nano = 100;

    scope_profiles.profiles = profiles;
    scope_profiles.n_profiles = sizeof(profiles) / sizeof(profiles[0]);

    resource_profiles.resource = &resource;
    resource_profiles.scope_profiles = scope_profiles_entries;
    resource_profiles.n_scope_profiles = sizeof(scope_profiles_entries) / sizeof(scope_profiles_entries[0]);

    request.dictionary = &dictionary;
    request.resource_profiles = resource_profiles_entries;
    request.n_resource_profiles = sizeof(resource_profiles_entries) / sizeof(resource_profiles_entries[0]);

    decoded_context = NULL;
    result = decode_export_service_request(&decoded_context, &request);
    TEST_CHECK(result == CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR);
    TEST_CHECK(decoded_context == NULL);
}

static void test_decoder_rejects_invalid_stack_table_reference()
{
    int result;
    struct cprof *decoded_context;
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *request;
    Opentelemetry__Proto__Profiles__V1development__Stack **original_stack_table;
    size_t original_stack_table_count;

    request = create_unpacked_dictionary_request();
    TEST_CHECK(request != NULL);
    if (request == NULL) {
        return;
    }

    original_stack_table = request->dictionary->stack_table;
    original_stack_table_count = request->dictionary->n_stack_table;
    request->dictionary->stack_table = NULL;
    request->dictionary->n_stack_table = 0;
    request->resource_profiles[0]->scope_profiles[0]->profiles[0]->samples[0]->stack_index = 0;

    decoded_context = NULL;
    result = decode_export_service_request(&decoded_context, request);
    TEST_CHECK(result == CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR);
    TEST_CHECK(decoded_context == NULL);

    request->dictionary->stack_table = original_stack_table;
    request->dictionary->n_stack_table = original_stack_table_count;

    opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
        request, NULL);
}

static void test_decoder_rejects_invalid_location_mapping_reference()
{
    int result;
    struct cprof *decoded_context;
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *request;
    size_t index;
    Opentelemetry__Proto__Profiles__V1development__Location *location_entry;

    request = create_unpacked_dictionary_request();
    TEST_CHECK(request != NULL);
    if (request == NULL) {
        return;
    }

    location_entry = NULL;
    for (index = 0; index < request->dictionary->n_location_table; index++) {
        if (request->dictionary->location_table[index] != NULL) {
            location_entry = request->dictionary->location_table[index];
            break;
        }
    }

    TEST_CHECK(location_entry != NULL);
    if (location_entry == NULL) {
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
            request, NULL);
        return;
    }

    location_entry->mapping_index = request->dictionary->n_mapping_table;

    decoded_context = NULL;
    result = decode_export_service_request(&decoded_context, request);
    TEST_CHECK(result == CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR);
    TEST_CHECK(decoded_context == NULL);

    opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
        request, NULL);
}

static void test_decoder_rejects_invalid_line_function_reference()
{
    int result;
    struct cprof *decoded_context;
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *request;
    size_t index;
    size_t line_index;
    Opentelemetry__Proto__Profiles__V1development__Location *location_entry;

    request = create_unpacked_dictionary_request();
    TEST_CHECK(request != NULL);
    if (request == NULL) {
        return;
    }

    location_entry = NULL;
    for (index = 0; index < request->dictionary->n_location_table; index++) {
        if (request->dictionary->location_table[index] != NULL &&
            request->dictionary->location_table[index]->n_lines > 0) {
            location_entry = request->dictionary->location_table[index];
            break;
        }
    }

    TEST_CHECK(location_entry != NULL);
    if (location_entry == NULL) {
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
            request, NULL);
        return;
    }

    for (line_index = 0; line_index < location_entry->n_lines; line_index++) {
        if (location_entry->lines[line_index] != NULL) {
            location_entry->lines[line_index]->function_index = request->dictionary->n_function_table;
            break;
        }
    }

    TEST_CHECK(line_index < location_entry->n_lines);
    if (line_index >= location_entry->n_lines) {
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
            request, NULL);
        return;
    }

    decoded_context = NULL;
    result = decode_export_service_request(&decoded_context, request);
    TEST_CHECK(result == CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR);
    TEST_CHECK(decoded_context == NULL);

    opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
        request, NULL);
}

static void test_decoder_rejects_invalid_profile_attribute_reference()
{
    int result;
    struct cprof *decoded_context;
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *request;
    Opentelemetry__Proto__Profiles__V1development__Profile *profile;

    request = create_unpacked_dictionary_request();
    TEST_CHECK(request != NULL);
    if (request == NULL) {
        return;
    }

    profile = request->resource_profiles[0]->scope_profiles[0]->profiles[0];
    TEST_CHECK(profile != NULL);
    if (profile == NULL) {
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
            request, NULL);
        return;
    }

    profile->attribute_indices = realloc(profile->attribute_indices, sizeof(int32_t));
    TEST_CHECK(profile->attribute_indices != NULL);
    if (profile->attribute_indices == NULL) {
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
            request, NULL);
        return;
    }
    profile->n_attribute_indices = 1;
    profile->attribute_indices[0] = request->dictionary->n_attribute_table;

    decoded_context = NULL;
    result = decode_export_service_request(&decoded_context, request);
    TEST_CHECK(result == CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR);
    TEST_CHECK(decoded_context == NULL);

    opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
        request, NULL);
}

static void test_decoder_rejects_invalid_sample_attribute_reference()
{
    int result;
    struct cprof *decoded_context;
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *request;
    Opentelemetry__Proto__Profiles__V1development__Profile *profile;
    Opentelemetry__Proto__Profiles__V1development__Sample *sample;

    request = create_unpacked_dictionary_request();
    TEST_CHECK(request != NULL);
    if (request == NULL) {
        return;
    }

    profile = request->resource_profiles[0]->scope_profiles[0]->profiles[0];
    sample = profile->samples[0];
    TEST_CHECK(sample != NULL);
    if (sample == NULL) {
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
            request, NULL);
        return;
    }

    sample->attribute_indices = realloc(sample->attribute_indices, sizeof(int32_t));
    TEST_CHECK(sample->attribute_indices != NULL);
    if (sample->attribute_indices == NULL) {
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
            request, NULL);
        return;
    }
    sample->n_attribute_indices = 1;
    sample->attribute_indices[0] = request->dictionary->n_attribute_table;

    decoded_context = NULL;
    result = decode_export_service_request(&decoded_context, request);
    TEST_CHECK(result == CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR);
    TEST_CHECK(decoded_context == NULL);

    opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
        request, NULL);
}

static void test_decoder_rejects_invalid_sample_link_reference()
{
    int result;
    struct cprof *decoded_context;
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *request;
    Opentelemetry__Proto__Profiles__V1development__Profile *profile;
    Opentelemetry__Proto__Profiles__V1development__Sample *sample;

    request = create_unpacked_dictionary_request();
    TEST_CHECK(request != NULL);
    if (request == NULL) {
        return;
    }

    profile = request->resource_profiles[0]->scope_profiles[0]->profiles[0];
    sample = profile->samples[0];
    TEST_CHECK(sample != NULL);
    if (sample == NULL) {
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
            request, NULL);
        return;
    }

    sample->link_index = request->dictionary->n_link_table;

    decoded_context = NULL;
    result = decode_export_service_request(&decoded_context, request);
    TEST_CHECK(result == CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR);
    TEST_CHECK(decoded_context == NULL);

    opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(
        request, NULL);
}

TEST_LIST = {
    {"encoder", test_encoder},
    {"decoder", test_decoder},
    {"encoder_dictionary_tables", test_encoder_dictionary_tables},
    {"wire_format_dictionary_present", test_wire_format_dictionary_present},
    {"decoder_dictionary_tables", test_decoder_dictionary_tables},
    {"decoder_dictionary_string_references", test_decoder_dictionary_string_references},
    {"decoder_dictionary_nested_string_references", test_decoder_dictionary_nested_string_references},
    {"decoder_rejects_missing_string_table_for_resource_attributes",
     test_decoder_rejects_missing_string_table_for_resource_attributes},
    {"decoder_rejects_invalid_stack_table_reference", test_decoder_rejects_invalid_stack_table_reference},
    {"decoder_rejects_invalid_location_mapping_reference",
     test_decoder_rejects_invalid_location_mapping_reference},
    {"decoder_rejects_invalid_line_function_reference",
     test_decoder_rejects_invalid_line_function_reference},
    {"decoder_rejects_invalid_profile_attribute_reference",
     test_decoder_rejects_invalid_profile_attribute_reference},
    {"decoder_rejects_invalid_sample_attribute_reference",
     test_decoder_rejects_invalid_sample_attribute_reference},
    {"decoder_rejects_invalid_sample_link_reference",
     test_decoder_rejects_invalid_sample_link_reference},
    { 0 }
};
