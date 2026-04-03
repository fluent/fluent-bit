/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_PLUGIN_ALIAS_H
#define FLB_PLUGIN_ALIAS_H

#include <stddef.h>

/*
 * Returned by flb_plugin_alias_rewrite() when an alias exists but an internal
 * error prevents generating a rewritten string.
 */
#define FLB_PLUGIN_ALIAS_ERR ((char *) -1)

/*
 * Returns the canonical plugin name for alias_name when a mapping exists,
 * otherwise returns NULL.
 */
const char *flb_plugin_alias_get(int plugin_type, const char *alias_name,
                                 size_t alias_name_length);

/*
 * Rewrites plugin_reference when it starts with a known alias.
 *
 * Return values:
 *   - NULL: no rewrite needed
 *   - FLB_PLUGIN_ALIAS_ERR: rewrite needed but failed
 *   - allocated string: rewritten plugin reference (caller must free)
 */
char *flb_plugin_alias_rewrite(int plugin_type, const char *plugin_reference);

#endif
