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

#ifndef FLB_ML_MODE_H
#define FLB_ML_MODE_H

struct flb_ml *flb_ml_mode_create(struct flb_config *config, char *mode,
                                  int flush_ms, char *key);

/* Python language mode */
struct flb_ml *flb_ml_mode_python(struct flb_config *config,
                                  int flush_ms, char *key);

/* Java language mode */
struct flb_ml *flb_ml_mode_java(struct flb_config *config,
                                int flush_ms, char *key);

/* Go language mode */
struct flb_ml *flb_ml_mode_go(struct flb_config *config,
                              int flush_ms, char *key);

#endif
