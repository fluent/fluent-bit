/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "we.h"
#include "we_wmi.h"

int we_wmi_init(struct flb_we *ctx)
{
    return 0;
}

int we_wmi_exit(struct flb_we *ctx)
{
    return 0;
}

/*
https://stackoverflow.com/questions/33033111/create-com-object-using-plain-c
https://stackoverflow.com/questions/1431103/how-to-obtain-data-from-wmi-using-a-c-application
https://stackoverflow.com/questions/626674/wmi-queries-in-c
https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/WmiSdk/example--getting-wmi-data-from-the-local-computer.md
https://docs.microsoft.com/en-us/windows/win32/wmisdk/creating-wmi-clients
*/
