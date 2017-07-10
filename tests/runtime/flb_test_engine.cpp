/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

pthread_mutex_t result_mutex;
bool result;

int callback_test(void* data, size_t size)
{
    if (size > 0) {
        free(data);
        pthread_mutex_lock(&result_mutex);
        result = true;/* success */
        pthread_mutex_unlock(&result_mutex);
    }
    return 0;
}

int check_routing(const char* tag, const char* match, bool expect)
{
    int in_ffd;
    int out_ffd;
    bool          ret    = false;
    flb_ctx_t    *ctx    = NULL;
    char         *str    = (char*)"[1, {\"key\":\"value\"}]";

    /* initialize */
    ret = pthread_mutex_init(&result_mutex, NULL);
    result = false;
    EXPECT_EQ(ret, 0);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", tag, NULL);

    out_ffd = flb_output(ctx, (char *) "lib", (void*)callback_test);
    EXPECT_TRUE(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", match, NULL);

    flb_service_set(ctx, "Flush", "1", "Daemon", "false", NULL);

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    /* start test */
    flb_lib_push(ctx, in_ffd, str, strlen(str));
    sleep(1);/*waiting flush*/

    pthread_mutex_lock(&result_mutex);
    ret = result;
    pthread_mutex_unlock(&result_mutex);
    EXPECT_EQ(ret, expect);

    /* finalize */
    flb_stop(ctx);
    flb_destroy(ctx);

    ret = pthread_mutex_destroy(&result_mutex);
    EXPECT_EQ(ret, 0);

    return 0;
}

TEST(Engine, wildcard)
{
    struct test_wildcard_fmt {
        const char* tag;
        const char* match;
        bool        expect;
    };
    int i = 0;

    test_wildcard_fmt checklist[] =
    {
        {"cpu.rpi","cpu.rpi", true  },
        {"cpu.rpi","cpu.ard", false },
        {"cpu.rpi","cpu.*",   true  },
        {"cpu.rpi","*",       true  },
        {"cpu.rpi","*.*",     true  },
        {"cpu.rpi","*.rpi",   true  },
        {"cpu.rpi","mem.*",   false },
        {"cpu.rpi","*u.r*",   true  },
        {NULL, NULL, 0}
    };

    while(checklist[i].tag != NULL){
        check_routing(checklist[i].tag,
                      checklist[i].match,
                      checklist[i].expect);
        i++;
    }
}
