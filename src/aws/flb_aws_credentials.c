/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>

#include <jsmn/jsmn.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#define TEN_MINUTES    600
#define TWELVE_HOURS   43200

/* Credentials Environment Variables */
#define AWS_ACCESS_KEY_ID              "AWS_ACCESS_KEY_ID"
#define AWS_SECRET_ACCESS_KEY          "AWS_SECRET_ACCESS_KEY"
#define AWS_SESSION_TOKEN              "AWS_SESSION_TOKEN"


/* Environment Provider */
struct flb_aws_credentials *get_credentials_fn_environment(struct
                                                           flb_aws_provider
                                                           *provider)
{
    char *access_key = NULL;
    char *secret_key = NULL;
    char *session_token = NULL;
    struct flb_aws_credentials *creds = NULL;

    flb_debug("[aws_credentials] Requesting credentials from the "
              "env provider..");

    access_key = getenv(AWS_ACCESS_KEY_ID);
    if (!access_key || strlen(access_key) <= 0) {
        return NULL;
    }

    secret_key = getenv(AWS_SECRET_ACCESS_KEY);
    if (!secret_key || strlen(secret_key) <= 0) {
        return NULL;
    }

    creds = flb_malloc(sizeof(struct flb_aws_credentials));
    if (!creds) {
        flb_errno();
        return NULL;
    }

    creds->access_key_id = flb_sds_create(access_key);
    if (!creds->access_key_id) {
        flb_aws_credentials_destroy(creds);
        flb_errno();
        return NULL;
    }

    creds->secret_access_key = flb_sds_create(secret_key);
    if (!creds->secret_access_key) {
        flb_aws_credentials_destroy(creds);
        flb_errno();
        return NULL;
    }

    session_token = getenv(AWS_SESSION_TOKEN);
    if (session_token && strlen(session_token) > 0) {
        creds->session_token = flb_sds_create(session_token);
        if (!creds->session_token) {
            flb_aws_credentials_destroy(creds);
            flb_errno();
            return NULL;
        }
    } else {
        creds->session_token = NULL;
    }

    return creds;

}

int refresh_env(struct flb_aws_provider *provider)
{
    char *access_key = NULL;
    char *secret_key = NULL;

    access_key = getenv(AWS_ACCESS_KEY_ID);
    if (!access_key || strlen(access_key) <= 0) {
        return -1;
    }

    secret_key = getenv(AWS_SECRET_ACCESS_KEY);
    if (!secret_key || strlen(secret_key) <= 0) {
        return -1;
    }

    return 0;
}

/*
 * For the env provider, refresh simply checks if the environment
 * variables are available.
 */
int refresh_fn_environment(struct flb_aws_provider *provider)
{
    flb_debug("[aws_credentials] Refresh called on the env provider");

    return refresh_env(provider);
}

/*
 * sync and async are no-ops for the env provider because it does not make
 * network IO calls
 */
void sync_fn_environment(struct flb_aws_provider *provider)
{
    return;
}

void async_fn_environment(struct flb_aws_provider *provider)
{
    return;
}

/* Destroy is a no-op for the env provider */
void destroy_fn_environment(struct flb_aws_provider *provider) {
    return;
}

static struct flb_aws_provider_vtable environment_provider_vtable = {
    .get_credentials = get_credentials_fn_environment,
    .refresh = refresh_fn_environment,
    .destroy = destroy_fn_environment,
    .sync = sync_fn_environment,
    .async = async_fn_environment,
};

struct flb_aws_provider *flb_aws_env_provider_create() {
    struct flb_aws_provider *provider = flb_calloc(1, sizeof(
                                                   struct flb_aws_provider));

    if (!provider) {
        flb_errno();
        return NULL;
    }

    provider->provider_vtable = &environment_provider_vtable;
    provider->implementation = NULL;

    return provider;
}


void flb_aws_credentials_destroy(struct flb_aws_credentials *creds)
{
    if (creds) {
        if (creds->access_key_id) {
            flb_sds_destroy(creds->access_key_id);
        }
        if (creds->secret_access_key) {
            flb_sds_destroy(creds->secret_access_key);
        }
        if (creds->secret_access_key) {
            flb_sds_destroy(creds->session_token);
        }

        flb_free(creds);
    }
}

void flb_aws_provider_destroy(struct flb_aws_provider *provider)
{
    if (provider) {
        if (provider->implementation) {
            provider->provider_vtable->destroy(provider);
        }

        flb_free(provider);
    }
}

time_t timestamp_to_epoch(const char *timestamp)
{
    struct tm tm = {0};
    time_t seconds;
    int r;

    r = sscanf(timestamp, "%d-%d-%dT%d:%d:%dZ", &tm.tm_year, &tm.tm_mon,
               &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    if (r != 6) {
        return -1;
    }

    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    tm.tm_isdst = -1;
    seconds = timegm(&tm);
    if (seconds < 0) {
        return -1;
    }

    return seconds;
}

time_t flb_aws_cred_expiration(const char *timestamp)
{
    time_t now;
    time_t expiration = timestamp_to_epoch(timestamp);
    if (expiration < 0) {
        flb_warn("[aws_credentials] Could not parse expiration: %s", timestamp);
        return -1;
    }
    /*
     * Sanity check - expiration should be ~10 minutes to 12 hours in the future
     * < 10 minutes is problematic because the provider auto-refreshes if creds
     * expire in 5 minutes. Disabling auto-refresh reduces requests for creds.
     * (The flb_aws_client will still force a refresh of creds and then retry
     * if it receives an auth error).
     * (> 12 hours is impossible with the current APIs and would likely indicate
     *  a bug in how this code processes timestamps.)
     */
     now = time(NULL);
     if (expiration < (now + TEN_MINUTES)) {
         flb_warn("[aws_credentials] Credential expiration '%s' is less than"
                  "10 minutes in the future. Disabling auto-refresh.",
                  timestamp);
         return -1;
     }
     if (expiration > (now + TWELVE_HOURS)) {
         flb_warn("[aws_credentials] Credential expiration '%s' is greater than"
                  "12 hours in the future. This should not be possible.",
                  timestamp);
     }
     return expiration;
}

int flb_read_file(const char *path, char **out_buf, size_t *out_size)
{
    int ret;
    long bytes;
    char *buf = NULL;
    FILE *fp = NULL;
    struct stat st;

    ret = stat(path, &st);
    if (ret == -1) {
        return -1;
    }

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    buf = flb_malloc(st.st_size + sizeof(char));
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    bytes = fread(buf, st.st_size, 1, fp);
    if (bytes != 1) {
        flb_errno();
        flb_free(buf);
        fclose(fp);
        return -1;
    }

    /* fread does not add null byte */
    buf[st.st_size] = '\0';

    fclose(fp);
    *out_buf = buf;
    *out_size = st.st_size;

    return 0;
}

/*
 * Fluent Bit is single-threaded but asynchonous. Only one co-routine will
 * be running at a time, and they only pause/resume for IO.
 *
 * Thus, while synchronization is needed (to prevent multiple co-routines
 * from duplicating effort and performing the same work), it can be obtained
 * using a simple integer flag on the provider.
 */

/* Like a traditional try lock- it does not block if the lock is not obtained */
int try_lock_provider(struct flb_aws_provider *provider)
{
    if (provider->locked == FLB_TRUE) {
        return FLB_FALSE;
    }
    provider->locked = FLB_TRUE;
    return FLB_TRUE;
}

void unlock_provider(struct flb_aws_provider *provider)
{
    if (provider->locked == FLB_TRUE) {
        provider->locked = FLB_FALSE;
    }
}
