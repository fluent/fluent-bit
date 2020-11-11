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

#define TEN_MINUTES    600
#define TWELVE_HOURS   43200

/* Credentials Environment Variables */
#define AWS_ACCESS_KEY_ID              "AWS_ACCESS_KEY_ID"
#define AWS_SECRET_ACCESS_KEY          "AWS_SECRET_ACCESS_KEY"
#define AWS_SESSION_TOKEN              "AWS_SESSION_TOKEN"


/*
 * The standard credential provider chain:
 * 1. Environment variables
 * 2. Shared credentials file (AWS Profile)
 * 3. EKS OIDC
 * 4. EC2 IMDS
 * 5. ECS HTTP credentials endpoint
 *
 * This provider will evaluate each provider in order, returning the result
 * from the first provider that returns valid credentials.
 *
 * Note: Client code should use this provider by default.
 */
struct flb_aws_provider_chain {
    struct mk_list sub_providers;

    /*
     * The standard chain provider picks the first successful provider and
     * then uses it until a call to refresh is made.
     */
    struct flb_aws_provider *sub_provider;
};

/*
 * Iterates through the chain and returns credentials from the first provider
 * that successfully returns creds. Caches this provider on the implementation.
 */
struct flb_aws_credentials *get_from_chain(struct flb_aws_provider_chain
                                           *implementation)
{
    struct flb_aws_provider *sub_provider = NULL;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_aws_credentials *creds = NULL;

    /* find the first provider that produces a valid set of creds */
    mk_list_foreach_safe(head, tmp, &implementation->sub_providers) {
        sub_provider = mk_list_entry(head,
                                     struct flb_aws_provider,
                                     _head);
        creds = sub_provider->provider_vtable->get_credentials(sub_provider);
        if (creds) {
            implementation->sub_provider = sub_provider;
            return creds;
        }
    }

    return NULL;
}

struct flb_aws_credentials *get_credentials_fn_standard_chain(struct
                                                              flb_aws_provider
                                                              *provider)
{
    struct flb_aws_credentials *creds = NULL;
    struct flb_aws_provider_chain *implementation = provider->implementation;
    struct flb_aws_provider *sub_provider = implementation->sub_provider;

    if (sub_provider) {
        return sub_provider->provider_vtable->get_credentials(sub_provider);
    }

    if (try_lock_provider(provider)) {
        creds = get_from_chain(implementation);
        unlock_provider(provider);
        return creds;
    }

    /*
     * We failed to lock the provider and sub_provider is unset. This means that
     * another co-routine is selecting a provider from the chain.
     */
    flb_warn("[aws_credentials] No cached credentials are available and "
             "a credential refresh is already in progress. The current "
             "co-routine will retry.");
    return NULL;
}

int init_fn_standard_chain(struct flb_aws_provider *provider)
{
    struct flb_aws_provider_chain *implementation = provider->implementation;
    struct flb_aws_provider *sub_provider = NULL;
    struct mk_list *tmp;
    struct mk_list *head;
    int ret = -1;

    if (try_lock_provider(provider)) {
        /* find the first provider that indicates successful init */
        mk_list_foreach_safe(head, tmp, &implementation->sub_providers) {
            sub_provider = mk_list_entry(head,
                                         struct flb_aws_provider,
                                         _head);
            ret = sub_provider->provider_vtable->init(sub_provider);
            if (ret >= 0) {
                implementation->sub_provider = sub_provider;
                break;
            }
        }
        unlock_provider(provider);
    }

    return ret;
}

/*
 * Client code should only call refresh if there has been an
 * error from the AWS APIs indicating creds are expired/invalid.
 * Refresh may change the current sub_provider.
 */
int refresh_fn_standard_chain(struct flb_aws_provider *provider)
{
    struct flb_aws_provider_chain *implementation = provider->implementation;
    struct flb_aws_provider *sub_provider = NULL;
    struct mk_list *tmp;
    struct mk_list *head;
    int ret = -1;

    if (try_lock_provider(provider)) {
        /* find the first provider that indicates successful refresh */
        mk_list_foreach_safe(head, tmp, &implementation->sub_providers) {
            sub_provider = mk_list_entry(head,
                                         struct flb_aws_provider,
                                         _head);
            ret = sub_provider->provider_vtable->refresh(sub_provider);
            if (ret >= 0) {
                implementation->sub_provider = sub_provider;
                break;
            }
        }
        unlock_provider(provider);
    }

    return ret;
}

void sync_fn_standard_chain(struct flb_aws_provider *provider)
{
    struct flb_aws_provider_chain *implementation = provider->implementation;
    struct flb_aws_provider *sub_provider = NULL;
    struct mk_list *tmp;
    struct mk_list *head;

    /* set all providers to sync mode */
    mk_list_foreach_safe(head, tmp, &implementation->sub_providers) {
        sub_provider = mk_list_entry(head,
                                     struct flb_aws_provider,
                                     _head);
        sub_provider->provider_vtable->sync(sub_provider);
    }
}

void async_fn_standard_chain(struct flb_aws_provider *provider)
{
    struct flb_aws_provider_chain *implementation = provider->implementation;
    struct flb_aws_provider *sub_provider = NULL;
    struct mk_list *tmp;
    struct mk_list *head;

    /* set all providers to async mode */
    mk_list_foreach_safe(head, tmp, &implementation->sub_providers) {
        sub_provider = mk_list_entry(head,
                                     struct flb_aws_provider,
                                     _head);
        sub_provider->provider_vtable->async(sub_provider);
    }
}

void destroy_fn_standard_chain(struct flb_aws_provider *provider) {
    struct flb_aws_provider *sub_provider;
    struct flb_aws_provider_chain *implementation;
    struct mk_list *tmp;
    struct mk_list *head;

    implementation = provider->implementation;

    if (implementation) {
        mk_list_foreach_safe(head, tmp, &implementation->sub_providers) {
            sub_provider = mk_list_entry(head, struct flb_aws_provider,
                                         _head);
            mk_list_del(&sub_provider->_head);
            flb_aws_provider_destroy(sub_provider);
        }

        flb_free(implementation);
    }
}

static struct flb_aws_provider_vtable standard_chain_provider_vtable = {
    .get_credentials = get_credentials_fn_standard_chain,
    .init = init_fn_standard_chain,
    .refresh = refresh_fn_standard_chain,
    .destroy = destroy_fn_standard_chain,
    .sync = sync_fn_standard_chain,
    .async = async_fn_standard_chain,
};

struct flb_aws_provider *flb_standard_chain_provider_create(struct flb_config
                                                            *config,
                                                            struct flb_tls *tls,
                                                            char *region,
                                                            char *sts_endpoint,
                                                            char *proxy,
                                                            struct
                                                            flb_aws_client_generator
                                                            *generator)
{
    struct flb_aws_provider *sub_provider;
    struct flb_aws_provider *provider;
    struct flb_aws_provider_chain *implementation;

    provider = flb_calloc(1, sizeof(struct flb_aws_provider));

    if (!provider) {
        flb_errno();
        return NULL;
    }

    implementation = flb_calloc(1, sizeof(struct flb_aws_provider_chain));

    if (!implementation) {
        flb_errno();
        flb_free(provider);
        return NULL;
    }

    provider->provider_vtable = &standard_chain_provider_vtable;
    provider->implementation = implementation;

    /* Create chain of providers */
    mk_list_init(&implementation->sub_providers);

    sub_provider = flb_aws_env_provider_create();
    if (!sub_provider) {
        /* Env provider will only fail creation if a memory alloc failed */
        flb_aws_provider_destroy(provider);
        return NULL;
    }
    flb_debug("[aws_credentials] Initialized Env Provider in standard chain");

    mk_list_add(&sub_provider->_head, &implementation->sub_providers);

    sub_provider = flb_profile_provider_create();
    if (sub_provider) {
        /* Profile provider can fail if HOME env var is not set */;
        mk_list_add(&sub_provider->_head, &implementation->sub_providers);
        flb_debug("[aws_credentials] Initialized AWS Profile Provider in "
                  "standard chain");
    }

    sub_provider = flb_eks_provider_create(config, tls, region, sts_endpoint, proxy, generator);
    if (sub_provider) {
        /* EKS provider can fail if we are not running in k8s */;
        mk_list_add(&sub_provider->_head, &implementation->sub_providers);
        flb_debug("[aws_credentials] Initialized EKS Provider in standard chain");
    }

    sub_provider = flb_ec2_provider_create(config, generator);
    if (!sub_provider) {
        /* EC2 provider will only fail creation if a memory alloc failed */
        flb_aws_provider_destroy(provider);
        return NULL;
    }
    mk_list_add(&sub_provider->_head, &implementation->sub_providers);
    flb_debug("[aws_credentials] Initialized EC2 Provider in standard chain");

    sub_provider = flb_ecs_provider_create(config, generator);
    if (sub_provider) {
        /* ECS Provider will fail creation if we are not running in ECS */
        mk_list_add(&sub_provider->_head, &implementation->sub_providers);
        flb_debug("[aws_credentials] Initialized ECS Provider in standard chain");
    }

    return provider;
}

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

int init_fn_environment(struct flb_aws_provider *provider)
{
    flb_debug("[aws_credentials] Init called on the env provider");

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
    .init = init_fn_environment,
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
        if (creds->session_token) {
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
