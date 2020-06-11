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

#define AWS_IMDS_ROLE_PATH      "/latest/meta-data/iam/security-credentials/"
#define AWS_IMDS_ROLE_PATH_LEN  43

#define AWS_IMDS_HOST           "169.254.169.254"

struct flb_aws_provider_ec2;
static int get_creds_ec2(struct flb_aws_provider_ec2 *implementation);
static int ec2_credentials_request(struct flb_aws_provider_ec2
                                   *implementation, char *cred_path);

/* EC2 IMDS Provider */

/*
 * A provider that obtains credentials from EC2 IMDS.
 */
struct flb_aws_provider_ec2 {
    struct flb_aws_credentials *creds;
    time_t next_refresh;

    /* upstream connection to IMDS */
     struct flb_aws_client *client;
};

struct flb_aws_credentials *get_credentials_fn_ec2(struct flb_aws_provider
                                                   *provider)
{
    struct flb_aws_credentials *creds;
    int refresh = FLB_FALSE;
    struct flb_aws_provider_ec2 *implementation = provider->implementation;

    flb_debug("[aws_credentials] Requesting credentials from the "
              "EC2 provider..");

    /* a negative next_refresh means that auto-refresh is disabled */
    if (implementation->next_refresh > 0
        && time(NULL) > implementation->next_refresh) {
        refresh = FLB_TRUE;
    }
    if (!implementation->creds || refresh == FLB_TRUE) {
        if (try_lock_provider(provider)) {
            get_creds_ec2(implementation);
            unlock_provider(provider);
        }
    }

    if (!implementation->creds) {
        /*
         * We failed to lock the provider and creds are unset. This means that
         * another co-routine is performing the refresh.
         */
        flb_warn("[aws_credentials] No cached credentials are available and "
                 "a credential refresh is already in progress. The current "
                 "co-routine will retry.");

        return NULL;
    }

    creds = flb_malloc(sizeof(struct flb_aws_credentials));
    if (!creds) {
        flb_errno();
        return NULL;
    }

    creds->access_key_id = flb_sds_create(implementation->creds->access_key_id);
    if (!creds->access_key_id) {
        flb_errno();
        flb_aws_credentials_destroy(creds);
        return NULL;
    }

    creds->secret_access_key = flb_sds_create(implementation->creds->
                                              secret_access_key);
    if (!creds->secret_access_key) {
        flb_errno();
        flb_aws_credentials_destroy(creds);
        return NULL;
    }

    if (implementation->creds->session_token) {
        creds->session_token = flb_sds_create(implementation->creds->
                                              session_token);
        if (!creds->session_token) {
            flb_errno();
            flb_aws_credentials_destroy(creds);
            return NULL;
        }

    } else {
        creds->session_token = NULL;
    }

    return creds;
}

int refresh_fn_ec2(struct flb_aws_provider *provider) {
    struct flb_aws_provider_ec2 *implementation = provider->implementation;
    int ret = -1;

    flb_debug("[aws_credentials] Refresh called on the EC2 IMDS provider");
    if (try_lock_provider(provider)) {
        ret = get_creds_ec2(implementation);
        unlock_provider(provider);
    }
    return ret;
}

int init_fn_ec2(struct flb_aws_provider *provider) {
    struct flb_aws_provider_ec2 *implementation = provider->implementation;
    int ret = -1;

    implementation->client->debug_only = FLB_TRUE;

    flb_debug("[aws_credentials] Init called on the EC2 IMDS provider");
    if (try_lock_provider(provider)) {
        ret = get_creds_ec2(implementation);
        unlock_provider(provider);
    }

    implementation->client->debug_only = FLB_FALSE;
    return ret;
}

void sync_fn_ec2(struct flb_aws_provider *provider) {
    struct flb_aws_provider_ec2 *implementation = provider->implementation;

    flb_debug("[aws_credentials] Sync called on the EC2 provider");
    /* remove async flag */
    implementation->client->upstream->flags &= ~(FLB_IO_ASYNC);
}

void async_fn_ec2(struct flb_aws_provider *provider) {
    struct flb_aws_provider_ec2 *implementation = provider->implementation;

    flb_debug("[aws_credentials] Async called on the EC2 provider");
    /* add async flag */
    implementation->client->upstream->flags |= FLB_IO_ASYNC;
}

void destroy_fn_ec2(struct flb_aws_provider *provider) {
    struct flb_aws_provider_ec2 *implementation = provider->implementation;

    if (implementation) {
        if (implementation->creds) {
            flb_aws_credentials_destroy(implementation->creds);
        }

        if (implementation->client) {
            flb_aws_client_destroy(implementation->client);
        }

        flb_free(implementation);
        provider->implementation = NULL;
    }

    return;
}

static struct flb_aws_provider_vtable ec2_provider_vtable = {
    .get_credentials = get_credentials_fn_ec2,
    .init = init_fn_ec2,
    .refresh = refresh_fn_ec2,
    .destroy = destroy_fn_ec2,
    .sync = sync_fn_ec2,
    .async = async_fn_ec2,
};

struct flb_aws_provider *flb_ec2_provider_create(struct flb_config *config,
                                                 struct
                                                 flb_aws_client_generator
                                                 *generator)
{
    struct flb_aws_provider_ec2 *implementation;
    struct flb_aws_provider *provider;
    struct flb_upstream *upstream;

    provider = flb_calloc(1, sizeof(struct flb_aws_provider));

    if (!provider) {
        flb_errno();
        return NULL;
    }

    implementation = flb_calloc(1, sizeof(struct flb_aws_provider_ec2));

    if (!implementation) {
        flb_free(provider);
        flb_errno();
        return NULL;
    }

    provider->provider_vtable = &ec2_provider_vtable;
    provider->implementation = implementation;

    upstream = flb_upstream_create(config, AWS_IMDS_HOST, 80,
                                   FLB_IO_TCP, NULL);
    if (!upstream) {
        flb_aws_provider_destroy(provider);
        flb_debug("[aws_credentials] unable to connect to EC2 IMDS.");
        return NULL;
    }

    upstream->net.connect_timeout = FLB_AWS_CREDENTIAL_NET_TIMEOUT;

    implementation->client = generator->create();
    if (!implementation->client) {
        flb_aws_provider_destroy(provider);
        flb_upstream_destroy(upstream);
        flb_error("[aws_credentials] EC2 IMDS: client creation error");
        return NULL;
    }
    implementation->client->name = "ec2_imds_provider_client";
    implementation->client->has_auth = FLB_FALSE;
    implementation->client->provider = NULL;
    implementation->client->region = NULL;
    implementation->client->service = NULL;
    implementation->client->port = 80;
    implementation->client->flags = 0;
    implementation->client->proxy = NULL;
    implementation->client->upstream = upstream;

    return provider;
}

/* Requests creds from IMDSv1 and sets them on the provider */
static int get_creds_ec2(struct flb_aws_provider_ec2 *implementation)
{
    int ret;
    flb_sds_t instance_role;
    size_t instance_role_len;
    char *cred_path;
    size_t cred_path_size;

    flb_debug("[aws_credentials] requesting credentials from EC2 IMDS");

    /* Get the name of the instance role */
    ret = flb_imds_request(implementation->client, AWS_IMDS_ROLE_PATH,
                           &instance_role, &instance_role_len);

    if (ret < 0) {
        return -1;
    }

    flb_debug("[aws_credentials] Requesting credentials for instance role %s",
              instance_role);

    /* Construct path where we will find the credentials */
    cred_path_size = sizeof(char) * (AWS_IMDS_ROLE_PATH_LEN +
                                     instance_role_len) + 1;
    cred_path = flb_malloc(cred_path_size);
    if (!cred_path) {
        flb_sds_destroy(instance_role);
        flb_errno();
        return -1;
    }

    ret = snprintf(cred_path, cred_path_size, "%s%s", AWS_IMDS_ROLE_PATH,
                   instance_role);
    if (ret < 0) {
        flb_sds_destroy(instance_role);
        flb_free(cred_path);
        flb_errno();
        return -1;
    }

    /* request creds */
    ret = ec2_credentials_request(implementation, cred_path);

    flb_sds_destroy(instance_role);
    flb_free(cred_path);
    return ret;

}

static int ec2_credentials_request(struct flb_aws_provider_ec2
                                   *implementation, char *cred_path)
{
    int ret;
    flb_sds_t credentials_response;
    size_t credentials_response_len;
    struct flb_aws_credentials *creds;
    time_t expiration;

    ret = flb_imds_request(implementation->client, cred_path,
                           &credentials_response, &credentials_response_len);

    if (ret < 0) {
        return -1;
    }

    creds = flb_parse_http_credentials(credentials_response,
                                       credentials_response_len,
                                       &expiration);

    if (creds == NULL) {
        flb_sds_destroy(credentials_response);
        return -1;
    }

    /* destroy existing credentials first */
    flb_aws_credentials_destroy(implementation->creds);
    implementation->creds = NULL;
    /* set new creds */
    implementation->creds = creds;
    implementation->next_refresh = expiration - FLB_AWS_REFRESH_WINDOW;

    flb_sds_destroy(credentials_response);
    return 0;
}
