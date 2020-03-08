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

#ifdef FLB_HAVE_AWS

#ifndef FLB_AWS_CREDENTIALS_H
#define FLB_AWS_CREDENTIALS_H

#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_io.h>
#include <monkey/mk_core.h>

/* Refresh creds if they will expire in 5 min or less */
#define FLB_AWS_REFRESH_WINDOW         300

/*
 * A structure that wraps the sensitive data needed to sign an AWS request
 */
struct flb_aws_credentials {
    flb_sds_t access_key_id;
    flb_sds_t secret_access_key;
    flb_sds_t session_token;
};

/* defined below but declared here for the function declarations */
struct flb_aws_provider;

/*
 * Get credentials using the provider.
 * Client is in charge of freeing the returned credentials struct.
 * Returns NULL if credentials could not be obtained.
 */
typedef struct flb_aws_credentials*(flb_aws_provider_get_credentials_fn)
                                   (struct flb_aws_provider *provider);

/*
 * Force a refesh of cached credentials. If client code receives a response
 * from AWS indicating that the credentials are expired or invalid,
 * it can call this method and retry.
 * Returns 0 if the refresh was successful.
 */
typedef int(flb_aws_provider_refresh_fn)(struct flb_aws_provider *provider);

/*
 * Clean up the underlying provider implementation.
 * Called by flb_aws_provider_destroy.
 */
typedef void(flb_aws_provider_destroy_fn)(struct flb_aws_provider *provider);

/*
 * Set provider to 'sync' mode; all network IO operations will be performed
 * synchronously. This must be set if the provider is called when co-routines
 * are not available (ex: during plugin initialization).
 */
typedef void(flb_aws_provider_sync_fn)(struct flb_aws_provider *provider);

/*
 * Set provider to 'async' mode; all network IO operations will be performed
 * asynchronously.
 *
 * All providers are created in 'async' mode by default.
 */
typedef void(flb_aws_provider_async_fn)(struct flb_aws_provider *provider);

/*
 * This structure is a virtual table for the functions implemented by each
 * provider
 */
struct flb_aws_provider_vtable {
    flb_aws_provider_get_credentials_fn *get_credentials;
    flb_aws_provider_refresh_fn *refresh;
    flb_aws_provider_destroy_fn *destroy;
    flb_aws_provider_sync_fn *sync;
    flb_aws_provider_async_fn *async;
};

/*
 * A generic structure to represent all providers.
 */
struct flb_aws_provider {
    /*
     * Fluent Bit is single-threaded but asynchonous. Co-routines are paused
     * and resumed during blocking IO calls.
     *
     * When a refresh is needed, only one co-routine should refresh.
     */
    int locked;

    struct flb_aws_provider_vtable *provider_vtable;

    void *implementation;

    /* Standard credentials chain is a list of providers */
    struct mk_list _head;
};

/*
 * Function to free memory used by an aws_credentials structure
 */
void flb_aws_credentials_destroy(struct flb_aws_credentials *creds);

/*
 * Function to free memory used by an flb_aws_provider structure
 */
void flb_aws_provider_destroy(struct flb_aws_provider *provider);


/*
 * A provider that uses OIDC tokens provided by kubernetes to obtain
 * AWS credentials.
 *
 * The AWS SDKs have defined a spec for an OIDC provider that obtains tokens
 * from environment variables or the shared config file.
 * This provider only contains the functionality needed for EKS- obtaining the
 * location of the OIDC token from an environment variable.
 */
struct flb_aws_provider *flb_eks_provider_create(struct flb_config *config,
                                                 struct flb_tls *tls,
                                                 char *region, char *proxy,
                                                 struct
                                                 flb_aws_client_generator
                                                 *generator);


/*
 * STS Assume Role Provider.
 */
struct flb_aws_provider *flb_sts_provider_create(struct flb_config *config,
                                                 struct flb_tls *tls,
                                                 struct flb_aws_provider
                                                 *base_provider,
                                                 char *external_id,
                                                 char *role_arn,
                                                 char *session_name,
                                                 char *region,
                                                 char *proxy,
                                                 struct
                                                 flb_aws_client_generator
                                                 *generator);

/*
 * Standard environment variables
 */
struct flb_aws_provider *flb_aws_env_provider_create();

/*
 * New http provider - retrieve credentials from a local http server.
 * Equivalent to:
 * https://github.com/aws/aws-sdk-go/tree/master/aws/credentials/endpointcreds
 *
 * Calling flb_aws_provider_destroy on this provider frees the memory
 * used by host and path.
 */
struct flb_aws_provider *flb_http_provider_create(struct flb_config *config,
                                                  flb_sds_t host,
                                                  flb_sds_t path,
                                                  struct
                                                  flb_aws_client_generator
                                                  *generator);

/*
 * ECS Provider
 * The ECS Provider is just a wrapper around the HTTP Provider
 * with the ECS credentials endpoint.
 */
struct flb_aws_provider *flb_ecs_provider_create(struct flb_config *config,
                                                 struct
                                                 flb_aws_client_generator
                                                 *generator);

/*
 * EC2 IMDS Provider
 */
struct flb_aws_provider *flb_ec2_provider_create(struct flb_config *config,
                                                 struct
                                                 flb_aws_client_generator
                                                 *generator);



/*
 * Helper functions
 */

time_t flb_aws_cred_expiration(const char* timestamp);

int flb_read_file(const char *path, char **out_buf, size_t *out_size);

struct flb_aws_credentials *flb_parse_sts_resp(char *response,
                                               time_t *expiration);
char *flb_sts_uri(char *action, char *role_arn, char *session_name,
                  char *external_id, char *identity_token);
char *flb_sts_session_name();

struct flb_aws_credentials *flb_parse_http_credentials(char *response,
                                                       size_t response_len,
                                                       time_t *expiration);

/*
 * Fluent Bit is single-threaded but asynchonous. Only one co-routine will
 * be running at a time, and they only pause/resume for IO.
 *
 * Thus, while synchronization is needed (to prevent multiple co-routines
 * from duplicating effort and performing the same work), it can be obtained
 * using a simple integer flag on the provider.
 */

/* Like a traditional try lock- it does not block if the lock is not obtained */
int try_lock_provider(struct flb_aws_provider *provider);

void unlock_provider(struct flb_aws_provider *provider);


#endif
#endif /* FLB_HAVE_AWS */
