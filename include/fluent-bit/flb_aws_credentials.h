/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_sds.h>
#include <monkey/mk_core.h>

/* Refresh creds if they will expire in 1 min or less */
#define FLB_AWS_REFRESH_WINDOW         60

/* 5 second timeout for credential related http requests */
#define FLB_AWS_CREDENTIAL_NET_TIMEOUT 5

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
 * "Initializes the provider". Used in the standard chain to determine which
 * provider is valid in the current environment. Init is similar to refresh,
 * except all log messages are printed as debug (so that the user does not get
 * confusing error messages when 'testing' a provider to see if its available).
 */
typedef int(flb_aws_provider_init_fn)(struct flb_aws_provider *provider);

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
 * Call flb_output_upstream_set() on all upstreams created 
 * by this provider and all sub-providers. 
 */
typedef void(flb_aws_provider_upstream_set_fn)(struct flb_aws_provider *provider, 
                                               struct flb_output_instance *ins);

/*
 * This structure is a virtual table for the functions implemented by each
 * provider
 */
struct flb_aws_provider_vtable {
    flb_aws_provider_get_credentials_fn *get_credentials;
    flb_aws_provider_init_fn *init;
    flb_aws_provider_refresh_fn *refresh;
    flb_aws_provider_destroy_fn *destroy;
    flb_aws_provider_sync_fn *sync;
    flb_aws_provider_async_fn *async;
    flb_aws_provider_upstream_set_fn *upstream_set;
};

/*
 * A generic structure to represent all providers.
 */
struct flb_aws_provider {
    /*
     * Fluent Bit now has multi-threads/workers, need to a mutex to protect cred provider.
     * When a refresh is needed, only one co-routine should refresh.
     * When one thread refreshes, the cached creds are freed and reset, there could be a double
     * free without a lock.
     * We use trylock to prevent deadlock.
     */
    pthread_mutex_t lock;

    struct flb_aws_provider_vtable *provider_vtable;

    void *implementation;

    /* Standard credentials chain is a list of providers */
    struct mk_list _head;

    /* Provider managed dependencies; to delete on destroy */
    struct flb_aws_provider *base_aws_provider;
    struct flb_tls *cred_tls;   /* tls instances can't be re-used; aws provider requires
                                   a separate one */
    struct flb_tls *sts_tls;    /* one for the standard chain provider, one for sts
                                   assume role */
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
 * The standard chain provider; client code should use this provider by default
 */
struct flb_aws_provider *flb_standard_chain_provider_create(struct flb_config
                                                            *config,
                                                            struct flb_tls *tls,
                                                            char *region,
                                                            char *sts_endpoint,
                                                            char *proxy,
                                                            struct
                                                            flb_aws_client_generator
                                                            *generator,
                                                            char *profile);

/* Provide base configuration options for managed chain */
#define FLB_AWS_CREDENTIAL_BASE_CONFIG_MAP(prefix)                                    \
    {                                                                                 \
     FLB_CONFIG_MAP_STR, prefix "region", NULL,                                       \
     0, FLB_FALSE, 0,                                                                 \
     "AWS region of your service"                                                     \
    },                                                                                \
    {                                                                                 \
     FLB_CONFIG_MAP_STR, prefix "sts_endpoint", NULL,                                 \
     0, FLB_FALSE, 0,                                                                 \
     "Custom endpoint for the AWS STS API, used with the `" prefix "role_arn` option" \
    },                                                                                \
    {                                                                                 \
     FLB_CONFIG_MAP_STR, prefix "role_arn", NULL,                                     \
     0, FLB_FALSE, 0,                                                                 \
     "ARN of an IAM role to assume (ex. for cross account access)"                    \
    },                                                                                \
    {                                                                                 \
     FLB_CONFIG_MAP_STR, prefix "external_id", NULL,                                  \
     0, FLB_FALSE, 0,                                                                 \
     "Specify an external ID for the STS API, can be used with the `" prefix          \
     "role_arn` parameter if your role requires an external ID."                      \
    },                                                                                \
    {                                                                                 \
     FLB_CONFIG_MAP_STR, prefix "profile", NULL,                                      \
     0, FLB_FALSE, 0,                                                                 \
     "AWS Profile name. AWS Profiles can be configured with AWS CLI and are usually"  \
     "stored in $HOME/.aws/ directory."                                               \
    }
/*
 * Managed chain provider; Creates and manages removal of dependancies for an instance
 */
struct flb_aws_provider *flb_managed_chain_provider_create(struct flb_output_instance
                                                           *ins,
                                                           struct flb_config
                                                           *config,
                                                           char *config_key_prefix,
                                                           char *proxy,
                                                           struct
                                                           flb_aws_client_generator
                                                           *generator);

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
                                                 char *region, 
                                                 char *sts_endpoint,
                                                 char *proxy,
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
                                                 char *sts_endpoint,
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
struct flb_aws_provider *flb_endpoint_provider_create(struct flb_config *config,
                                                      flb_sds_t host,
                                                      flb_sds_t path,
                                                      int port,
                                                      int insecure,
                                                      struct
                                                      flb_aws_client_generator
                                                      *generator);

/*
 * HTTP Provider for EKS and ECS
 * The ECS Provider is just a wrapper around the HTTP Provider
 * with the ECS credentials endpoint.
 */
struct flb_aws_provider *flb_http_provider_create(struct flb_config *config,
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
 * New AWS Profile provider, reads from the shared credentials file
 */
struct flb_aws_provider *flb_profile_provider_create(char* profile);

/*
 * Helper functions
 */

time_t flb_aws_cred_expiration(const char* timestamp);

struct flb_aws_credentials *flb_parse_sts_resp(char *response,
                                               time_t *expiration);
flb_sds_t flb_sts_uri(char *action, char *role_arn, char *session_name,
                      char *external_id, char *identity_token);
char *flb_sts_session_name();

struct flb_aws_credentials *flb_parse_http_credentials(char *response,
                                                       size_t response_len,
                                                       time_t *expiration);

struct flb_aws_credentials *flb_parse_json_credentials(char *response,
                                                       size_t response_len,
                                                       char *session_token_field,
                                                       time_t *expiration);

#ifdef FLB_HAVE_AWS_CREDENTIAL_PROCESS

/*
 * Parses the input string, which is assumed to be the credential_process
 * from the config file, into a sequence of tokens.
 * Returns the array of tokens on success, and NULL on failure.
 * The array of tokens will be terminated by NULL for use with `execvp`.
 * The caller is responsible for calling `flb_free` on the return value.
 * Note that this function modifies the input string.
 */
char** parse_credential_process(char* input);

/*
 * Executes the given credential_process, which is assumed to have come
 * from the config file, and parses its result into *creds and *expiration.
 * Returns 0 on success and < 0 on failure.
 *
 * If it succeeds, *creds and *expiration will be set appropriately, and the
 * caller is responsible for calling `flb_aws_credentials_destroy(*creds)`.
 * If the credentials do not expire, then *expiration will be 0.
 *
 * If it fails, then *creds will be NULL.
 */
int exec_credential_process(char* process, struct flb_aws_credentials** creds,
                            time_t* expiration);

#endif /* FLB_HAVE_AWS_CREDENTIAL_PROCESS */

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


/*
 * HTTP Credentials Provider - retrieve credentials from a local http server
 * Used to implement the ECS Credentials provider.
 * Equivalent to:
 * https://github.com/aws/aws-sdk-go/tree/master/aws/credentials/endpointcreds
 */

struct flb_aws_provider_http {
    struct flb_aws_credentials *creds;
    time_t next_refresh;

    struct flb_aws_client *client;

    /* Host and Path to request credentials */
    flb_sds_t host;
    flb_sds_t path;

    flb_sds_t auth_token; /* optional */
};


#endif
#endif /* FLB_HAVE_AWS */
