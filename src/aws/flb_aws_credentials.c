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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_output_plugin.h>

#include <stdlib.h>
#include <time.h>

#define FIVE_MINUTES   300
#define TWELVE_HOURS   43200

/* Credentials Environment Variables */
#define AWS_ACCESS_KEY_ID              "AWS_ACCESS_KEY_ID"
#define AWS_SECRET_ACCESS_KEY          "AWS_SECRET_ACCESS_KEY"
#define AWS_SESSION_TOKEN              "AWS_SESSION_TOKEN"

#define EKS_POD_EXECUTION_ROLE         "EKS_POD_EXECUTION_ROLE"
#define AWS_ROLE_ARN                   "AWS_ROLE_ARN"
#define AWS_WEB_IDENTITY_TOKEN_FILE    "AWS_WEB_IDENTITY_TOKEN_FILE"

/* declarations */
static struct flb_aws_provider *standard_chain_create(struct flb_config
                                                      *config,
                                                      struct flb_tls *tls,
                                                      char *region,
                                                      char *sts_endpoint,
                                                      char *proxy,
                                                      struct
                                                      flb_aws_client_generator
                                                      *generator,
                                                      int eks_irsa,
                                                      char *profile);


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

void upstream_set_fn_standard_chain(struct flb_aws_provider *provider,
                                    struct flb_output_instance *ins)
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
        sub_provider->provider_vtable->upstream_set(sub_provider, ins);
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
    .upstream_set = upstream_set_fn_standard_chain,
};

struct flb_aws_provider *flb_standard_chain_provider_create(struct flb_config
                                                            *config,
                                                            struct flb_tls *tls,
                                                            char *region,
                                                            char *sts_endpoint,
                                                            char *proxy,
                                                            struct
                                                            flb_aws_client_generator
                                                            *generator,
                                                            char *profile)
{
    struct flb_aws_provider *provider;
    struct flb_aws_provider *tmp_provider;
    char *eks_pod_role = NULL;
    char *session_name;

    eks_pod_role = getenv(EKS_POD_EXECUTION_ROLE);
    if (eks_pod_role && strlen(eks_pod_role) > 0) {
        /*
         * eks fargate
         * standard chain will be base provider used to
         * assume the EKS_POD_EXECUTION_ROLE
         */
        flb_debug("[aws_credentials] Using EKS_POD_EXECUTION_ROLE=%s", eks_pod_role);
        tmp_provider = standard_chain_create(config, tls, region, sts_endpoint,
                                             proxy, generator, FLB_FALSE, profile);

        if (!tmp_provider) {
            return NULL;
        }

        session_name = flb_sts_session_name();
        if (!session_name) {
            flb_error("Failed to generate random STS session name");
            flb_aws_provider_destroy(tmp_provider);
            return NULL;
        }

        provider = flb_sts_provider_create(config, tls, tmp_provider, NULL,
                                           eks_pod_role, session_name,
                                           region, sts_endpoint,
                                           NULL, generator);
        if (!provider) {
            flb_error("Failed to create EKS Fargate Credential Provider");
            flb_aws_provider_destroy(tmp_provider);
            return NULL;
        }
        /* session name can freed after provider is created */
        flb_free(session_name);
        session_name = NULL;

        return provider;
    }

    /* standard case- not in EKS Fargate */
    provider = standard_chain_create(config, tls, region, sts_endpoint,
                                     proxy, generator, FLB_TRUE, profile);
    return provider;
}

struct flb_aws_provider *flb_managed_chain_provider_create(struct flb_output_instance
                                                           *ins,
                                                           struct flb_config
                                                           *config,
                                                           char *config_key_prefix,
                                                           char *proxy,
                                                           struct
                                                           flb_aws_client_generator
                                                           *generator)
{
    flb_sds_t config_key_region;
    flb_sds_t config_key_sts_endpoint;
    flb_sds_t config_key_role_arn;
    flb_sds_t config_key_external_id;
    flb_sds_t config_key_profile;
    const char *region = NULL;
    const char *sts_endpoint = NULL;
    const char *role_arn = NULL;
    const char *external_id = NULL;
    const char *profile = NULL;
    char *session_name = NULL;
    int key_prefix_len;
    int key_max_len;

    /* Provider managed dependencies */
    struct flb_aws_provider *aws_provider = NULL;
    struct flb_aws_provider *base_aws_provider = NULL;
    struct flb_tls *cred_tls = NULL;
    struct flb_tls *sts_tls = NULL;

    /* Config keys */
    key_prefix_len = strlen(config_key_prefix);
    key_max_len = key_prefix_len + 12; /* max length of
                                              "region", "sts_endpoint", "role_arn",
                                              "external_id" */

    /* Evaluate full config keys */
    config_key_region = flb_sds_create_len(config_key_prefix, key_max_len);
    strcpy(config_key_region + key_prefix_len, "region");
    config_key_sts_endpoint = flb_sds_create_len(config_key_prefix, key_max_len);
    strcpy(config_key_sts_endpoint + key_prefix_len, "sts_endpoint");
    config_key_role_arn = flb_sds_create_len(config_key_prefix, key_max_len);
    strcpy(config_key_role_arn + key_prefix_len, "role_arn");
    config_key_external_id = flb_sds_create_len(config_key_prefix, key_max_len);
    strcpy(config_key_external_id + key_prefix_len, "external_id");
    config_key_profile = flb_sds_create_len(config_key_prefix, key_max_len);
    strcpy(config_key_profile + key_prefix_len, "profile");

    /* AWS provider needs a separate TLS instance */
    cred_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                              FLB_TRUE,
                              ins->tls_debug,
                              ins->tls_vhost,
                              ins->tls_ca_path,
                              ins->tls_ca_file,
                              ins->tls_crt_file,
                              ins->tls_key_file,
                              ins->tls_key_passwd);
    if (!cred_tls) {
        flb_plg_error(ins, "Failed to create TLS instance for AWS Provider");
        flb_errno();
        goto error;
    }

    region = flb_output_get_property(config_key_region, ins);
    if (!region) {
        flb_plg_error(ins, "aws_auth enabled but %s not set", config_key_region);
        goto error;
    }

    /* Use null sts_endpoint if none provided */
    sts_endpoint = flb_output_get_property(config_key_sts_endpoint, ins);
    /* Get the profile from configuration */
    profile = flb_output_get_property(config_key_profile, ins);
    aws_provider = flb_standard_chain_provider_create(config,
                                                      cred_tls,
                                                      (char *) region,
                                                      (char *) sts_endpoint,
                                                      NULL,
                                                      flb_aws_client_generator(),
                                                      (char *) profile);
    if (!aws_provider) {
        flb_plg_error(ins, "Failed to create AWS Credential Provider");
        goto error;
    }

    role_arn = flb_output_get_property(config_key_role_arn, ins);
    if (role_arn) {
        /* Use the STS Provider */
        base_aws_provider = aws_provider;
        external_id = flb_output_get_property(config_key_external_id, ins);

        session_name = flb_sts_session_name();
        if (!session_name) {
            flb_plg_error(ins, "Failed to generate aws iam role "
                        "session name");
            goto error;
        }

        /* STS provider needs yet another separate TLS instance */
        sts_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                 FLB_TRUE,
                                 ins->tls_debug,
                                 ins->tls_vhost,
                                 ins->tls_ca_path,
                                 ins->tls_ca_file,
                                 ins->tls_crt_file,
                                 ins->tls_key_file,
                                 ins->tls_key_passwd);
        if (!sts_tls) {
            flb_plg_error(ins, "Failed to create TLS instance for AWS STS Credential "
                          "Provider");
            flb_errno();
            goto error;
        }

        aws_provider = flb_sts_provider_create(config,
                                               sts_tls,
                                               base_aws_provider,
                                               (char *) external_id,
                                               (char *) role_arn,
                                               session_name,
                                               (char *) region,
                                               (char *) sts_endpoint,
                                               NULL,
                                               flb_aws_client_generator());
        if (!aws_provider) {
            flb_plg_error(ins, "Failed to create AWS STS Credential "
                        "Provider");
            goto error;
        }
    }

    /* initialize credentials in sync mode */
    aws_provider->provider_vtable->sync(aws_provider);
    aws_provider->provider_vtable->init(aws_provider);

    /* set back to async */
    aws_provider->provider_vtable->async(aws_provider);

    /* store dependencies in aws_provider for managed cleanup */
    aws_provider->base_aws_provider = base_aws_provider;
    aws_provider->cred_tls = cred_tls;
    aws_provider->sts_tls = sts_tls;

    goto cleanup;

error:
    if (aws_provider) {
        /* disconnect dependencies */
        aws_provider->base_aws_provider = NULL;
        aws_provider->cred_tls = NULL;
        aws_provider->sts_tls = NULL;
        /* destroy */
        flb_aws_provider_destroy(aws_provider);
    }
    /* free dependencies */
    if (base_aws_provider) {
        flb_aws_provider_destroy(base_aws_provider);
    }
    if (cred_tls) {
        flb_tls_destroy(cred_tls);
    }
    if (sts_tls) {
        flb_tls_destroy(sts_tls);
    }
    aws_provider = NULL;

cleanup:
    if (config_key_region) {
        flb_sds_destroy(config_key_region);
    }
    if (config_key_sts_endpoint) {
        flb_sds_destroy(config_key_sts_endpoint);
    }
    if (config_key_role_arn) {
        flb_sds_destroy(config_key_role_arn);
    }
    if (config_key_external_id) {
        flb_sds_destroy(config_key_external_id);
    }
    if (session_name) {
        flb_free(session_name);
    }
    if (config_key_profile) {
        flb_sds_destroy(config_key_profile);
    }

    return aws_provider;
}

static struct flb_aws_provider *standard_chain_create(struct flb_config
                                                      *config,
                                                      struct flb_tls *tls,
                                                      char *region,
                                                      char *sts_endpoint,
                                                      char *proxy,
                                                      struct
                                                      flb_aws_client_generator
                                                      *generator,
                                                      int eks_irsa,
                                                      char *profile)
{
    int irsa_env_present = FLB_FALSE;
    struct flb_aws_provider *sub_provider;
    struct flb_aws_provider *provider;
    struct flb_aws_provider_chain *implementation;
    char *role_arn_env = NULL;
    char *token_file_env = NULL;

    provider = flb_calloc(1, sizeof(struct flb_aws_provider));
    if (!provider) {
        flb_errno();
        return NULL;
    }

    pthread_mutex_init(&provider->lock, NULL);

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

    flb_debug("[aws_credentials] creating profile %s provider", profile);
    sub_provider = flb_profile_provider_create(profile);
    if (sub_provider) {
        /* Profile provider can fail if HOME env var is not set */;
        mk_list_add(&sub_provider->_head, &implementation->sub_providers);
        flb_debug("[aws_credentials] Initialized AWS Profile Provider in "
                  "standard chain");
    }

    role_arn_env = getenv(AWS_ROLE_ARN);
    token_file_env = getenv(AWS_WEB_IDENTITY_TOKEN_FILE);

    /* Check if IRSA environment variables are set */
    if (role_arn_env && strlen(role_arn_env) > 0 && token_file_env && strlen(token_file_env) > 0) {
        irsa_env_present = FLB_TRUE;
    }

    if (eks_irsa == FLB_TRUE) {
        sub_provider = flb_eks_provider_create(config, tls, region, sts_endpoint, proxy, generator);
        if (sub_provider) {
            /* EKS provider can fail if we are not running in k8s */;
            mk_list_add(&sub_provider->_head, &implementation->sub_providers);
            flb_debug("[aws_credentials] Initialized EKS Provider in standard chain");
        }
        else if (irsa_env_present) {
            flb_error("[aws_credentials] IRSA environment variables are set but the EKS provider could not be initialized");
            flb_aws_provider_destroy(provider);
            return NULL;
        }

        if (irsa_env_present) {
            flb_debug("[aws_credentials] IRSA environment detected; skipping ECS and EC2 providers");
            return provider;
        }
    }

    sub_provider = flb_http_provider_create(config, generator);
    if (sub_provider) {
        /* ECS Provider will fail creation if we are not running in ECS */
        mk_list_add(&sub_provider->_head, &implementation->sub_providers);
        flb_debug("[aws_credentials] Initialized ECS Provider in standard chain");
    }

    sub_provider = flb_ec2_provider_create(config, generator);
    if (!sub_provider) {
        /* EC2 provider will only fail creation if a memory alloc failed */
        flb_aws_provider_destroy(provider);
        return NULL;
    }
    mk_list_add(&sub_provider->_head, &implementation->sub_providers);
    flb_debug("[aws_credentials] Initialized EC2 Provider in standard chain");

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

    creds = flb_calloc(1, sizeof(struct flb_aws_credentials));
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

void upstream_set_fn_environment(struct flb_aws_provider *provider,
                                 struct flb_output_instance *ins)
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
    .upstream_set = upstream_set_fn_environment,
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

        pthread_mutex_destroy(&provider->lock);

        /* free managed dependencies */
        if (provider->base_aws_provider) {
            flb_aws_provider_destroy(provider->base_aws_provider);
        }
        if (provider->cred_tls) {
            flb_tls_destroy(provider->cred_tls);
        }
        if (provider->sts_tls) {
            flb_tls_destroy(provider->sts_tls);
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
     * (> 12 hours is impossible with the current APIs and would likely indicate
     *  a bug in how this code processes timestamps.)
     */
     now = time(NULL);
     if (expiration < (now + FIVE_MINUTES)) {
         flb_warn("[aws_credentials] Credential expiration '%s' is less than "
                  "5 minutes in the future.",
                  timestamp);
     }
     if (expiration > (now + TWELVE_HOURS)) {
         flb_warn("[aws_credentials] Credential expiration '%s' is greater than "
                  "12 hours in the future. This should not be possible.",
                  timestamp);
     }
     return expiration;
}

/*
 * Fluent Bit is now multi-threaded and asynchonous with coros.
 * The trylock prevents deadlock, and protects the provider
 * when a cred refresh happens. The refresh frees and
 * sets the shared cred cache, a double free could occur
 * if two threads do it at the same exact time.
 */

/* Like a traditional try lock- it does not block if the lock is not obtained */
int try_lock_provider(struct flb_aws_provider *provider)
{
    int ret = 0;
    ret = pthread_mutex_trylock(&provider->lock);
    if (ret != 0) {
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

void unlock_provider(struct flb_aws_provider *provider)
{
    pthread_mutex_unlock(&provider->lock);
}
