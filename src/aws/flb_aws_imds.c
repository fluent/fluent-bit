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

#include <fluent-bit/aws/flb_aws_imds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_jsmn.h>

#define FLB_AWS_IMDS_ROOT "/"
#define FLB_AWS_IMDS_V2_TOKEN_PATH "/latest/api/token"

/* Request headers */
static struct flb_aws_header imds_v2_token_ttl_header = {
    .key = "X-aws-ec2-metadata-token-ttl-seconds",
    .key_len = 36,
    .val = "21600",  /* 6 hours (ie maximum ttl) */
    .val_len = 5,
};

/* Request header templates */
const static struct flb_aws_header imds_v2_token_token_header_template = {
    .key = "X-aws-ec2-metadata-token",
    .key_len = 24,
    .val = "",     /* Replace with token value */
    .val_len = 0,  /* Replace with token length */
};

/* Declarations */
static int get_imds_version(struct flb_aws_imds *ctx);
static int refresh_imds_v2_token(struct flb_aws_imds *ctx);

/* Default config values */
const struct flb_aws_imds_config flb_aws_imds_config_default = {
    FLB_AWS_IMDS_VERSION_EVALUATE};

/* Create IMDS context */
struct flb_aws_imds *flb_aws_imds_create(const struct flb_aws_imds_config *imds_config,
                                         struct flb_aws_client *ec2_imds_client)
{
    struct flb_aws_imds *ctx = NULL;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_aws_imds));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /*
     * Set IMDS version to whatever is specified in config
     * Version may be evaluated later if set to FLB_AWS_IMDS_VERSION_EVALUATE
     */
    ctx->imds_version = imds_config->use_imds_version;
    ctx->imds_v2_token = flb_sds_create_len("INVALID_TOKEN", 13);
    ctx->imds_v2_token_len = 13;

    /* Detect IMDS support */
    if (!ec2_imds_client->upstream) {
        flb_debug(
            "[imds] unable to connect to EC2 IMDS. ec2_imds_client upstream is null");

        flb_aws_imds_destroy(ctx);
        return NULL;
    }
    if (0 != strncmp(ec2_imds_client->upstream->tcp_host, FLB_AWS_IMDS_HOST,
                     FLB_AWS_IMDS_HOST_LEN)) {
        flb_debug("[imds] ec2_imds_client tcp host must be set to %s", FLB_AWS_IMDS_HOST);
        flb_aws_imds_destroy(ctx);
        return NULL;
    }
    if (ec2_imds_client->upstream->tcp_port != FLB_AWS_IMDS_PORT) {
        flb_debug("[imds] ec2_imds_client tcp port must be set to %i", FLB_AWS_IMDS_PORT);
        flb_aws_imds_destroy(ctx);
        return NULL;
    }

    /* Connect client */
    ctx->ec2_imds_client = ec2_imds_client;
    return ctx;
}

/* Destroy IMDS context */
void flb_aws_imds_destroy(struct flb_aws_imds *ctx)
{
    if (ctx->imds_v2_token) {
        flb_sds_destroy(ctx->imds_v2_token);
    }

    flb_free(ctx);
}

/* Get IMDS metadata */
int flb_aws_imds_request(struct flb_aws_imds *ctx, const char *metadata_path,
                         flb_sds_t *metadata, size_t *metadata_len)
{
    return flb_aws_imds_request_by_key(ctx, metadata_path, metadata, metadata_len, NULL);
}

/* Get IMDS metadata by key */
int flb_aws_imds_request_by_key(struct flb_aws_imds *ctx, const char *metadata_path,
                                flb_sds_t *metadata, size_t *metadata_len, char *key)
{
    int ret;
    flb_sds_t tmp;

    struct flb_http_client *c = NULL;

    struct flb_aws_client *ec2_imds_client = ctx->ec2_imds_client;
    struct flb_aws_header token_header = imds_v2_token_token_header_template;

    /* Get IMDS version */
    int imds_version = get_imds_version(ctx);

    /* Abort on version detection failure */
    if (imds_version == FLB_AWS_IMDS_VERSION_EVALUATE) {
        /* Exit gracefully allowing for retrys */
        flb_warn("[imds] unable to evaluate IMDS version");
        return -1;
    }

    if (imds_version == FLB_AWS_IMDS_VERSION_2) {
        token_header.val = ctx->imds_v2_token;
        token_header.val_len = ctx->imds_v2_token_len;
        flb_debug("[imds] using IMDSv2");
    }
    else {
        flb_debug("[imds] using IMDSv1");
    }

    c = ec2_imds_client->client_vtable->request(
        ec2_imds_client, FLB_HTTP_GET, metadata_path, NULL, 0, &token_header,
        (imds_version == FLB_AWS_IMDS_VERSION_1) ? 0 : 1);
    if (!c) {
        /* Exit gracefully allowing for retrys */
        flb_warn("[imds] failed to retrieve metadata");
        return -1;
    }

    /* Detect invalid token */
    if (imds_version == FLB_AWS_IMDS_VERSION_2 && c->resp.status == 401) {
        /* Refresh token and retry request */
        flb_http_client_destroy(c);
        ret = refresh_imds_v2_token(ctx);
        if (ret < 0) {
            flb_debug("[imds] failed to refresh IMDSv2 token");
            return -1;
        }
        token_header.val = ctx->imds_v2_token;
        token_header.val_len = ctx->imds_v2_token_len;
        flb_debug("[imds] refreshed IMDSv2 token");
        c = ec2_imds_client->client_vtable->request(
            ec2_imds_client, FLB_HTTP_GET, metadata_path, NULL, 0, &token_header, 1);
        if (!c) {
            /* Exit gracefully allowing for retries */
            flb_warn("[imds] failed to retrieve metadata");
            return -1;
        }
    }

    if (c->resp.status != 200) {
        ret = -1;
        if (c->resp.status == 404) {
            ret = -2;
        }
        if (c->resp.payload_size > 0) {
            flb_debug("[imds] metadata request failure response\n%s", c->resp.payload);
        }
        flb_http_client_destroy(c);
        return ret;
    }

    if (key != NULL) {
        /* get the value of the key from payload json string */
        tmp = flb_json_get_val(c->resp.payload, c->resp.payload_size, key);
        if (!tmp) {
            tmp = flb_sds_create_len("NULL", 4);
            flb_error("[imds] %s is undefined in EC2 instance", key);
        }
    }
    else {
        tmp = flb_sds_create_len(c->resp.payload, c->resp.payload_size);
    }

    if (!tmp) {
        flb_errno();
        flb_http_client_destroy(c);
        return -1;
    }

    *metadata = tmp;
    *metadata_len = key == NULL ? c->resp.payload_size : strlen(tmp);

    flb_http_client_destroy(c);
    return 0;
}

/* Get VPC Id */
flb_sds_t flb_aws_imds_get_vpc_id(struct flb_aws_imds *ctx)
{
    int ret;
    flb_sds_t mac_id = NULL;
    size_t mac_len = 0;
    flb_sds_t vpc_id = NULL;
    size_t vpc_id_len = 0;

    /* get EC2 instance Mac id first before getting VPC id */
    ret = flb_aws_imds_request(ctx, FLB_AWS_IMDS_MAC_PATH, &mac_id, &mac_len);

    if (ret < 0) {
        flb_sds_destroy(mac_id);
        return NULL;
    }

    /*
     * the VPC full path should be like:
     * latest/meta-data/network/interfaces/macs/{mac_id}/vpc-id/"
     */
    flb_sds_t vpc_path = flb_sds_create_size(70);
    vpc_path =
        flb_sds_printf(&vpc_path, "%s/%s/%s/",
                       "/latest/meta-data/network/interfaces/macs", mac_id, "vpc-id");
    ret = flb_aws_imds_request(ctx, vpc_path, &vpc_id, &vpc_id_len);

    flb_sds_destroy(mac_id);
    flb_sds_destroy(vpc_path);

    return vpc_id;
}

/* Obtain the IMDS version */
static int get_imds_version(struct flb_aws_imds *ctx)
{
    int ret;
    struct flb_aws_client *client = ctx->ec2_imds_client;
    struct flb_aws_header invalid_token_header;
    struct flb_http_client *c = NULL;

    if (ctx->imds_version != FLB_AWS_IMDS_VERSION_EVALUATE) {
        return ctx->imds_version;
    }

    /*
     * Evaluate version
     * To evaluate wether IMDSv2 is available, send an invalid token
     * in IMDS request. If response status is 'Unauthorized', then IMDSv2
     * is available.
     */
    invalid_token_header = imds_v2_token_token_header_template;
    invalid_token_header.val = "INVALID";
    invalid_token_header.val_len = 7;
    c = client->client_vtable->request(client, FLB_HTTP_GET, FLB_AWS_IMDS_ROOT, NULL, 0,
                                       &invalid_token_header, 1);

    if (!c) {
        flb_debug("[imds] imds endpoint unavailable");
        return FLB_AWS_IMDS_VERSION_EVALUATE;
    }

    /* Unauthorized response means that IMDS version 2 is in use */
    if (c->resp.status == 401) {
        ctx->imds_version = FLB_AWS_IMDS_VERSION_2;
        ret = refresh_imds_v2_token(ctx);
        if (ret == -1) {
            /*
             * Token cannot be refreshed, test IMDSv1
             * If IMDSv1 cannot be used, response will be status 401
             */
            flb_http_client_destroy(c);
            ctx->imds_version = FLB_AWS_IMDS_VERSION_EVALUATE;
            c = client->client_vtable->request(client, FLB_HTTP_GET, FLB_AWS_IMDS_ROOT,
                                               NULL, 0, NULL, 0);
            if (!c) {
                flb_debug("[imds] imds v1 attempt, endpoint unavailable");
                return FLB_AWS_IMDS_VERSION_EVALUATE;
            }

            if (c->resp.status == 200) {
                flb_info("[imds] to use IMDSv2, set --http-put-response-hop-limit to 2");
            }
            else {
                /* IMDSv1 unavailable. IMDSv2 beyond network hop count */
                flb_warn("[imds] failed to retrieve IMDSv2 token and IMDSv1 unavailable. "
                        "This is likely due to instance-metadata-options "
                        "--http-put-response-hop-limit being set to 1 and --http-tokens "
                        "set to required. "
                        "To use IMDSv2, please set --http-put-response-hop-limit to 2 as "
                        "described https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/"
                        "configuring-instance-metadata-options.html");
            }
        }
    }

    /*
     * Success means that IMDS version 1 is in use
     */
    if (c->resp.status == 200) {
        flb_warn("[imds] falling back on IMDSv1");
        ctx->imds_version = FLB_AWS_IMDS_VERSION_1;
    }

    flb_http_client_destroy(c);
    return ctx->imds_version;
}

/*
 * Get an IMDSv2 token
 * Token preserved in imds context
 */
static int refresh_imds_v2_token(struct flb_aws_imds *ctx)
{
    struct flb_http_client *c = NULL;
    struct flb_aws_client *ec2_imds_client = ctx->ec2_imds_client;

    c = ec2_imds_client->client_vtable->request(ec2_imds_client, FLB_HTTP_PUT,
                                                FLB_AWS_IMDS_V2_TOKEN_PATH, NULL, 0,
                                                &imds_v2_token_ttl_header, 1);

    if (!c) {
        return -1;
    }

    if (c->resp.status != 200) {
        if (c->resp.payload_size > 0) {
            flb_error("[imds] IMDSv2 token retrieval failure response\n%s",
                      c->resp.payload);
        }

        flb_http_client_destroy(c);
        return -1;
    }

    /* Preserve token information in ctx */
    if (c->resp.payload_size > 0) {
        if (ctx->imds_v2_token) {
            flb_sds_destroy(ctx->imds_v2_token);
        }
        ctx->imds_v2_token = flb_sds_create_len(c->resp.payload, c->resp.payload_size);
        if (!ctx->imds_v2_token) {
            flb_errno();
            flb_http_client_destroy(c);
            return -1;
        }
        ctx->imds_v2_token_len = c->resp.payload_size;

        flb_http_client_destroy(c);
        return 0;
    }

    flb_debug("[imds] IMDS metadata response was empty");
    flb_http_client_destroy(c);
    return -1;
}
