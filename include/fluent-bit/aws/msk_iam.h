#ifndef FLB_AWS_MSK_IAM_H
#define FLB_AWS_MSK_IAM_H

#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_sds.h>
#include <rdkafka.h>

struct flb_aws_msk_iam;

/* Wrapper for storing plugin context and MSK IAM state */
struct flb_msk_iam_cb {
    void *plugin_ctx;                 /* in_kafka or out_kafka context       */
    struct flb_aws_msk_iam *iam;      /* token generator state               */
    char *broker_host;                /* actual broker host for MSK Serverless (dynamically allocated) */
};

/*
 * Register the oauthbearer refresh callback for MSK IAM authentication.
 * Returns context pointer on success or NULL on failure.
 */
struct flb_aws_msk_iam *flb_aws_msk_iam_register_oauth_cb(struct flb_config *config,
                                                          rd_kafka_conf_t *kconf,
                                                          const char *cluster_arn,
                                                          void *owner);

/* Destroy MSK IAM context */
void flb_aws_msk_iam_destroy(struct flb_aws_msk_iam *ctx);

#endif /* FLB_AWS_MSK_IAM_H */
