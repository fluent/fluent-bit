#ifndef FLB_AWS_MSK_IAM_H
#define FLB_AWS_MSK_IAM_H

#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_sds.h>
#include <rdkafka.h>

struct flb_aws_msk_iam;
struct flb_msk_iam_cb;

struct flb_msk_iam_cb {
    void *plugin_ctx;
    struct flb_aws_msk_iam *iam;
    char *broker_host;  /* Store the actual broker hostname */
};

/* Wrapper for storing plugin context and MSK IAM state */

/*
 * Register the oauthbearer refresh callback for MSK IAM authentication.
 * Returns context pointer on success or NULL on failure.
 */
struct flb_aws_msk_iam *flb_aws_msk_iam_register_oauth_cb(struct flb_config *config,
                                                          rd_kafka_conf_t *kconf,
                                                          const char *cluster_arn,
                                                        //   const char *broker_host,
                                                          void *owner);

/* Destroy MSK IAM context */
void flb_aws_msk_iam_destroy(struct flb_aws_msk_iam *ctx);

#endif /* FLB_AWS_MSK_IAM_H */
