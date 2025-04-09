#include <stdio.h>
#include <string.h>
#include <librdkafka/rdkafka.h>

int main(int argc, char **argv) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        char features[256];
        size_t fsize = sizeof(features);
        char errstr[512];
        const char *exp_features[] = {
            "gzip", "snappy",           "ssl",        "sasl",       "regex",
            "lz4",  "sasl_gssapi",      "sasl_plain", "sasl_scram", "plugins",
            "zstd", "sasl_oauthbearer", NULL,
        };
        const char **exp;
        int missing = 0;


        printf("librdkafka %s\n", rd_kafka_version_str());

        conf = rd_kafka_conf_new();
        if (rd_kafka_conf_get(conf, "builtin.features", features, &fsize) !=
            RD_KAFKA_CONF_OK) {
                fprintf(stderr, "conf_get failed\n");
                return 1;
        }

        printf("builtin.features %s\n", features);

        /* Verify that expected features are enabled. */
        for (exp = exp_features; *exp; exp++) {
                const char *t = features;
                size_t elen   = strlen(*exp);
                int match     = 0;

                while ((t = strstr(t, *exp))) {
                        if (t[elen] == ',' || t[elen] == '\0') {
                                match = 1;
                                break;
                        }
                        t += elen;
                }

                if (match)
                        continue;

                fprintf(stderr, "ERROR: feature %s not found\n", *exp);
                missing++;
        }

        if (rd_kafka_conf_set(conf, "security.protocol", "SASL_SSL", errstr,
                              sizeof(errstr)) ||
            rd_kafka_conf_set(conf, "sasl.mechanism", "PLAIN", errstr,
                              sizeof(errstr)) ||
            rd_kafka_conf_set(conf, "sasl.username", "username", errstr,
                              sizeof(errstr)) ||
            rd_kafka_conf_set(conf, "sasl.password", "password", errstr,
                              sizeof(errstr)) ||
            rd_kafka_conf_set(conf, "debug", "security", errstr,
                              sizeof(errstr))) {
                fprintf(stderr, "conf_set failed: %s\n", errstr);
                return 1;
        }

        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        if (!rk) {
                fprintf(stderr, "rd_kafka_new failed: %s\n", errstr);
                return 1;
        }

        printf("client name %s\n", rd_kafka_name(rk));

        rd_kafka_destroy(rk);

        return missing ? 1 : 0;
}
