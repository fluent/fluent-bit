#include <stdio.h>
#include <string.h>
#include <librdkafka/rdkafka.h>

int main (int argc, char **argv) {
        rd_kafka_conf_t *conf;
        char buf[512];
        size_t sz = sizeof(buf);
        rd_kafka_conf_res_t res;
        static const char *expected_features = "ssl,sasl_gssapi,lz4,zstd";
        char errstr[512];
        int i;
        int failures = 0;

        printf("librdkafka %s (0x%x, define: 0x%x)\n",
               rd_kafka_version_str(), rd_kafka_version(), RD_KAFKA_VERSION);

        if (argc > 1 && !(argc & 1)) {
                printf("Usage: %s [config.property config-value ..]\n",
                       argv[0]);
                return 1;
        }

        conf = rd_kafka_conf_new();
        res = rd_kafka_conf_get(conf, "builtin.features", buf, &sz);

        if (res != RD_KAFKA_CONF_OK) {
                printf("ERROR: conf_get failed: %d\n", res);
                return 1;
        }

        printf("builtin.features: %s\n", buf);

        /* librdkafka allows checking for expected features
         * by setting the corresponding feature flags in builtin.features,
         * which will return an error if one or more flags are not enabled. */
        if (rd_kafka_conf_set(conf, "builtin.features", expected_features,
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                printf("ERROR: expected at least features: %s\n"
                       "got error: %s\n",
                       expected_features, errstr);
                failures++;
        }

        printf("all expected features matched: %s\n", expected_features);

        /* Apply config from argv key value pairs */
        for (i = 1 ; i+1 < argc ; i += 2) {
                printf("verifying config %s=%s\n", argv[i], argv[i+1]);
                if (rd_kafka_conf_set(conf, argv[i], argv[i+1],
                                      errstr, sizeof(errstr)) !=
                    RD_KAFKA_CONF_OK) {
                        printf("ERROR: failed to set %s=%s: %s\n",
                               argv[i], argv[i+1], errstr);
                        failures++;
                }
        }

        rd_kafka_conf_destroy(conf);

        printf("%d failures\n", failures);

        return !!failures;
}
