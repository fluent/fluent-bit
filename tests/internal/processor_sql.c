/* SPDX-License-Identifier: Apache-2.0 */

#include <fluent-bit.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include "flb_tests_internal.h"

static void sql_string_boundaries(void)
{
    const char *inputs[] = {
        "[0,{\"keep\":\"yes\",\"next\":\"not part of keep\"}]",
        "[0,{\"keep\":\"yes\\u0000suffix\"}]",
        "[0,{\"keep\":\"\"}]",
        "[0,{}]"
    };
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct cfl_variant *query;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    char *packed;
    void *output;
    size_t packed_size;
    size_t output_size;
    size_t index;
    int root_type;
    int records;

    flb_init_env();
    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    processor = flb_processor_create(config, "sql_boundaries", NULL, 0);
    TEST_ASSERT(processor != NULL);
    unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS, "sql");
    TEST_ASSERT(unit != NULL);
    query = cfl_variant_create_from_string("SELECT * FROM STREAM WHERE keep = 'yes';");
    TEST_ASSERT(query != NULL);
    TEST_ASSERT(flb_processor_unit_set_property(unit, "query", query) == 0);
    cfl_variant_destroy(query);
    TEST_ASSERT(flb_processor_init(processor) == 0);

    for (index = 0; index < sizeof(inputs) / sizeof(inputs[0]); index++) {
        TEST_ASSERT(flb_pack_json(inputs[index], strlen(inputs[index]), &packed,
                                  &packed_size, &root_type, NULL) == 0);
        output = NULL;
        output_size = 0;
        TEST_ASSERT(flb_processor_run(processor, 0, FLB_PROCESSOR_LOGS, "test", 4,
                                      packed, packed_size, &output, &output_size) == 0);
        records = 0;
        if (output_size > 0) {
            TEST_ASSERT(flb_log_event_decoder_init(&decoder, output, output_size) == 0);
            while (flb_log_event_decoder_next(&decoder, &event) == 0) {
                records++;
            }
            flb_log_event_decoder_destroy(&decoder);
        }
        TEST_CHECK(records == (index == 0 ? 1 : 0));
        if (output != packed) {
            flb_free(output);
        }
        flb_free(packed);
    }
    flb_processor_destroy(processor);
    flb_config_exit(config);
}

TEST_LIST = {
    { "sql_string_boundaries", sql_string_boundaries },
    { 0 }
};
