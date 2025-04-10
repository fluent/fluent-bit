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
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_conditionals.h>
#include <cfl/cfl_array.h>
#include <cfl/cfl_kvlist.h>
#include <cfl/cfl_variant.h>

#include "flb_tests_internal.h"

/* Helper functions */
static void cleanup_test_resources(struct flb_config *config, struct flb_processor_unit *pu,
                                  struct cfl_variant *condition, struct cfl_variant *rule)
{
    /* Free rule if it wasn't successfully added to the condition */
    if (rule) {
        cfl_variant_destroy(rule);
    }
    
    if (condition) {
        cfl_variant_destroy(condition);
    }
    
    if (pu) {
        if (pu->condition) {
            flb_condition_destroy(pu->condition);
        }
        if (pu->name) {
            flb_sds_destroy(pu->name);
        }
        pthread_mutex_destroy(&pu->lock);
        
        if (pu->parent) {
            /* Remove from parent's list */
            mk_list_del(&pu->_head);
            flb_processor_destroy(pu->parent);
        }
        
        flb_free(pu);
    }
    
    if (config) {
        flb_config_exit(config);
    }
}

static struct cfl_variant *create_condition_variant(const char *op, int rules_count)
{
    struct cfl_variant *variant;
    struct cfl_kvlist *kvlist;
    struct cfl_array *rules;
    struct cfl_variant *rules_var;

    variant = cfl_variant_create();
    if (!variant) {
        return NULL;
    }

    kvlist = cfl_kvlist_create();
    if (!kvlist) {
        cfl_variant_destroy(variant);
        return NULL;
    }

    /* Set operator */
    if (cfl_kvlist_insert_string(kvlist, "op", (char *)op) != 0) {
        cfl_kvlist_destroy(kvlist);
        cfl_variant_destroy(variant);
        return NULL;
    }

    /* Create empty rules array */
    rules = cfl_array_create(rules_count);
    if (!rules) {
        cfl_kvlist_destroy(kvlist);
        cfl_variant_destroy(variant);
        return NULL;
    }

    /* Insert rules array into kvlist */
    rules_var = cfl_variant_create();
    if (!rules_var) {
        cfl_array_destroy(rules);
        cfl_kvlist_destroy(kvlist);
        cfl_variant_destroy(variant);
        return NULL;
    }
    rules_var->type = CFL_VARIANT_ARRAY;
    rules_var->data.as_array = rules;

    if (cfl_kvlist_insert_array(kvlist, "rules", rules_var->data.as_array) != 0) {
        cfl_variant_destroy(rules_var);
        cfl_kvlist_destroy(kvlist);
        cfl_variant_destroy(variant);
        return NULL;
    }

    /* The array is now owned by the kvlist, but we need to clean up rules_var */
    rules_var->data.as_array = NULL; /* Prevent double-free */
    cfl_variant_destroy(rules_var);

    /* Link variant to kvlist */
    variant->type = CFL_VARIANT_KVLIST;
    variant->data.as_kvlist = kvlist;

    return variant;
}

static struct cfl_variant *create_rule_variant(const char *field, 
                                              const char *op, 
                                              void *value, 
                                              int value_type,
                                              int is_array,
                                              const char *context)
{
    struct cfl_variant *variant;
    struct cfl_kvlist *kvlist;
    struct cfl_array *array;
    char **values;
    int i;

    variant = cfl_variant_create();
    if (!variant) {
        return NULL;
    }

    kvlist = cfl_kvlist_create();
    if (!kvlist) {
        cfl_variant_destroy(variant);
        return NULL;
    }

    /* Set field */
    if (cfl_kvlist_insert_string(kvlist, "field", (char *)field) != 0) {
        cfl_kvlist_destroy(kvlist);
        cfl_variant_destroy(variant);
        return NULL;
    }

    /* Set operator */
    if (cfl_kvlist_insert_string(kvlist, "op", (char *)op) != 0) {
        cfl_kvlist_destroy(kvlist);
        cfl_variant_destroy(variant);
        return NULL;
    }

    /* Set value based on type */
    if (is_array) {
        /* Create array for IN and NOT_IN operators */
        array = cfl_array_create(2);
        if (!array) {
            cfl_kvlist_destroy(kvlist);
            cfl_variant_destroy(variant);
            return NULL;
        }

        /* Add array values */
        values = (char **)value;
        for (i = 0; i < 2; i++) {
            if (cfl_array_append_string(array, values[i]) != 0) {
                cfl_array_destroy(array);
                cfl_kvlist_destroy(kvlist);
                cfl_variant_destroy(variant);
                return NULL;
            }
        }

        if (cfl_kvlist_insert_array(kvlist, "value", array) != 0) {
            cfl_array_destroy(array);
            cfl_kvlist_destroy(kvlist);
            cfl_variant_destroy(variant);
            return NULL;
        }
    }
    else {
        switch (value_type) {
            case CFL_VARIANT_STRING:
                if (cfl_kvlist_insert_string(kvlist, "value", (char *)value) != 0) {
                    cfl_kvlist_destroy(kvlist);
                    cfl_variant_destroy(variant);
                    return NULL;
                }
                break;
            case CFL_VARIANT_INT:
                if (cfl_kvlist_insert_int64(kvlist, "value", (int64_t)*((int *)value)) != 0) {
                    cfl_kvlist_destroy(kvlist);
                    cfl_variant_destroy(variant);
                    return NULL;
                }
                break;
            case CFL_VARIANT_DOUBLE:
                if (cfl_kvlist_insert_double(kvlist, "value", *((double *)value)) != 0) {
                    cfl_kvlist_destroy(kvlist);
                    cfl_variant_destroy(variant);
                    return NULL;
                }
                break;
            case CFL_VARIANT_BOOL:
                if (cfl_kvlist_insert_bool(kvlist, "value", *((int *)value)) != 0) {
                    cfl_kvlist_destroy(kvlist);
                    cfl_variant_destroy(variant);
                    return NULL;
                }
                break;
            default:
                cfl_kvlist_destroy(kvlist);
                cfl_variant_destroy(variant);
                return NULL;
        }
    }

    /* Set context if provided */
    if (context != NULL) {
        if (cfl_kvlist_insert_string(kvlist, "context", (char *)context) != 0) {
            cfl_kvlist_destroy(kvlist);
            cfl_variant_destroy(variant);
            return NULL;
        }
    }

    /* Link variant to kvlist */
    variant->type = CFL_VARIANT_KVLIST;
    variant->data.as_kvlist = kvlist;

    return variant;
}

static int add_rule_to_condition(struct cfl_variant *condition, struct cfl_variant *rule)
{
    struct cfl_array *rules;
    
    if (!condition || !rule || 
        condition->type != CFL_VARIANT_KVLIST || 
        rule->type != CFL_VARIANT_KVLIST) {
        return -1;
    }
    
    /* Get rules array from condition */
    struct cfl_variant *rules_var = cfl_kvlist_fetch(condition->data.as_kvlist, "rules");
    if (!rules_var || rules_var->type != CFL_VARIANT_ARRAY) {
        return -1;
    }
    
    rules = rules_var->data.as_array;
    
    /* Append rule to rules array */
    return cfl_array_append(rules, rule);
}

static struct flb_processor_unit *create_processor_unit(struct flb_config *config)
{
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    
    /* Create the processor */
    proc = flb_processor_create(config, "test_processor", NULL, 0);
    if (!proc) {
        return NULL;
    }
    
    /* Let's create a mock processor unit directly for testing */
    pu = flb_calloc(1, sizeof(struct flb_processor_unit));
    if (!pu) {
        flb_processor_destroy(proc);
        return NULL;
    }
    
    pu->parent = proc;
    pu->event_type = FLB_PROCESSOR_LOGS;
    pu->name = flb_sds_create("test_unit");
    pu->condition = NULL;
    
    /* Initialize the mutex */
    pthread_mutex_init(&pu->lock, NULL);
    
    /* Initialize the lists */
    mk_list_init(&pu->unused_list);
    
    /* Add to the parent's list */
    mk_list_add(&pu->_head, &proc->logs);
    
    return pu;
}

void test_basic_condition()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    char *string_value = "error";
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create a simple rule: $level eq "error" */
    rule = create_rule_variant("$level", "eq", string_value, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        /* If we failed to add the rule, we need to free it manually */
        if (rule) {
            cfl_variant_destroy(rule);
            rule = NULL;
        }
        goto cleanup;
    }
    /* After successful addition, rule is owned by condition */
    rule = NULL;
    
    /* Test setting the condition */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == 0);
    
    /* Verify condition was created and stored */
    if (ret == 0) {
        TEST_CHECK(pu->condition != NULL);
        TEST_CHECK(pu->condition->op == FLB_COND_OP_AND);
        TEST_CHECK(mk_list_size(&pu->condition->rules) == 1);
        
        /* Condition is now owned by processor unit, destroy our copy */
        cfl_variant_destroy(condition);
        condition = NULL;
    }
    
cleanup:
    /* Free rule if it wasn't successfully added to the condition */
    if (rule) {
        cfl_variant_destroy(rule);
    }
    if (condition) {
        cfl_variant_destroy(condition);
    }
    if (pu) {
        if (pu->condition) {
            flb_condition_destroy(pu->condition);
        }
        if (pu->name) {
            flb_sds_destroy(pu->name);
        }
        pthread_mutex_destroy(&pu->lock);
        
        if (pu->parent) {
            /* Remove from parent's list */
            mk_list_del(&pu->_head);
            flb_processor_destroy(pu->parent);
        }
        
        flb_free(pu);
    }
    if (config) {
        flb_config_exit(config);
    }
}

void test_condition_operator_validation()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    char *string_value = "error";
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with invalid operator */
    condition = create_condition_variant("INVALID", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create a simple rule */
    rule = create_rule_variant("$level", "eq", string_value, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        /* If we failed to add the rule, we need to free it manually */
        if (rule) {
            cfl_variant_destroy(rule);
            rule = NULL;
        }
        goto cleanup;
    }
    /* After successful addition, rule is owned by condition */
    rule = NULL;
    
    /* Test setting the condition - might fail due to invalid operator */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == -1); /* Should fail with invalid operator */
    
    /* In this test we're expecting it to fail, so we don't verify condition properties */
    
cleanup:
    /* Free rule if it wasn't successfully added to the condition */
    if (rule) {
        cfl_variant_destroy(rule);
    }
    if (condition) {
        cfl_variant_destroy(condition);
    }
    if (pu) {
        if (pu->condition) {
            flb_condition_destroy(pu->condition);
        }
        if (pu->name) {
            flb_sds_destroy(pu->name);
        }
        pthread_mutex_destroy(&pu->lock);
        
        if (pu->parent) {
            /* Remove from parent's list */
            mk_list_del(&pu->_head);
            flb_processor_destroy(pu->parent);
        }
        
        flb_free(pu);
    }
    if (config) {
        flb_config_exit(config);
    }
}

void test_empty_rules()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    int ret;
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator and no rules */
    condition = create_condition_variant("and", 0);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Test setting the condition - expected to fail with empty rules array */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == -1); /* Empty rules array should cause failure */
    
    /* We're expecting failure, so no condition should be set */
    
cleanup:
    if (condition) {
        cfl_variant_destroy(condition);
    }
    if (pu) {
        if (pu->condition) {
            flb_condition_destroy(pu->condition);
        }
        if (pu->name) {
            flb_sds_destroy(pu->name);
        }
        pthread_mutex_destroy(&pu->lock);
        
        if (pu->parent) {
            /* Remove from parent's list */
            mk_list_del(&pu->_head);
            flb_processor_destroy(pu->parent);
        }
        
        flb_free(pu);
    }
    if (config) {
        flb_config_exit(config);
    }
}

void test_multiple_rules()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule1 = NULL, *rule2 = NULL;
    int ret;
    char *string_value1 = "error";
    double numeric_value = 100.5;
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 2);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create first rule: $level eq "error" */
    rule1 = create_rule_variant("$level", "eq", string_value1, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule1 != NULL);
    if (!rule1) {
        goto cleanup;
    }
    
    /* Create second rule: $response_time gt 100.5 */
    rule2 = create_rule_variant("$response_time", "gt", &numeric_value, CFL_VARIANT_DOUBLE, 0, NULL);
    TEST_CHECK(rule2 != NULL);
    if (!rule2) {
        goto cleanup;
    }
    
    /* Add rules to condition */
    ret = add_rule_to_condition(condition, rule1);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        /* If we failed to add the rule, we need to free it manually */
        cfl_variant_destroy(rule1);
        rule1 = NULL;
        goto cleanup;
    }
    /* rule1 is now owned by condition */
    rule1 = NULL;
    
    ret = add_rule_to_condition(condition, rule2);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        /* If we failed to add the rule, we need to free it manually */
        cfl_variant_destroy(rule2);
        rule2 = NULL;
        goto cleanup;
    }
    /* rule2 is now owned by condition */
    rule2 = NULL;
    
    /* Test setting the condition */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == 0);
    
    /* Verify condition was created and stored with both rules */
    if (ret == 0 && pu->condition != NULL) {
        TEST_CHECK(pu->condition->op == FLB_COND_OP_AND);
        TEST_CHECK(mk_list_size(&pu->condition->rules) == 2);
        
        /* Condition is now owned by processor unit, destroy our copy */
        cfl_variant_destroy(condition);
        condition = NULL;
    }
    
cleanup:
    /* Free rules if they weren't successfully added to the condition */
    if (rule1) {
        cfl_variant_destroy(rule1);
    }
    if (rule2) {
        cfl_variant_destroy(rule2);
    }
    if (condition) {
        cfl_variant_destroy(condition);
    }
    if (pu) {
        if (pu->condition) {
            flb_condition_destroy(pu->condition);
        }
        if (pu->name) {
            flb_sds_destroy(pu->name);
        }
        pthread_mutex_destroy(&pu->lock);
        
        if (pu->parent) {
            /* Remove from parent's list */
            mk_list_del(&pu->_head);
            flb_processor_destroy(pu->parent);
        }
        
        flb_free(pu);
    }
    if (config) {
        flb_config_exit(config);
    }
}

void test_context_metadata()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    char *string_value = "production";
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create a rule with metadata context: $namespace eq "production" in metadata */
    rule = create_rule_variant("$namespace", "eq", string_value, CFL_VARIANT_STRING, 0, "metadata");
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        /* If we failed to add the rule, we need to free it manually */
        if (rule) {
            cfl_variant_destroy(rule);
            rule = NULL;
        }
        goto cleanup;
    }
    /* After successful addition, rule is owned by condition */
    rule = NULL;
    
    /* Test setting the condition */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == 0);
    
    /* Verify condition was created and stored */
    if (ret == 0) {
        TEST_CHECK(pu->condition != NULL);
        TEST_CHECK(pu->condition->op == FLB_COND_OP_AND);
        TEST_CHECK(mk_list_size(&pu->condition->rules) == 1);
        
        /* Condition is now owned by processor unit, destroy our copy */
        cfl_variant_destroy(condition);
        condition = NULL;
    }
    
cleanup:
    cleanup_test_resources(config, pu, condition, rule);
}

void test_all_comparison_operators()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    char *string_value = "error";
    double numeric_value = 100.0;
    char *array_values[2] = {"warning", "error"};
    char *regex_pattern = "^error.*$";
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with OR operator */
    condition = create_condition_variant("or", 6);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Test EQ operator */
    rule = create_rule_variant("$level", "eq", string_value, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test NEQ operator */
    rule = create_rule_variant("$level", "neq", string_value, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test GT operator */
    rule = create_rule_variant("$response_time", "gt", &numeric_value, CFL_VARIANT_DOUBLE, 0, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test LT operator */
    rule = create_rule_variant("$response_time", "lt", &numeric_value, CFL_VARIANT_DOUBLE, 0, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test REGEX operator */
    rule = create_rule_variant("$message", "regex", regex_pattern, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test IN operator */
    rule = create_rule_variant("$level", "in", array_values, CFL_VARIANT_STRING, 1, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == 0);
    
    /* Verify condition was created and stored with all rules */
    if (ret == 0) {
        TEST_CHECK(pu->condition != NULL);
        TEST_CHECK(pu->condition->op == FLB_COND_OP_OR);
        TEST_CHECK(mk_list_size(&pu->condition->rules) == 6);
    }
    
    /* Condition is now owned by processor unit, destroy our copy */
    cfl_variant_destroy(condition);
    condition = NULL;
    
cleanup:
    if (rule) {
        cfl_variant_destroy(rule);
    }
    if (condition) {
        cfl_variant_destroy(condition);
    }
    
    if (pu) {
        if (pu->condition) {
            flb_condition_destroy(pu->condition);
        }
        if (pu->name) {
            flb_sds_destroy(pu->name);
        }
        pthread_mutex_destroy(&pu->lock);
        
        if (pu->parent) {
            /* Remove from parent's list */
            mk_list_del(&pu->_head);
            flb_processor_destroy(pu->parent);
        }
        
        flb_free(pu);
    }
    
    if (config) {
        flb_config_exit(config);
    }
}

void test_gte_lte_operators() 
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule1 = NULL, *rule2 = NULL;
    int ret;
    double value1 = 1024.0;
    double value2 = 95.5;
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 2);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create first rule: $memory gte 1024.0 */
    rule1 = create_rule_variant("$memory", "gte", &value1, CFL_VARIANT_DOUBLE, 0, NULL);
    TEST_CHECK(rule1 != NULL);
    if (!rule1) {
        goto cleanup;
    }
    
    /* Create second rule: $cpu lte 95.5 */
    rule2 = create_rule_variant("$cpu", "lte", &value2, CFL_VARIANT_DOUBLE, 0, NULL);
    TEST_CHECK(rule2 != NULL);
    if (!rule2) {
        goto cleanup;
    }
    
    /* Add rules to condition */
    ret = add_rule_to_condition(condition, rule1);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule1);
        rule1 = NULL;
        goto cleanup;
    }
    rule1 = NULL; /* Ownership transferred to condition */
    
    ret = add_rule_to_condition(condition, rule2);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule2);
        rule2 = NULL;
        goto cleanup;
    }
    rule2 = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == 0);
    
    /* Verify condition was created and stored */
    if (ret == 0) {
        TEST_CHECK(pu->condition != NULL);
        TEST_CHECK(pu->condition->op == FLB_COND_OP_AND);
        TEST_CHECK(mk_list_size(&pu->condition->rules) == 2);
        
        /* Condition is now owned by processor unit, destroy our copy */
        cfl_variant_destroy(condition);
        condition = NULL;
    }
    
cleanup:
    cleanup_test_resources(config, pu, condition, NULL);
    if (rule1) {
        cfl_variant_destroy(rule1);
    }
    if (rule2) {
        cfl_variant_destroy(rule2);
    }
}

void test_not_regex_operator()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    char *pattern = "error|warning";
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create rule: $log not_regex "error|warning" */
    rule = create_rule_variant("$log", "not_regex", pattern, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == 0);
    
    /* Verify condition was created and stored */
    if (ret == 0) {
        TEST_CHECK(pu->condition != NULL);
        TEST_CHECK(pu->condition->op == FLB_COND_OP_AND);
        TEST_CHECK(mk_list_size(&pu->condition->rules) == 1);
        
        /* Condition is now owned by processor unit, destroy our copy */
        cfl_variant_destroy(condition);
        condition = NULL;
    }
    
cleanup:
    cleanup_test_resources(config, pu, condition, rule);
}

void test_not_in_operator()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    char *array_values[2] = {"info", "debug"};
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create rule: $level not_in ["info", "debug"] */
    rule = create_rule_variant("$level", "not_in", array_values, CFL_VARIANT_STRING, 1, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == 0);
    
    /* Verify condition was created and stored */
    if (ret == 0) {
        TEST_CHECK(pu->condition != NULL);
        TEST_CHECK(pu->condition->op == FLB_COND_OP_AND);
        TEST_CHECK(mk_list_size(&pu->condition->rules) == 1);
        
        /* Condition is now owned by processor unit, destroy our copy */
        cfl_variant_destroy(condition);
        condition = NULL;
    }
    
cleanup:
    cleanup_test_resources(config, pu, condition, rule);
}

void test_dollar_prefixed_fields()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    char *string_value = "GET";
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create a rule with complex field path using $ prefix: $request['method'] eq "GET" */
    rule = create_rule_variant("$request['method']", "eq", string_value, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == 0);
    
    /* Verify condition was created and stored */
    if (ret == 0) {
        TEST_CHECK(pu->condition != NULL);
        TEST_CHECK(pu->condition->op == FLB_COND_OP_AND);
        TEST_CHECK(mk_list_size(&pu->condition->rules) == 1);
        
        /* Condition is now owned by processor unit, destroy our copy */
        cfl_variant_destroy(condition);
        condition = NULL;
    }
    
cleanup:
    cleanup_test_resources(config, pu, condition, rule);
}

void test_deeply_nested_field_access()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    char *string_value = "Bearer token";
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create a rule with deeply nested field path: $request['headers']['Authorization'] eq "Bearer token" */
    rule = create_rule_variant("$request['headers']['Authorization']", "eq", 
                              string_value, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == 0);
    
    /* Verify condition was created and stored */
    if (ret == 0) {
        TEST_CHECK(pu->condition != NULL);
        TEST_CHECK(pu->condition->op == FLB_COND_OP_AND);
        TEST_CHECK(mk_list_size(&pu->condition->rules) == 1);
        
        /* Condition is now owned by processor unit, destroy our copy */
        cfl_variant_destroy(condition);
        condition = NULL;
    }
    
cleanup:
    cleanup_test_resources(config, pu, condition, rule);
}

void test_overwrite_existing_condition()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition1 = NULL;
    struct cfl_variant *condition2 = NULL;
    struct cfl_variant *rule1 = NULL;
    struct cfl_variant *rule2 = NULL;
    int ret;
    char *string_value1 = "error";
    char *string_value2 = "warning";
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create first condition with AND operator */
    condition1 = create_condition_variant("and", 1);
    TEST_CHECK(condition1 != NULL);
    if (!condition1) {
        goto cleanup;
    }
    
    /* Create a rule: $level eq "error" */
    rule1 = create_rule_variant("$level", "eq", string_value1, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule1 != NULL);
    if (!rule1) {
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition1, rule1);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule1);
        rule1 = NULL;
        goto cleanup;
    }
    rule1 = NULL; /* Ownership transferred to condition1 */
    
    /* Test setting the first condition */
    ret = flb_processor_unit_set_property(pu, "condition", condition1);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }
    
    /* Verify first condition was created and stored */
    TEST_CHECK(pu->condition != NULL);
    TEST_CHECK(pu->condition->op == FLB_COND_OP_AND);
    TEST_CHECK(mk_list_size(&pu->condition->rules) == 1);
    
    /* The pu->condition now owns the condition, so we can free condition1 */
    cfl_variant_destroy(condition1);
    condition1 = NULL;
    
    /* Now create second condition with OR operator */
    condition2 = create_condition_variant("or", 1);
    TEST_CHECK(condition2 != NULL);
    if (!condition2) {
        goto cleanup;
    }
    
    /* Create a rule: $level eq "warning" */
    rule2 = create_rule_variant("$level", "eq", string_value2, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule2 != NULL);
    if (!rule2) {
        goto cleanup;
    }
    
    /* Add rule to second condition */
    ret = add_rule_to_condition(condition2, rule2);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule2);
        rule2 = NULL;
        goto cleanup;
    }
    rule2 = NULL; /* Ownership transferred to condition2 */
    
    /* Test setting the second condition (should overwrite the first one) */
    ret = flb_processor_unit_set_property(pu, "condition", condition2);
    TEST_CHECK(ret == 0);
    
    /* Verify second condition replaced the first one */
    if (ret == 0) {
        TEST_CHECK(pu->condition != NULL);
        TEST_CHECK(pu->condition->op == FLB_COND_OP_OR);
        TEST_CHECK(mk_list_size(&pu->condition->rules) == 1);
    }
    
    /* Condition is now owned by the processor unit, so we can free condition2 */
    cfl_variant_destroy(condition2);
    condition2 = NULL;
    
cleanup:
    if (rule1) {
        cfl_variant_destroy(rule1);
    }
    if (rule2) {
        cfl_variant_destroy(rule2);
    }
    if (condition1) {
        cfl_variant_destroy(condition1);
    }
    if (condition2) {
        cfl_variant_destroy(condition2);
    }
    if (pu) {
        if (pu->condition) {
            flb_condition_destroy(pu->condition);
        }
        if (pu->name) {
            flb_sds_destroy(pu->name);
        }
        pthread_mutex_destroy(&pu->lock);
        
        if (pu->parent) {
            /* Remove from parent's list */
            mk_list_del(&pu->_head);
            flb_processor_destroy(pu->parent);
        }
        
        flb_free(pu);
    }
    if (config) {
        flb_config_exit(config);
    }
}

void test_invalid_rule_missing_field()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create invalid rule variant with missing fields */
    rule = cfl_variant_create();
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    rule->type = CFL_VARIANT_KVLIST;
    rule->data.as_kvlist = cfl_kvlist_create();
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition - should fail due to missing field in rule */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == -1);
    
cleanup:
    cleanup_test_resources(config, pu, condition, rule);
}

void test_invalid_rule_missing_operator()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create invalid rule variant with missing operator */
    rule = cfl_variant_create();
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    rule->type = CFL_VARIANT_KVLIST;
    rule->data.as_kvlist = cfl_kvlist_create();
    
    if (!rule->data.as_kvlist) {
        goto cleanup;
    }
    
    if (cfl_kvlist_insert_string(rule->data.as_kvlist, "field", "$level") != 0) {
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition - should fail due to missing operator in rule */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == -1);
    
cleanup:
    cleanup_test_resources(config, pu, condition, rule);
}

void test_invalid_rule_missing_value()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create invalid rule variant with missing value */
    rule = cfl_variant_create();
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    rule->type = CFL_VARIANT_KVLIST;
    rule->data.as_kvlist = cfl_kvlist_create();
    
    if (!rule->data.as_kvlist) {
        goto cleanup;
    }
    
    if (cfl_kvlist_insert_string(rule->data.as_kvlist, "field", "$level") != 0 ||
        cfl_kvlist_insert_string(rule->data.as_kvlist, "op", "eq") != 0) {
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition - should fail due to missing value in rule */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == -1);
    
cleanup:
    cleanup_test_resources(config, pu, condition, rule);
}

void test_invalid_condition_structure()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *invalid_condition = NULL;
    int ret;
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create invalid condition (not a kvlist) */
    invalid_condition = cfl_variant_create();
    TEST_CHECK(invalid_condition != NULL);
    if (!invalid_condition) {
        goto cleanup;
    }
    
    /* Properly allocate the string to avoid memory issues */
    invalid_condition->type = CFL_VARIANT_STRING;
    invalid_condition->data.as_string = flb_sds_create("not a valid condition");
    
    /* Test setting the condition - should fail due to invalid condition structure */
    ret = flb_processor_unit_set_property(pu, "condition", invalid_condition);
    TEST_CHECK(ret == -1);
    
cleanup:
    /* Clean up variant manually instead of using the helper */
    if (invalid_condition) {
        if (invalid_condition->type == CFL_VARIANT_STRING && 
            invalid_condition->data.as_string) {
            flb_sds_destroy(invalid_condition->data.as_string);
            invalid_condition->data.as_string = NULL;
        }
        cfl_variant_destroy(invalid_condition);
    }
    
    if (pu) {
        if (pu->condition) {
            flb_condition_destroy(pu->condition);
        }
        if (pu->name) {
            flb_sds_destroy(pu->name);
        }
        pthread_mutex_destroy(&pu->lock);
        
        if (pu->parent) {
            /* Remove from parent's list */
            mk_list_del(&pu->_head);
            flb_processor_destroy(pu->parent);
        }
        
        flb_free(pu);
    }
    
    if (config) {
        flb_config_exit(config);
    }
}

void test_invalid_rules_array()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    int ret;
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition without rules array */
    condition = cfl_variant_create();
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    condition->type = CFL_VARIANT_KVLIST;
    condition->data.as_kvlist = cfl_kvlist_create();
    
    if (!condition->data.as_kvlist) {
        goto cleanup;
    }
    
    if (cfl_kvlist_insert_string(condition->data.as_kvlist, "op", "and") != 0) {
        goto cleanup;
    }
    
    /* Test setting the condition - should fail due to missing rules array */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == -1);
    
cleanup:
    /* In this case, we're correctly using cfl_kvlist_insert_string which 
     * properly handles the memory, so we can use the helper function */
    cleanup_test_resources(config, pu, condition, NULL);
}

void test_array_value_for_numeric_operator()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    char *array_values[2] = {"100", "200"};
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create invalid rule: $response_time gt ["100", "200"] */
    rule = create_rule_variant("$response_time", "gt", array_values, CFL_VARIANT_STRING, 1, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition - should fail due to array value for numeric operator */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == -1);
    
cleanup:
    cleanup_test_resources(config, pu, condition, rule);
}

void test_string_value_for_in_operator()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create our own rule variant directly instead of using create_rule_variant */
    rule = cfl_variant_create();
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    /* Set up the rule structure manually */
    rule->type = CFL_VARIANT_KVLIST;
    rule->data.as_kvlist = cfl_kvlist_create();
    if (!rule->data.as_kvlist) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    
    /* Add required fields to the rule */
    if (cfl_kvlist_insert_string(rule->data.as_kvlist, "field", "$level") != 0 ||
        cfl_kvlist_insert_string(rule->data.as_kvlist, "op", "in") != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    
    /* Create a string value instead of an array - this is intentionally incorrect
     * Now that we've fixed the code, this should be properly validated and rejected
     * with an error instead of crashing */
    if (cfl_kvlist_insert_string(rule->data.as_kvlist, "value", "error") != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition - should now fail with a proper validation error
     * instead of crashing, because we added explicit validation for 'in' operations */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == -1);
    
cleanup:
    cleanup_test_resources(config, pu, condition, rule);
}

void test_invalid_regex_pattern()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule = NULL;
    int ret;
    char *invalid_pattern = "[invalid";
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create condition with AND operator */
    condition = create_condition_variant("and", 1);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Create rule with invalid regex pattern: $log regex "[invalid" */
    rule = create_rule_variant("$log", "regex", invalid_pattern, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule != NULL);
    if (!rule) {
        goto cleanup;
    }
    
    /* Add rule to condition */
    ret = add_rule_to_condition(condition, rule);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule);
        rule = NULL;
        goto cleanup;
    }
    rule = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition - should fail due to invalid regex pattern */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == -1);
    
cleanup:
    cleanup_test_resources(config, pu, condition, rule);
}

void test_complex_nested_condition()
{
    struct flb_config *config = NULL;
    struct flb_processor_unit *pu = NULL;
    struct cfl_variant *condition = NULL;
    struct cfl_variant *rule1 = NULL;
    struct cfl_variant *rule2 = NULL;
    struct cfl_variant *rule3 = NULL;
    int ret;
    char *string_value1 = "error";
    double numeric_value = 1000.0;
    char *array_values[2] = {"production", "staging"};
    
    /* Initialize */
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        goto cleanup;
    }
    
    pu = create_processor_unit(config);
    TEST_CHECK(pu != NULL);
    if (!pu) {
        goto cleanup;
    }
    
    /* Create complex condition with AND operator */
    condition = create_condition_variant("and", 3);
    TEST_CHECK(condition != NULL);
    if (!condition) {
        goto cleanup;
    }
    
    /* Rule 1: $level eq "error" */
    rule1 = create_rule_variant("$level", "eq", string_value1, CFL_VARIANT_STRING, 0, NULL);
    TEST_CHECK(rule1 != NULL);
    if (!rule1) {
        goto cleanup;
    }
    
    /* Rule 2: $response_time gt 1000.0 */
    rule2 = create_rule_variant("$response_time", "gt", &numeric_value, CFL_VARIANT_DOUBLE, 0, NULL);
    TEST_CHECK(rule2 != NULL);
    if (!rule2) {
        goto cleanup;
    }
    
    /* Rule 3: $env in ["production", "staging"] using metadata context */
    rule3 = create_rule_variant("$env", "in", array_values, CFL_VARIANT_STRING, 1, "metadata");
    TEST_CHECK(rule3 != NULL);
    if (!rule3) {
        goto cleanup;
    }
    
    /* Add rule1 to condition */
    ret = add_rule_to_condition(condition, rule1);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule1);
        rule1 = NULL;
        goto cleanup;
    }
    rule1 = NULL; /* Ownership transferred to condition */
    
    /* Add rule2 to condition */
    ret = add_rule_to_condition(condition, rule2);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule2);
        rule2 = NULL;
        goto cleanup;
    }
    rule2 = NULL; /* Ownership transferred to condition */
    
    /* Add rule3 to condition */
    ret = add_rule_to_condition(condition, rule3);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cfl_variant_destroy(rule3);
        rule3 = NULL;
        goto cleanup;
    }
    rule3 = NULL; /* Ownership transferred to condition */
    
    /* Test setting the condition */
    ret = flb_processor_unit_set_property(pu, "condition", condition);
    TEST_CHECK(ret == 0);
    
    /* Verify condition was created and stored */
    if (ret == 0) {
        TEST_CHECK(pu->condition != NULL);
        TEST_CHECK(pu->condition->op == FLB_COND_OP_AND);
        TEST_CHECK(mk_list_size(&pu->condition->rules) == 3);
    }
    
    /* Condition is now owned by the processor unit, destroy our copy */
    cfl_variant_destroy(condition);
    condition = NULL;
    
cleanup:
    if (rule1) cfl_variant_destroy(rule1);
    if (rule2) cfl_variant_destroy(rule2);
    if (rule3) cfl_variant_destroy(rule3);
    if (condition) cfl_variant_destroy(condition);
    
    if (pu) {
        if (pu->condition) {
            flb_condition_destroy(pu->condition);
        }
        if (pu->name) {
            flb_sds_destroy(pu->name);
        }
        pthread_mutex_destroy(&pu->lock);
        
        if (pu->parent) {
            /* Remove from parent's list */
            mk_list_del(&pu->_head);
            flb_processor_destroy(pu->parent);
        }
        
        flb_free(pu);
    }
    
    if (config) {
        flb_config_exit(config);
    }
}

TEST_LIST = {
    {"basic_condition", test_basic_condition},
    {"condition_operator_validation", test_condition_operator_validation},
    {"empty_rules", test_empty_rules},
    {"multiple_rules", test_multiple_rules},
    {"context_metadata", test_context_metadata},
    {"all_comparison_operators", test_all_comparison_operators},
    {"gte_lte_operators", test_gte_lte_operators},
    {"not_regex_operator", test_not_regex_operator},
    {"not_in_operator", test_not_in_operator},
    {"dollar_prefixed_fields", test_dollar_prefixed_fields},
    {"deeply_nested_field_access", test_deeply_nested_field_access},
    {"overwrite_existing_condition", test_overwrite_existing_condition},
    {"invalid_rule_missing_field", test_invalid_rule_missing_field},
    {"invalid_rule_missing_operator", test_invalid_rule_missing_operator},
    {"invalid_rule_missing_value", test_invalid_rule_missing_value},
    {"invalid_condition_structure", test_invalid_condition_structure},
    {"invalid_rules_array", test_invalid_rules_array},
    {"array_value_for_numeric_operator", test_array_value_for_numeric_operator},
    {"string_value_for_in_operator", test_string_value_for_in_operator},
    {"invalid_regex_pattern", test_invalid_regex_pattern},
    {"complex_nested_condition", test_complex_nested_condition},
    {NULL, NULL}
};