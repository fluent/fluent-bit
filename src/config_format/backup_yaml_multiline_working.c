    case STATE_MULTILINE_PARSER:
        switch (event->type) {
        case YAML_SEQUENCE_START_EVENT:
            /* Start of the multiline parsers list */
            printf("sequence starts: %d\n", state->state);
            break;

        case YAML_MAPPING_START_EVENT:
            printf("mapping starts");
            /* we handle each multiline parser definition as a new section */
            if (add_section_type(conf, state) == -1) {
                flb_error("Unable to add multiline parsers section");
                return YAML_FAILURE;
            }

            /* Start of an individual multiline parser entry */
            state = state_push_withvals(ctx, state, STATE_MULTILINE_PARSER_ENTRY);
            if (!state) {
                flb_error("Unable to allocate state for multiline parser entry");
                return YAML_FAILURE;
            }
            break;

        case YAML_SEQUENCE_END_EVENT:
            /* End of the multiline parsers list */
            state = state_pop(ctx);
            if (!state) {
                flb_error("No state left");
                return YAML_FAILURE;
            }
            break;

        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;
    case STATE_MULTILINE_PARSER_ENTRY:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            printf("parser entry: scalar event: %s\n", event->data.scalar.value);
            /* Found a key within the multiline parser entry */
            value = (char *) event->data.scalar.value;

            if (strcmp(value, "rules") == 0) {
                state = state_push(ctx, STATE_MULTILINE_PARSER_RULE);
                if (state == NULL) {
                    flb_error("Unable to allocate state for multiline parser rules");
                    return YAML_FAILURE;
                }

                if (state_create_group(conf, state, "rules") == YAML_FAILURE) {
                    flb_error("unable to create group");
                    return YAML_FAILURE;
                }
                break;
            }

            state = state_push_key(ctx, STATE_MULTILINE_PARSER_VALUE, value);
            if (!state) {
                flb_error("Unable to allocate state for multiline parser key");
                return YAML_FAILURE;
            }
            break;

        case YAML_MAPPING_END_EVENT:
            /* End of an individual multiline parser entry */
            print_current_properties(state);
            state = state_pop(ctx);
            if (!state) {
                flb_error("No state left");
                return YAML_FAILURE;
            }
            break;

        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;
    case STATE_MULTILINE_PARSER_VALUE:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            /* Store the value for the previous key */
            value = (char *)event->data.scalar.value;
            printf("value: %s\n", value);
            if (flb_cf_section_property_add(conf, state->cf_section->properties,
                                        state->key, flb_sds_len(state->key),
                                        value, strlen(value)) < 0) {
                flb_error("unable to add property");
                return YAML_FAILURE;
            }

            /* Return to the multiline parser entry state */
            state = state_pop(ctx);
            if (!state) {
                flb_error("No state left");
                return YAML_FAILURE;
              }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;
    /*
     * multiline_parser:
     *   type: ...
     *   others: ...
     *   rules:
     */

    case STATE_MULTILINE_PARSER_RULE:
        switch(event->type) {
            case YAML_SEQUENCE_START_EVENT:
                break;
            case YAML_SEQUENCE_END_EVENT:

                state = state_pop(ctx);

                if (state == NULL) {
                    flb_error("no state left");
                    return YAML_FAILURE;
                }
                break;
            case YAML_MAPPING_START_EVENT:
                state = state_push_withvals(ctx, state, STATE_MULTILINE_RULE_KEY);

                if (state == NULL) {
                    flb_error("unable to allocate state");
                    return YAML_FAILURE;
                }
                state->section = SECTION_PROCESSOR;
                break;
            case YAML_MAPPING_END_EVENT:
                return YAML_FAILURE;
                break;
            default:
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
        };
        break;
    case STATE_MULTILINE_RULE_KEY:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            /* Found a key in the rule */
            value = (char *) event->data.scalar.value;
            printf("Rule key: %s\n", value);

            /* Push to capture the value for this key */
            state = state_push_key(ctx, STATE_MULTILINE_RULE_VALUE, value);
            if (!state) {
                flb_error("Unable to allocate state for rule key value");
                return YAML_FAILURE;
            }
            break;

        case YAML_MAPPING_END_EVENT:
            /* End of a rule entry */
            printf("End of rule\n");

            state = state_pop(ctx);
            if (!state) {
                flb_error("No state left");
                return YAML_FAILURE;
            }
            break;

        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_MULTILINE_RULE_VALUE:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            /* Found a value for the rule key */
            value = (char *)event->data.scalar.value;
            printf("Rule value: %s\n", value);

            /* Store the key-value pair in the current rule */
            if (cfl_kvlist_insert_string(state->keyvals, state->key, value) < 0) {
                flb_error("Unable to insert key-value pair into rule");
                return YAML_FAILURE;
            }

            /* Pop back to the rule key state */
            state = state_pop(ctx);
            if (!state) {
                flb_error("No state left");
                return YAML_FAILURE;
            }
            break;

        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;
