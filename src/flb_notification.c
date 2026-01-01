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

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_notification.h>

union generic_plugin_instance {
    struct flb_input_instance     *input;
    struct flb_output_instance    *output;
    struct flb_filter_instance    *filter;
    struct flb_processor_instance *processor;
    void                          *generic;
};

static struct flb_input_instance *find_input_instance(
                                    char *name,
                                    struct flb_config *config)
{
    struct mk_list              *iterator;
    struct flb_input_instance   *instance;

    mk_list_foreach(iterator, &config->inputs) {
        instance = mk_list_entry(iterator,
                                 struct flb_input_instance,
                                 _head);

        if (strcmp(flb_input_name(instance), name) == 0) {
            return instance;
        }
    }

    return NULL;
}

static struct flb_output_instance *find_output_instance(
                                    char *name,
                                    struct flb_config *config)
{
    struct mk_list              *iterator;
    struct flb_output_instance  *instance;

    mk_list_foreach(iterator, &config->outputs) {
        instance = mk_list_entry(iterator,
                                 struct flb_output_instance,
                                 _head);

        if (strcmp(flb_output_name(instance), name) == 0) {
            return instance;
        }
    }

    return NULL;
}

static struct flb_filter_instance *find_filter_instance(
                                    char *name,
                                    struct flb_config *config)
{
    struct mk_list              *iterator;
    struct flb_filter_instance  *instance;

    mk_list_foreach(iterator, &config->filters) {
        instance = mk_list_entry(iterator,
                                 struct flb_filter_instance,
                                 _head);

        if (strcmp(flb_filter_name(instance), name) == 0) {
            return instance;
        }
    }

    return NULL;
}

static void *find_processor_instance_internal_unit_level(
                char *name,
                int  *plugin_type,
                struct mk_list *processor_unit_list)
{
    struct mk_list                *iterator;
    struct flb_processor_unit     *processor_unit;
    struct flb_filter_instance    *filter_instance;
    struct flb_processor_instance *processor_instance;

    mk_list_foreach(iterator, processor_unit_list) {
        processor_unit = mk_list_entry(iterator,
                                        struct flb_processor_unit,
                                        _head);

        if (processor_unit->unit_type == FLB_PROCESSOR_UNIT_FILTER) {
            filter_instance = (struct flb_filter_instance *) \
                                processor_unit->ctx;

            if (strcmp(flb_filter_name(filter_instance), name) == 0) {
                *plugin_type = FLB_PLUGIN_FILTER;

                return (void *) filter_instance;
            }
        }
        else if (processor_unit->unit_type == FLB_PROCESSOR_UNIT_NATIVE) {
            processor_instance = (struct flb_processor_instance *) \
                                    processor_unit->ctx;

            if (strcmp(flb_processor_instance_get_name(processor_instance),
                        name) == 0) {
                *plugin_type = FLB_PLUGIN_PROCESSOR;

                return (void *) processor_instance;
            }
        }
    }

    return NULL;
}


static void *find_processor_instance_internal_processor_level(
                char *name,
                int  *plugin_type,
                struct flb_processor *processor)
{
    void *result;

    result = find_processor_instance_internal_unit_level(
                name,
                plugin_type,
                &processor->logs);

    if (result == NULL) {
        result = find_processor_instance_internal_unit_level(
                    name,
                    plugin_type,
                    &processor->metrics);
    }

    if (result == NULL) {
        result = find_processor_instance_internal_unit_level(
                    name,
                    plugin_type,
                    &processor->traces);
    }

    return result;
}

static void *find_processor_instance(
                char *name,
                int  *plugin_type,
                struct flb_config *config)
{
    struct flb_output_instance    *output_instance;
    struct flb_input_instance     *input_instance;
    struct mk_list                *iterator;
    void                          *result;

    mk_list_foreach(iterator, &config->inputs) {
        input_instance = mk_list_entry(iterator,
                                       struct flb_input_instance,
                                       _head);

        result = find_processor_instance_internal_processor_level(
                    name,
                    plugin_type,
                    input_instance->processor);

        if (result != NULL) {
            return result;
        }
    }

    mk_list_foreach(iterator, &config->outputs) {
        output_instance = mk_list_entry(iterator,
                                       struct flb_output_instance,
                                       _head);

        result = find_processor_instance_internal_processor_level(
                    name,
                    plugin_type,
                    output_instance->processor);

        if (result != NULL) {
            return result;
        }
    }

    return NULL;
}

int flb_notification_enqueue(int plugin_type,
                             char *instance_name,
                             struct flb_notification *notification,
                             struct flb_config *config)
{
    flb_pipefd_t                  notification_channel;
    union generic_plugin_instance plugin_instance;
    int                           result;

    plugin_instance.generic = NULL;

    if (plugin_instance.generic == NULL &&
        (plugin_type == FLB_PLUGIN_INPUT ||
         plugin_type == -1)) {
        plugin_instance.input = find_input_instance(instance_name, config);
        notification_channel = plugin_instance.input->notification_channel;
        plugin_type = FLB_PLUGIN_INPUT;
    }

    if (plugin_instance.generic == NULL &&
        (plugin_type == FLB_PLUGIN_OUTPUT ||
         plugin_type == -1)) {
        plugin_instance.output = find_output_instance(instance_name, config);
        notification_channel = plugin_instance.output->notification_channel;
        plugin_type = FLB_PLUGIN_OUTPUT;
    }

    if (plugin_instance.generic == NULL &&
        (plugin_type == FLB_PLUGIN_FILTER ||
         plugin_type == -1)) {
        plugin_instance.filter = find_filter_instance(instance_name, config);
        notification_channel = plugin_instance.filter->notification_channel;
        plugin_type = FLB_PLUGIN_FILTER;
    }

    if (plugin_instance.generic == NULL &&
        (plugin_type == FLB_PLUGIN_FILTER ||
         plugin_type == -1)) {
        plugin_instance.generic = find_processor_instance(instance_name,
                                                          &plugin_type,
                                                          config);

        if (plugin_instance.generic != NULL) {
            if (plugin_type == FLB_PLUGIN_FILTER) {
                notification_channel = plugin_instance.filter->notification_channel;
            }
            else if (plugin_type == FLB_PLUGIN_PROCESSOR) {
                notification_channel = plugin_instance.processor->notification_channel;
            }
        }
    }

    if (plugin_instance.generic == NULL) {
        flb_error("cannot enqueue notification for plugin \"%s\" with type %d",
                  instance_name, plugin_type);

        return -1;
    }

    notification->plugin_type = plugin_type;
    notification->plugin_instance = plugin_instance.generic;

    result = flb_pipe_w(notification_channel,
                        &notification,
                        sizeof(void *));

    if (result == -1) {
        flb_pipe_error();

        return -1;
    }

    return 0;
}

int flb_notification_receive(flb_pipefd_t channel,
                             struct flb_notification **notification)
{
    int result;

    result = flb_pipe_r(channel, notification, sizeof(struct flb_notification *));

    if (result <= 0) {
        flb_pipe_error();
        return -1;;
    }

    return 0;
}

int flb_notification_deliver(struct flb_notification *notification)
{
    int result;
    union generic_plugin_instance instance;

    if (notification == NULL) {
        flb_error("cannot deliver NULL notification instance");

        return -1;
    }

    instance.generic = notification->plugin_instance;
    result = -2;

    switch(notification->plugin_type) {
    case FLB_PLUGIN_INPUT:
        if (instance.input->p->cb_notification != NULL) {
            result = instance.input->p->cb_notification(
                                            instance.input->context,
                                            instance.input->config,
                                            (void *) notification);
        }
        else {
            result = -3;
        }

        break;

    case FLB_PLUGIN_OUTPUT:
        if (instance.output->p->cb_notification != NULL) {
            result = instance.output->p->cb_notification(
                                            instance.output->context,
                                            instance.output->config,
                                            (void *) notification);
        }
        else {
            result = -3;
        }

        break;

    case FLB_PLUGIN_FILTER:
        if (instance.filter->p->cb_notification != NULL) {
            result = instance.filter->p->cb_notification(
                                            instance.filter->context,
                                            instance.filter->config,
                                            (void *) notification);
        }
        else {
            result = -3;
        }

        break;

    case FLB_PLUGIN_PROCESSOR:
        if (instance.processor->p->cb_notification != NULL) {
            result = instance.processor->p->cb_notification(
                                                instance.processor->context,
                                                instance.processor->config,
                                                (void *) notification);
        }
        else {
            result = -3;
        }

        break;
    }

    return result;
}

void flb_notification_cleanup(struct flb_notification *notification)
{
    if (notification->destructor != NULL) {
        notification->destructor((void *) notification);
    }

    if (notification->dynamically_allocated == FLB_TRUE) {
        flb_free(notification);
    }
}
