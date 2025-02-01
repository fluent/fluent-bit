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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_plugin_proxy.h>

#include <cfl/cfl_sds.h>
#include <cfl/cfl_variant.h>
#include <cfl/cfl_kvlist.h>

#include <sys/types.h>
#include <sys/stat.h>

#define PLUGIN_PREFIX           "flb-"
#define PLUGIN_EXTENSION        ".so"
#define PLUGIN_STRUCT_SUFFIX    "_plugin"
#define PLUGIN_STR_MIN                                              \
    ((sizeof(PLUGIN_PREFIX) - 1) + sizeof(PLUGIN_EXTENSION) - 1)

static int is_input(char *name)
{
    if (strncmp(name, "in_", 3) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int is_filter(char *name)
{
    if (strncmp(name, "filter_", 7) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int is_processor(char *name)
{
    if (strncmp(name, "processor_", 10) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int is_output(char *name)
{
    if (strncmp(name, "out_", 4) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static void *get_handle(const char *path)
{
    void *handle;

    handle = dlopen(path, RTLD_LAZY);
    if (!handle) {
        flb_error("[plugin] dlopen() %s", dlerror());
        return NULL;
    }

    return handle;
}

static void *load_symbol(void *dso_handle, const char *symbol)
{
    void *s;

    dlerror();
    s = dlsym(dso_handle, symbol);
    if (dlerror() != NULL) {
        return NULL;
    }
    return s;
}

/*
 * From a given path file (.so file), retrieve the expected structure name
 * used to perform the plugin registration.
 */
static char *path_to_plugin_name(char *path)
{
    int len;
    int o_len;
    char *bname;
    char *name;
    char *p;

    /* Get the basename of the file */
    bname = basename(path);
    if (!bname) {
        flb_error("[plugin] could not resolve basename(3) of the plugin");
        return NULL;
    }
    len = strlen(bname);

    if (len < PLUGIN_STR_MIN) {
        flb_error("[plugin] invalid plugin name: %s", bname);
        return NULL;
    }

    if (strncmp(bname, PLUGIN_PREFIX, sizeof(PLUGIN_PREFIX) - 1) != 0) {
        flb_error("[plugin] invalid plugin prefix: %s", bname);
        return NULL;
    }

    if (strncmp(bname + len - (sizeof(PLUGIN_EXTENSION) - 1),
                PLUGIN_EXTENSION, sizeof(PLUGIN_EXTENSION) - 1) != 0) {
        flb_error("[plugin] invalid plugin extension: %s", bname);
        return NULL;
    }

    /* Get the expected structure name */
    name = flb_malloc(len + (sizeof(PLUGIN_STRUCT_SUFFIX) - 1) + 1);
    if (!name) {
        flb_errno();
        return NULL;
    }

    /* Name without prefix */
    p = bname + (sizeof(PLUGIN_PREFIX) - 1);
    o_len = len - (sizeof(PLUGIN_PREFIX) - 1) - (sizeof(PLUGIN_EXTENSION) - 1);
    memcpy(name, p, o_len);
    name[o_len] = '\0';

    /* Validate expected plugin type */
    if (is_input(name) == FLB_FALSE &&
        is_processor(name) == FLB_FALSE &&
        is_filter(name) == FLB_FALSE &&
        is_output(name) == FLB_FALSE) {
        flb_error("[plugin] invalid plugin type: %s", name);
        flb_free(name);
        return NULL;
    }

    /* Append struct suffix */
    p = name + o_len;
    memcpy(p, PLUGIN_STRUCT_SUFFIX, sizeof(PLUGIN_STRUCT_SUFFIX) - 1);
    o_len += sizeof(PLUGIN_STRUCT_SUFFIX) - 1;
    name[o_len] = '\0';

    return name;
}

static void destroy_plugin(struct flb_plugin *plugin)
{
    flb_sds_destroy(plugin->path);
    dlclose(plugin->dso_handle);
    mk_list_del(&plugin->_head);
    flb_free(plugin);
}

/* Creates the global plugin context for 'dynamic plugins' */
struct flb_plugins *flb_plugin_create()
{
    struct flb_plugins *ctx;

    ctx = flb_malloc(sizeof(struct flb_plugins));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    mk_list_init(&ctx->input);
    mk_list_init(&ctx->processor);
    mk_list_init(&ctx->filter);
    mk_list_init(&ctx->output);

    return ctx;
}

int flb_plugin_load(char *path, struct flb_plugins *ctx,
                    struct flb_config *config)
{
    int type = -1;
    void *dso_handle;
    void *symbol = NULL;
    char *plugin_stname;
    struct flb_plugin *plugin;
    struct flb_input_plugin *input;
    struct flb_processor_plugin *processor;
    struct flb_filter_plugin *filter;
    struct flb_output_plugin *output;

    /* Open the shared object file: dlopen(3) */
    dso_handle = get_handle(path);
    if (!dso_handle) {
        return -1;
    }

    /*
     * Based on the shared object file name, compose the expected
     * registration structure name.
     */
    plugin_stname = path_to_plugin_name(path);
    if (!plugin_stname) {
        dlclose(dso_handle);
        return -1;
    }

    /* Get the registration structure */
    symbol = load_symbol(dso_handle, plugin_stname);
    if (!symbol) {
        flb_error("[plugin] cannot load plugin '%s', "
                  "registration structure is missing '%s'",
                  path, plugin_stname);
        flb_free(plugin_stname);
        dlclose(dso_handle);
        return -1;
    }

    /* Detect plugin type and link it to the main context */
    if (is_input(plugin_stname) == FLB_TRUE) {
        type = FLB_PLUGIN_INPUT;
        input = flb_malloc(sizeof(struct flb_input_plugin));
        if (!input) {
            flb_errno();
            flb_free(plugin_stname);
            dlclose(dso_handle);
            return -1;
        }
        memcpy(input, symbol, sizeof(struct flb_input_plugin));
        mk_list_add(&input->_head, &config->in_plugins);
    }
    else if (is_processor(plugin_stname) == FLB_TRUE) {
        type = FLB_PLUGIN_PROCESSOR;
        processor = flb_malloc(sizeof(struct flb_processor_plugin));
        if (processor == NULL) {
            flb_errno();
            flb_free(plugin_stname);
            dlclose(dso_handle);
            return -1;
        }
        memcpy(processor, symbol, sizeof(struct flb_processor_plugin));
        mk_list_add(&processor->_head, &config->processor_plugins);
    }
    else if (is_filter(plugin_stname) == FLB_TRUE) {
        type = FLB_PLUGIN_FILTER;
        filter = flb_malloc(sizeof(struct flb_filter_plugin));
        if (!filter) {
            flb_errno();
            flb_free(plugin_stname);
            dlclose(dso_handle);
            return -1;
        }
        memcpy(filter, symbol, sizeof(struct flb_filter_plugin));
        mk_list_add(&filter->_head, &config->filter_plugins);
    }
    else if (is_output(plugin_stname) == FLB_TRUE) {
        type = FLB_PLUGIN_OUTPUT;
        output = flb_malloc(sizeof(struct flb_output_plugin));
        if (!output) {
            flb_errno();
            flb_free(plugin_stname);
            dlclose(dso_handle);
            return -1;
        }
        memcpy(output, symbol, sizeof(struct flb_output_plugin));
        mk_list_add(&output->_head, &config->out_plugins);
    }
    flb_free(plugin_stname);

    if (type == -1) {
        flb_error("[plugin] plugin type not defined on '%s'", path);
        dlclose(dso_handle);
        return -1;
    }

    /* Create plugin context (internal reference only) */
    plugin = flb_malloc(sizeof(struct flb_plugin));
    if (!plugin) {
        flb_errno();
        dlclose(dso_handle);
        return -1;
    }

    plugin->type = type;
    plugin->path = flb_sds_create(path);
    plugin->dso_handle = dso_handle;

    /* Link by type to the plugins parent context */
    if (type == FLB_PLUGIN_INPUT) {
        mk_list_add(&plugin->_head, &ctx->input);
    }
    else if (type == FLB_PLUGIN_PROCESSOR) {
        mk_list_add(&plugin->_head, &ctx->processor);
    }
    else if (type == FLB_PLUGIN_FILTER) {
        mk_list_add(&plugin->_head, &ctx->filter);
    }
    else if (type == FLB_PLUGIN_OUTPUT) {
        mk_list_add(&plugin->_head, &ctx->output);
    }

    return 0;
}

int flb_plugin_load_router(char *path, struct flb_config *config)
{
    int ret = -1;
    char *bname;

    bname = basename(path);

    /* Is this a DSO C plugin ? */
    if (strncmp(bname, PLUGIN_PREFIX, sizeof(PLUGIN_PREFIX) - 1) == 0) {
        ret = flb_plugin_load(path, config->dso_plugins, config);
        if (ret == -1) {
            flb_error("[plugin] error loading DSO C plugin: %s", path);
            return -1;
        }
    }
    else {
#ifdef FLB_HAVE_PROXY_GO
        if (flb_plugin_proxy_create(path, 0, config) == NULL) {
            flb_error("[plugin] error loading proxy plugin: %s", path);
            return -1;
        }
#else
        flb_error("[plugin] unsupported plugin type at: %s", path);
        return -1;
#endif
    }

    return 0;
}

int flb_plugin_load_config_format(struct flb_cf *cf, struct flb_config *config)
{
    int ret;
    struct mk_list *head;
    struct cfl_list *head_e;
    struct flb_cf_section *section;
    struct cfl_kvpair *entry;

    /* read all 'plugins' sections */
    mk_list_foreach(head, &cf->plugins) {
        section = mk_list_entry(head, struct flb_cf_section, _head_section);

        cfl_list_foreach(head_e, &section->properties->list) {
            entry = cfl_list_entry(head_e, struct cfl_kvpair, _head);

            /* Load plugin with router function */
            ret = flb_plugin_load_router(entry->key, config);
            if (ret == -1) {
                flb_cf_destroy(cf);
                return -1;
            }
        }
    }

    return 0;
}

/* Load plugins from a configuration file */
int flb_plugin_load_config_file(const char *file, struct flb_config *config)
{
    int ret;
    char tmp[PATH_MAX + 1];
    char *cfg = NULL;
    struct mk_list *head;
    struct cfl_list *head_e;
    struct stat st;
    struct flb_cf *cf;
    struct flb_cf_section *section;
    struct cfl_kvpair *entry;

#ifndef FLB_HAVE_STATIC_CONF
    ret = stat(file, &st);
    if (ret == -1 && errno == ENOENT) {
        /* Try to resolve the real path (if exists) */
        if (file[0] == '/') {
            flb_utils_error(FLB_ERR_CFG_PLUGIN_FILE);
            return -1;
        }

        if (config->conf_path) {
            snprintf(tmp, PATH_MAX, "%s%s", config->conf_path, file);
            cfg = tmp;
        }
    }
    else {
        cfg = (char *) file;
    }

    flb_debug("[plugin] opening configuration file %s", cfg);

    cf = flb_cf_create_from_file(NULL, cfg);
#else
    cf = flb_config_static_open(file);
#endif

    if (!cf) {
        return -1;
    }

    if (cf->format == FLB_CF_FLUENTBIT) {
        /* (classic mode) read all 'plugins' sections */
        mk_list_foreach(head, &cf->sections) {
            section = mk_list_entry(head, struct flb_cf_section, _head);
            if (strcasecmp(section->name, "plugins") != 0) {
                continue;
            }

            cfl_list_foreach(head_e, &section->properties->list) {
                entry = cfl_list_entry(head_e, struct cfl_kvpair, _head);
                if (strcasecmp(entry->key, "path") != 0) {
                    continue;
                }

                /* Load plugin with router function */
                ret = flb_plugin_load_router(entry->val->data.as_string, config);
                if (ret == -1) {
                    flb_cf_destroy(cf);
                    return -1;
                }
            }
        }
    }
#ifdef FLB_HAVE_LIBYAML
    else if (cf->format == FLB_CF_YAML) {
        /*
         * pass to the config_format loader also in case some Yaml have been included in
         * the service section through the option 'plugins_file'
         */
        ret = flb_plugin_load_config_format(cf, config);
        if (ret == -1) {
            return -1;
        }
    }
#endif

    flb_cf_destroy(cf);
    return 0;
}

/* Destroy plugin context */
void flb_plugin_destroy(struct flb_plugins *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_plugin *plugin;

    mk_list_foreach_safe(head, tmp, &ctx->input) {
        plugin = mk_list_entry(head, struct flb_plugin, _head);
        destroy_plugin(plugin);
    }

    mk_list_foreach_safe(head, tmp, &ctx->processor) {
        plugin = mk_list_entry(head, struct flb_plugin, _head);
        destroy_plugin(plugin);
    }

    mk_list_foreach_safe(head, tmp, &ctx->filter) {
        plugin = mk_list_entry(head, struct flb_plugin, _head);
        destroy_plugin(plugin);
    }

    mk_list_foreach_safe(head, tmp, &ctx->output) {
        plugin = mk_list_entry(head, struct flb_plugin, _head);
        destroy_plugin(plugin);
    }

    flb_free(ctx);
}
