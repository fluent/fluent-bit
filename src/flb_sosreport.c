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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_kv.h>

#ifndef _MSC_VER
#include <sys/utsname.h>
#endif

static void print_key(char *key)
{
    printf("    %-20s", key);
}

static void print_kv(char *key, char *val)
{
    print_key(key);
    printf("%s\n", val);
}

static char *get_str(char *p)
{
    if (p) {
        return p;
    }

    return "(not set)";
}



static char *log_level(int x)
{
    switch (x) {
    case 0: return "Off";
    case 1: return "Error";
    case 2: return "Warn";
    case 3: return "Info";
    case 4: return "Debug";
    case 5: return "Trace";
    default: return "Unknown";
    }
}

static void input_flags(int flags)
{
    if (flags & FLB_INPUT_NET) {
        printf("NET ");
    }

    if (flags & FLB_INPUT_CORO) {
        printf("CORO ");
    }

    printf("\n");
}

static void print_host(struct flb_net_host *host)
{
    if (host->address) {
        printf("    Host.Address\t%s\n", host->address);
    }
    if (host->port > 0) {
        printf("    Host.TCP_Port\t%i\n", host->port);
    }
    if (host->name) {
        printf("    Host.Name\t\t%s\n", host->name);
    }
    if (host->listen) {
        printf("    Host.Listen\t\t%s\n", host->listen);
    }
}

static void print_properties(struct mk_list *props)
{
    struct mk_list *head;
    struct flb_kv *kv;

    mk_list_foreach(head, props) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        print_kv(kv->key, kv->val);
    }
}

#ifdef _MSC_VER
/* A definition table of SYSTEM_INFO.wProcessorArchitecture.
 *
 * This is a streight-forward translation of the official manual.
 * https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/
 */
static const char* win32_arch(int archid)
{
    switch(archid)
    {
        case PROCESSOR_ARCHITECTURE_AMD64:
            return "x64 (AMD or Intel)";
        case PROCESSOR_ARCHITECTURE_ARM:
            return "ARM";
        case PROCESSOR_ARCHITECTURE_ARM64:
            return "ARM64";
        case PROCESSOR_ARCHITECTURE_IA64:
            return "Intel Itanium-based";
        case PROCESSOR_ARCHITECTURE_INTEL:
            return "x86";
        case PROCESSOR_ARCHITECTURE_UNKNOWN:
        default:
            return "unknown";
    }
}

static void win32_operating_system_info()
{
    OSVERSIONINFOA win32os;

    /* TODO Support "Application Manifest". Windows 10 reports a wrong
     * version info if we do not manifest the supported OS.
     * https://blogs.msdn.microsoft.com/chuckw/2013/09/10/manifest-madness/
     */
    win32os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    GetVersionExA(&win32os);

    printf("[Operating System]\n");
    printf("    Name\t\tWindows\n");
    printf("    Version\t\t%i.%i\n", win32os.dwMajorVersion, win32os.dwMinorVersion);
    printf("    Build\t\t%i\n", win32os.dwBuildNumber);
    printf("\n");
}

static void win32_hardware_info()
{
    SYSTEM_INFO win32info;

    GetNativeSystemInfo(&win32info);
    printf("[Hardware]\n");
    printf("    Architecture\t%s\n", win32_arch(win32info.wProcessorArchitecture));
    printf("    Processors\t\t%i\n", win32info.dwNumberOfProcessors);
    printf("\n");
}
#endif

int flb_sosreport(struct flb_config *config)
{
    char tmp[32];
    struct mk_list *head;
    struct cfl_list *head_r;
    struct flb_input_plugin *in;
    struct flb_filter_plugin *filter;
    struct flb_output_plugin *out;
    struct flb_input_instance *ins_in;
    struct flb_filter_instance *ins_filter;
    struct flb_output_instance *ins_out;
    struct flb_router_path *route;

    printf("\n");
    printf("Fluent Bit Enterprise - SOS Report\n");
    printf("==================================\n");
    printf("The following report aims to be used by Fluent Bit and Fluentd "
           "community users.\n\n");

    /* Fluent Bit */
    printf("\n[Fluent Bit]\n");
    printf("    Version\t\t%s\n", FLB_VERSION_STR);
    printf("    Built Flags\t\t%s\n", FLB_INFO_FLAGS);
    printf("\n");

#ifndef _MSC_VER
    struct utsname uts;
    uname(&uts);

    /* Operating System */
    printf("[Operating System]\n");
    printf("    Name\t\t%s\n", uts.sysname);
    printf("    Release\t\t%s\n", uts.release);
    printf("    Version\t\t%s\n", uts.version);
    printf("\n");

    /* Basic hardware info */
    printf("[Hardware]\n");
    printf("    Architecture\t%s\n", uts.machine);
    printf("    Processors\t\t%i\n",  (int) sysconf(_SC_NPROCESSORS_ONLN));
    printf("\n");
#else
    win32_operating_system_info();
    win32_hardware_info();
#endif

    /* Fluent Bit */
    printf("[Built Plugins]\n");
    print_key("Inputs");
    mk_list_foreach(head, &config->in_plugins) {
        in = mk_list_entry(head, struct flb_input_plugin, _head);
        printf("%s ", in->name);
    }
    printf("\n");

    print_key("Filters");
    mk_list_foreach(head, &config->filter_plugins) {
        filter = mk_list_entry(head, struct flb_filter_plugin, _head);
        printf("%s ", filter->name);
    }
    printf("\n");

    print_key("Outputs");
    mk_list_foreach(head, &config->out_plugins) {
        out = mk_list_entry(head, struct flb_output_plugin, _head);
        printf("%s ", out->name);
    }
    printf("\n");

    /* Runtime configuration, what do the Engine have before to start */
    printf("\n");

    /* Config: [SERVER] */
    printf("[SERVER] Runtime configuration\n");
    printf("    Flush\t\t%f\n", config->flush);
    printf("    Daemon\t\t%s\n", config->daemon ? "On": "Off");
    printf("    Log_Level\t\t%s\n", log_level(config->verbose));
    printf("\n");

    /* Config: [INPUT] */
    mk_list_foreach(head, &config->inputs) {
        ins_in = mk_list_entry(head, struct flb_input_instance, _head);
        printf("[INPUT] Instance\n");
        printf("    Name\t\t%s (%s, id=%i)\n", ins_in->name, ins_in->p->name,
               ins_in->id);
        printf("    Flags\t\t"); input_flags(ins_in->flags);
        printf("    Coroutines\t\t%s\n", ins_in->runs_in_coroutine ? "Yes": "No");
        if (ins_in->tag) {
            printf("    Tag\t\t\t%s\n", ins_in->tag);
        }
        if (ins_in->flags & FLB_INPUT_NET) {
            print_host(&ins_in->host);
        }

        if (ins_in->mem_buf_limit > 0) {
            flb_utils_bytes_to_human_readable_size(ins_in->mem_buf_limit,
                                                   tmp, sizeof(tmp) - 1);
            printf("    Mem_Buf_Limit\t%s\n", tmp);
        }

        print_properties(&ins_in->properties);

        /* Fixed Routes */
        if (!cfl_list_is_empty(&ins_in->routes)) {
            printf("    Routes\t\t");
            cfl_list_foreach(head_r, &ins_in->routes) {
                route = cfl_list_entry(head_r, struct flb_router_path, _head);
                printf("%s ", route->ins->name);
            }
            printf("\n");
        }
        printf("\n");
    }

    /* Config: [FILTER] */
    mk_list_foreach(head, &config->filters) {
        ins_filter = mk_list_entry(head, struct flb_filter_instance, _head);
        printf("[FILTER] Instance\n");
        printf("    Name\t\t%s (%s, id=%i)\n", ins_filter->name, ins_filter->p->name,
               ins_filter->id);
        printf("    Match\t\t%s\n", ins_filter->match);
        print_properties(&ins_filter->properties);
    }
    printf("\n");

    /* Config: [OUTPUT] */
    mk_list_foreach(head, &config->outputs) {
        ins_out = mk_list_entry(head, struct flb_output_instance, _head);
        printf("[OUTPUT] Instance\n");
        printf("    Name\t\t%s (%s, id=%" PRIu64 ")\n", ins_out->name, ins_out->p->name,
               (uint64_t) ins_out->id);
        printf("    Match\t\t%s\n", ins_out->match);

#ifdef FLB_HAVE_TLS
        printf("    TLS Active\t\t%s\n", ins_out->use_tls ? "Yes" : "No");
        if (ins_out->use_tls == FLB_TRUE) {
            printf("    TLS.Verify\t\t%s\n", ins_out->tls_verify ? "On": "Off");
            printf("    TLS.Ca_File\t\t%s\n", get_str(ins_out->tls_ca_file));
            printf("    TLS.Crt_File\t%s\n", get_str(ins_out->tls_crt_file));
            printf("    TLS.Key_File\t%s\n", get_str(ins_out->tls_key_file));
            printf("    TLS.Key_Passwd\t%s\n",
                   ins_out->tls_key_passwd ? "*****" : "(not set)");
        }
#endif
        if (ins_out->retry_limit == FLB_OUT_RETRY_UNLIMITED) {
            printf("    Retry Limit\t\tno limit\n");
        }
        else {
            printf("    Retry Limit\t\t%i\n", ins_out->retry_limit);
        }
        print_host(&ins_out->host);
        print_properties(&ins_out->properties);
        printf("\n");
    }

    return 0;
}
