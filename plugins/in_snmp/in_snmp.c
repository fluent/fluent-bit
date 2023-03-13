#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_error.h>
#include "in_snmp.h"

#define PLUGIN_NAME "snmp"

int snmp_plugin_under_test()
{
    if (getenv("FLB_SNMP_PLUGIN_UNDER_TEST") != NULL) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

int mock_snmp_synch_response(netsnmp_session *ss, netsnmp_pdu *pdu, netsnmp_pdu **response)
{
    char *mock_status = NULL;
    netsnmp_pdu *mock_response = NULL;
    netsnmp_variable_list *mock_netsnmp_variable_list = NULL;
    oid mock_objid[MAX_OID_LEN];
    size_t mock_objid_len;

    mock_status = getenv("TEST_SNMP_RESPONSE");

    if (strcmp(mock_status, "normal") == 0) {
        // if ((mock_response = flb_calloc(1, sizeof(netsnmp_pdu))) == NULL) {
        //     flb_errno();
        //     flb_free(mock_status);
        //     return NULL;
        // }

        // if ((mock_netsnmp_variable_list = flb_calloc(1, sizeof(netsnmp_variable_list))) == NULL) {
        //     flb_errno();
        //     flb_free(mock_response);
        //     flb_free(mock_status);
        //     return NULL;
        // }

        // // sysUpTime
        // mock_objid_len = MAX_OID_LEN;
        // if (snmp_parse_oid("1.3.6.1.2.1.1.3.0", mock_objid, &mock_objid_len) == NULL) {
        //     flb_errno();
        //     flb_free(mock_netsnmp_variable_list);
        //     flb_free(mock_response);
        //     flb_free(mock_status);
        //     return NULL;
        // }

        // mock_netsnmp_variable_list->next_variable = NULL;
        // mock_netsnmp_variable_list->name = NULL;
        // mock_netsnmp_variable_list->val.string = NULL;
        // mock_netsnmp_variable_list->val_len = 0;
        // mock_netsnmp_variable_list->data = NULL;
        // mock_netsnmp_variable_list->dataFreeHook = NULL;
        // mock_netsnmp_variable_list->index = 0;

        // if (snmp_set_var_objid(mock_netsnmp_variable_list, mock_objid, mock_objid_len)) {
        //     flb_errno();
        //     flb_free(mock_netsnmp_variable_list);
        //     flb_free(mock_response);
        //     flb_free(mock_status);
        //     return NULL;
        // }

        // if (snmp_set_var_typed_integer(mock_netsnmp_variable_list, ASN_TIMETICKS, 123)) {
        //     flb_errno();
        //     flb_free(mock_netsnmp_variable_list);
        //     flb_free(mock_response);
        //     flb_free(mock_status);
        //     return NULL;
        // }

        // mock_response->variables = mock_netsnmp_variable_list;
        // mock_response->errstat == SNMP_ERR_NOERROR;
        // *response = mock_response;

        // flb_free(mock_status);

        return STAT_SUCCESS;
    }
}

static int in_snmp_collect(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    int ret = 0;
    struct flb_snmp *ctx = in_context;

    netsnmp_session session, *ss;
    netsnmp_pdu *pdu;
    netsnmp_pdu *response;

    oid anOID[MAX_OID_LEN], name[MAX_OID_LEN], end_oid[MAX_OID_LEN];
    size_t anOID_len, name_len, end_len;

    netsnmp_variable_list *vars;
    int status;

    u_char *buf = NULL, *oid_buf = NULL;
    size_t buf_len = 256, oid_buf_len = 256, out_len = 0, oid_out_len = 0;
    int running = 1;
    int buf_overflow = 0;
    bool is_walk = false;

    char *err;

    init_snmp(PLUGIN_NAME);
    snmp_sess_init(&session);

    session.peername = strdup(ctx->target_host);

    if (strcmp(ctx->version, "1") == 0) {
        session.version = SNMP_VERSION_1;
    } else if (strcmp(ctx->version, "2c") == 0) {
        session.version = SNMP_VERSION_2c;
    } else {
        flb_plg_error(ctx->ins, "Unsupported SNMP version : %s", ctx->version);
        return -1;
    }

    if (strcmp(ctx->oid_type, "get") == 0) {
        is_walk = false;
    } else if (strcmp(ctx->oid_type, "walk") == 0) {
        is_walk = true;
    } else {
        flb_plg_error(ctx->ins, "Unsupported oid_type : %s", ctx->oid_type);
        return -1;
    }

    session.community = (u_char *) strdup(ctx->community);
    session.community_len = strlen(ctx->community);

    SOCK_STARTUP;
    ss = snmp_open(&session);
    if (!ss) {
        snmp_error(ss, NULL, NULL, &err);
        flb_plg_error(ctx->ins, "%s", err);
        SOCK_CLEANUP;
        return -1;
    }

    anOID_len = MAX_OID_LEN;
    if (snmp_parse_oid(strdup(ctx->oid), anOID, &anOID_len) == NULL) {
        flb_plg_error(ctx->ins, "Fail to parse oid");
        SOCK_CLEANUP;
        return -1;
    }

    if (is_walk) {
        memmove(end_oid, anOID, anOID_len*sizeof(oid));
        end_len = anOID_len;
        end_oid[end_len-1]++;
    }

    memmove(name, anOID, anOID_len*sizeof(oid));
    name_len = anOID_len;

    ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);
                        
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(
                &ctx->log_encoder);
    }

    while (running) {
        if (is_walk) {
            pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
        } else {
            pdu = snmp_pdu_create(SNMP_MSG_GET);
        }

        snmp_add_null_var(pdu, name, name_len);

        if (snmp_plugin_under_test() == FLB_TRUE) {
            flb_plg_error(ctx->ins, "Ha Ha");

            status = mock_snmp_synch_response(ss, pdu, &response);
        } else {
            status = snmp_synch_response(ss, pdu, &response);
        }

        if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
                        
            for(vars = response->variables; vars; vars = vars->next_variable) {
                if (is_walk && snmp_oid_compare(end_oid, end_len,
                        vars->name, vars->name_length) <= 0) {
                    // not part of this subtree
                    running = 0;
                    continue;
                }
                
                oid_out_len = 0;
                out_len = 0;

                if ((oid_buf = flb_calloc(oid_buf_len, 1)) == NULL) {
                    flb_plg_error(ctx->ins, "[TRUNCATED]");
                    return -1;
                } else {
                    netsnmp_sprint_realloc_objid_tree(&oid_buf, &oid_buf_len, &oid_out_len,
                                          1, &buf_overflow,
                                          vars->name, vars->name_length);                    
                    if (buf_overflow) {
                        flb_plg_error(ctx->ins, "[TRUNCATED]");
                        return -1;
                    }
                }

                if ((buf = flb_calloc(buf_len, 1)) == NULL) {
                    flb_plg_error(ctx->ins, "[TRUNCATED]");
                    return -1;
                } else {
                    if (sprint_realloc_by_type(&buf, &buf_len, &out_len,
                                            1, vars, NULL, NULL,
                                            NULL)) {
                        // append values
                        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                            ret = flb_log_event_encoder_append_body_values(
                                    &ctx->log_encoder,
                                    FLB_LOG_EVENT_CSTRING_VALUE((char *) oid_buf),
                                    FLB_LOG_EVENT_CSTRING_VALUE((char *) buf));
                        }
                    } else {
                        flb_plg_error(ctx->ins, "[TRUNCATED]");
                        return -1;
                    }
                }

                if ((vars->type != SNMP_ENDOFMIBVIEW) &&
                        (vars->type != SNMP_NOSUCHOBJECT) &&
                        (vars->type != SNMP_NOSUCHINSTANCE)) {
                    if (snmp_oid_compare(name, name_len,
                                            vars->name,
                                            vars->name_length) >= 0 && is_walk) {
                        flb_plg_error(ctx->ins, "Error: OID not increasing");
                        running = 0;
                    }
                    memmove(name, vars->name,
                            vars->name_length * sizeof(oid));
                    name_len = vars->name_length;
                } else {
                    flb_plg_error(ctx->ins, "an exception value");
                    running = 0;
                }
            }
        } else {
            if (status == STAT_SUCCESS) {
                flb_plg_error(ctx->ins, "Error in packet. Reason: %s", snmp_errstring(response->errstat));
                running = 0;
            } else if (status == STAT_TIMEOUT) {
                flb_plg_error(ctx->ins, "Timeout: No response from %s", session.peername);
                running = 0;
            } else {
                snmp_error(ss, NULL, NULL, &err);
                flb_plg_error(ctx->ins, "%s", err);
                running = 0;
            }
        }
        if (response) {
            snmp_free_pdu(response);
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(ins, NULL, 0,
                            ctx->log_encoder.output_buffer,
                            ctx->log_encoder.output_length);

        ret = 0;
    } else {
        flb_plg_error(ctx->ins, "Error encoding record : %d", ret);
        ret = -1;
    }
    
    flb_log_event_encoder_reset(&ctx->log_encoder);

    snmp_close(ss);

    flb_free(buf);
    flb_free(oid_buf);

    SOCK_CLEANUP;

    return ret;
}

/* Initialize plugin */
static int in_snmp_init(struct flb_input_instance *in,
                         struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_snmp *ctx = NULL;
    struct timespec tm;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_snmp));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;

    ret = flb_input_config_map_set(in, (void *)ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    // Set plugin context
    flb_input_set_context(in, ctx);

    /* interval settings */
    tm.tv_sec  = 1;
    tm.tv_nsec = 0;

    ret = flb_input_set_collector_time(in,
                                       in_snmp_collect,
                                       tm.tv_sec,
                                       tm.tv_nsec, config);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "could not set collector for snmp input plugin");
        return -1;
    }

    ctx->coll_fd = ret;

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "error initializing event encoder : %d", ret);

        /* done */
        flb_free(ctx);

        return -1;
    }

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NUMERIC_TIMETICKS, 1);
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);

    return 0;
}

static void in_snmp_pause(void *data, struct flb_config *config)
{
    struct flb_snmp *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_snmp_resume(void *data, struct flb_config *config)
{
    struct flb_snmp *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int in_snmp_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_snmp *ctx = data;

    flb_log_event_encoder_destroy(&ctx->log_encoder);

    flb_free(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
   {
    FLB_CONFIG_MAP_STR, "target_host", "127.0.0.1",
    0, FLB_TRUE, offsetof(struct flb_snmp, target_host),
    "set the target host IP to collect metrics through SNMP."
   },
   {
    FLB_CONFIG_MAP_INT, "port", "161",
    0, FLB_TRUE, offsetof(struct flb_snmp, port),
    "set the host port to collect metrics through SNMP."
   },
   {
    FLB_CONFIG_MAP_INT, "timeout", "5",
    0, FLB_TRUE, offsetof(struct flb_snmp, timeout),
    "set the timeout to when doing a SNMP request."
   },
   {
    FLB_CONFIG_MAP_STR, "version", "2c",
    0, FLB_TRUE, offsetof(struct flb_snmp, version),
    "set the version of the SNMP request."
   },
   {
    FLB_CONFIG_MAP_STR, "community", "public",
    0, FLB_TRUE, offsetof(struct flb_snmp, community),
    "set the community of the SNMP request."
   },
   {
    FLB_CONFIG_MAP_INT, "retries", "3",
    0, FLB_TRUE, offsetof(struct flb_snmp, retries),
    "set the retry times to do SNMP request when fail."
   },
   {
    FLB_CONFIG_MAP_STR, "oid_type", "get",
    0, FLB_TRUE, offsetof(struct flb_snmp, oid_type),
    "set the type of the SNMP request. Use a 'field' to collect a variable by OID."
   },
   {
    FLB_CONFIG_MAP_STR, "oid", "1.3.6.1.2.1.1.3.0",
    0, FLB_TRUE, offsetof(struct flb_snmp, oid),
    "set the OID of the SNMP request."
   },
   {
    FLB_CONFIG_MAP_STR, "name", "",
    0, FLB_TRUE, offsetof(struct flb_snmp, name),
    "set the name for the variable from SNMP request."
   },
   {0}
};

struct flb_input_plugin in_snmp_plugin = {
    .name         = "snmp",
    .description  = "Collect metrics through SNMP",
    .cb_init      = in_snmp_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_snmp_collect,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_pause     = in_snmp_pause,
    .cb_resume    = in_snmp_resume,
    .cb_exit      = in_snmp_exit
};
