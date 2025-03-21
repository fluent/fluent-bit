#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_kv.h>
#include "flb_fuzz_header.h"

/* A sample of configurations */
char conf_file[] = "# Parser: no_year\n"
"# ===============\n"
"# the given format don't contain the Year, this is a common\n"
"# case on old Syslog implementations.\n"
"#\n"
"[PARSER]\n"
"    Name        no_year\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %b %d %H:%M:%S\n"
"    Time_Keep   On\n"
"\n"
"# Parser: no_year_N\n"
"# =================\n"
"# Just for compatibility, check a string with no year but including Nanoseconds.\n"
"#\n"
"[PARSER]\n"
"    Name        no_year_N\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %b %d %H:%M:%S.%L\n"
"    Time_Keep   On\n"
"\n"
"# Parser: no_year_NC\n"
"# =================\n"
"# Just for compatibility, check a string with no year but including Nanoseconds with comma as fractional separator.\n"
"#\n"
"[PARSER]\n"
"    Name        no_year_NC\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %b %d %H:%M:%S,%L\n"
"    Time_Keep   On\n"
"\n"
"# Parser: no_year_TZ\n"
"# =================\n"
"# Time string with no year and including timezone\n"
"#\n"
"[PARSER]\n"
"    Name        no_year_TZ\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %b %d %H:%M:%S %z\n"
"    Time_Keep   On\n"
"\n"
"# Parser: no_year_N_TZ\n"
"# ====================\n"
"# Time string with no year, nanoseconds and timezone\n"
"#\n"
"[PARSER]\n"
"    Name        no_year_N_TZ\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %b %d %H:%M:%S.%L %z\n"
"    Time_Keep   On\n"
"\n"
"\n"
"# Parser: no_year_NC_TZ\n"
"# ====================\n"
"# Time string with no year, nanoseconds and timezone with comma as fractional separator.\n"
"#\n"
"[PARSER]\n"
"    Name        no_year_NC_TZ\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %b %d %H:%M:%S,%L %z\n"
"    Time_Keep   On\n"
"\n"
"\n"
"# Parser: default_UTC\n"
"# ===================\n"
"# Time string with timezone in UTC\n"
"#\n"
"[PARSER]\n"
"    Name        default_UTC\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %m/%d/%Y %H:%M:%S\n"
"    Time_Keep   On\n"
"\n"
"# Parser: default_UTC_Z\n"
"# =====================\n"
"# Time string with timezone in UTC and ending Z\n"
"#\n"
"[PARSER]\n"
"    Name        default_UTC_Z\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %m/%d/%Y %H:%M:%SZ\n"
"    Time_Keep   On\n"
"\n"
"# Parser: default_UTC_N_Z\n"
"# =======================\n"
"# Time string with timezone in UTC, nanoseconds and ending Z\n"
"#\n"
"[PARSER]\n"
"    Name        default_UTC_N_Z\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %m/%d/%Y %H:%M:%S.%LZ\n"
"    Time_Keep   On\n"
"\n"
"# Parser: default_UTC_NC_Z\n"
"# =======================\n"
"# Time string with timezone in UTC, nanoseconds with comma as fractional separator and ending Z\n"
"#\n"
"[PARSER]\n"
"    Name        default_UTC_NC_Z\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %m/%d/%Y %H:%M:%S,%LZ\n"
"    Time_Keep   On\n"
"\n"
"# Parser: generic_TZ\n"
"# ==================\n"
"# Generic date with timezone\n"
"#\n"
"[PARSER]\n"
"    Name        generic_TZ\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %m/%d/%Y %H:%M:%S %z\n"
"    Time_Keep   On\n"
"\n"
"# Parser: generic\n"
"# ===============\n"
"# Generic date\n"
"#\n"
"[PARSER]\n"
"    Name        generic\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %m/%d/%Y %H:%M:%S\n"
"    Time_Keep   On\n"
"\n"
"# Parser: generic_N\n"
"# ===============\n"
"# Generic date with nanoseconds\n"
"#\n"
"[PARSER]\n"
"    Name        generic_N\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %m/%d/%Y %H:%M:%S.%L\n"
"    Time_Keep   On\n"
"\n"
"# Parser: generic_NC\n"
"# ===============\n"
"# Generic date with nanoseconds with comma as fractional separator\n"
"#\n"
"[PARSER]\n"
"    Name        generic_NC\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %m/%d/%Y %H:%M:%S,%L\n"
"    Time_Keep   On\n"
"\n"
"# Parser: generic_N_TZ\n"
"# ====================\n"
"# Generic date with nanoseconds and timezone\n"
"#\n"
"[PARSER]\n"
"    Name        generic_N_TZ\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %m/%d/%Y %H:%M:%S.%L %z\n"
"    Time_Keep   On\n"
"\n"
"# Parser: generic_NC_TZ\n"
"# ====================\n"
"# Generic date with nanoseconds with comma as fractional separator and timezone\n"
"#\n"
"[PARSER]\n"
"    Name        generic_NC_TZ\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %m/%d/%Y %H:%M:%S,%L %z\n"
"    Time_Keep   On\n"
"\n"
"# Parser: apache_error\n"
"# ====================\n"
"# Apache error log time format\n"
"#\n"
"[PARSER]\n"
"    Name        apache_error\n"
"    Format      json\n"
"    Time_Key    time\n"
"    Time_Format %a %b %d %H:%M:%S.%L %Y\n"
"    Time_Keep   On\n"
"# Parser: mysql_quoted_stuff\n"
"# ====================\n"
"# Apache error log time format\n"
"#\n"
"[PARSER]\n"
"    Name        mysql_quoted_stuff\n"
"    Format      regex\n"
"    Regex       ^(?<time>.*?),(?<key001>.*)$\n"
"    Time_Key    time\n"
"    Time_Format %Y-%M-%S %H:%M:%S\n"
"    Time_Keep   On\n"
"    Decode_Field_As   mysql_quoted key001\n"
"# Parser: REGEX_generic_NC_TZ\n"
"# ====================\n"
"# Generic date with nanoseconds with comma as fractional separator and timezone\n"
"#\n"
"[PARSER]\n"
"    Name        REGEX_generic_NC_TZ\n"
"    Format      regex\n"
"    Regex       ^(?<key001>[^ ]*) (?<key002>[^ ]*) (?<time>.+)$\n"
"    Time_Key    time\n"
"    Time_Format %m/%d/%Y %H:%M:%S,%L %z\n"
"    Time_Keep   On\n"
"\n"
"# Parser: REGEX_apache_error\n"
"# ====================\n"
"# Apache error log time format\n"
"#\n"
"[PARSER]\n"
"    Name        REGEX_apache_error\n"
"    Format      regex\n"
"    Regex       ^(?<key001>[^ ]*) (?<key002>[^ ]*) (?<time>.+)$\n"
"    Time_Key    time\n"
"    Time_Format %a %b %d %H:%M:%S.%L %Y\n"
"    Time_Keep   On\n"
"\n"
"\n"
"\n"
"# Parser: REGEX_mysql_quoted_stuff\n"
"# ====================\n"
"# Apache error log time format\n"
"#\n"
"[PARSER]\n"
"    Name        REGEX_mysql_quoted_stuff\n"
"    Format      regex\n"
"    Regex       ^(?<time>.*?),(?<key001>.*)$\n"
"    Time_Key    time\n"
"    Time_Format %Y-%M-%S %H:%M:%S\n"
"    Time_Keep   On\n"
"    Decode_Field_As   mysql_quoted key001\n"
"\n"
"\n"
"\n"
"# Parser: REGEX2_mysql_quoted_stuff\n"
"# ====================\n"
"# Apache error log time format\n"
"#\n"
"[PARSER]\n"
"    Name        REGEX2_mysql_quoted_stuff\n"
"    Format      logfmt\n"
"    Regex       ^(?<time>.*?),(?<key001>.*)$\n"
"    Time_Key    time\n"
"    Time_Format %Y-%M-%S %H:%M:%S\n"
"    Time_Keep   On\n"
"    Decode_Field_As   mysql_quoted key001\n"
"    Types A1:integer A2:string A3:bool A4:float A5:hex\n"
"\n"
"\n"
"\n"
"# Parser: REGEX3_mysql_quoted_stuff\n"
"# ====================\n"
"# Apache error log time format\n"
"#\n"
"[PARSER]\n"
"    Name        REGEX3_mysql_quoted_stuff\n"
"    Format      json\n"
"    Regex       ^(?<time>.*?),(?<key001>.*)$\n"
"    Time_Key    time\n"
"    Time_Format %Y-%M-%S %H:%M:%S\n"
"    Time_Keep   On\n"
"    Decode_Field_As   escaped_utf8 key001\n"
"    Types A1:integer A2:string A3:bool A4:float A5:hex\n"
"\n"
"\n"
"\n"
"# Parser: REGEX33_mysql_quoted_stuff\n"
"# ====================\n"
"# Apache error log time format\n"
"#\n"
"[PARSER]\n"
"    Name        REGEX33_mysql_quoted_stuff\n"
"    Format      json\n"
"    Regex       ^(?<time>.*?),(?<key001>.*)$\n"
"    Time_Key    time\n"
"    Time_Format %Y-%M-%S %H:%M:%S\n"
"    Time_Keep   On\n"
"    Decode_Field_As   escaped key001\n"
"    Types A1:integer A2:string A3:bool A4:float A5:hex\n"
"\n"
"\n"
"\n"
"# Parser: REGEX4_mysql_quoted_stuff\n"
"# ====================\n"
"# Apache error log time format\n"
"#\n"
"[PARSER]\n"
"    Name        REGEX4_mysql_quoted_stuff\n"
"    Format      json\n"
"    Regex       ^(?<time>.*?),(?<key001>.*)$\n"
"    Time_Key    time\n"
"    Time_Format %Y-%M-%S %H:%M:%S\n"
"    Time_Keep   On\n"
"    Decode_Field_As   json key001\n"
"    Types A1:integer A2:string A3:bool A4:float A5:hex\n"
"[MULTILINE_PARSER]\n"
"    name          exception_test\n"
"    type          regex\n"
"    flush_timeout 1000\n"
"    rule          \"start_state\"  \"/(Dec \\d+ \\d+\\:\\d+\\:\\d+)(.*)/\" \"cont\"\n"
"    rule          \"cont\" \"/^\\s+at.*/\" \"cont\"\n";


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Set fuzzer-malloc chance of failure */
    flb_malloc_p = 0;
    flb_malloc_mod = 25000;

    /* Limit the size of the config files to 32KB. */
    if (size > 32768) {
        return 0;
    }

    /* Write the config file to a location we know OSS-Fuzz has */
    char filename[256];
    sprintf(filename, "/tmp/libfuzzer.%d", getpid());
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(conf_file, strlen(conf_file), 1, fp);
    fclose(fp);


    /* Now parse random data based on the config files */
    struct flb_config *config = NULL;
    config = flb_config_init();
    int ret = flb_parser_conf_file(filename, config);
    if (ret == 0) {
        struct mk_list *head = NULL;
        mk_list_foreach(head, &config->parsers) {
            size_t out_size;
            char *out_buf = NULL;
            struct flb_parser *parser = NULL;
            struct flb_time out_time;
            parser = mk_list_entry(head, struct flb_parser, _head);
            flb_parser_do(parser, (const char*)data, size, (void **)&out_buf,
                          &out_size, &out_time);
            if (out_buf != NULL) {
                free(out_buf);
            }
        }
    }
    flb_parser_exit(config);
    flb_config_exit(config);

    if (size > 100) {
        /* Now let's do a second run where we also call flb_config_set_property */
        config = flb_config_init();
        ret = flb_parser_conf_file(filename, config);
        char *key_1 = get_null_terminated(15, &data, &size);
        char *val_1 = get_null_terminated(15, &data, &size);
        char *key_2 = get_null_terminated(15, &data, &size);
        char *val_2 = get_null_terminated(15, &data, &size);
        char *progname = get_null_terminated(15, &data, &size);

        flb_config_set_property(config, key_1, val_1);
        flb_config_set_property(config, key_2, val_2);
        flb_config_set_program_name(config, progname);
        set_log_level_from_env(config);

        struct mk_list prop;
        flb_kv_init(&prop);
        flb_kv_item_create(&prop, key_1, val_1);
        flb_config_prop_get(progname, &prop);
        flb_slist_entry_get(&prop, (int)data[0]);
        flb_slist_dump(&prop);
        
        if (ret == 0) {
            struct mk_list *head = NULL;
            mk_list_foreach(head, &config->parsers) {
                size_t out_size;
                char *out_buf = NULL;
                struct flb_parser *parser = NULL;
                struct flb_time out_time;
                
                parser = mk_list_entry(head, struct flb_parser, _head);
                flb_parser_do(parser, (const char*)data, size, (void **)&out_buf,
                              &out_size, &out_time);
                if (out_buf != NULL) {
                    free(out_buf);
                }
            }
        }
        flb_parser_exit(config);
        flb_config_exit(config);
        flb_free(key_1);
        flb_free(val_1);
        flb_free(key_2);
        flb_free(val_2);
        flb_free(progname);
        flb_kv_release(&prop);
    }

    /* clean up the file */
    unlink(filename);

    return 0;
}
