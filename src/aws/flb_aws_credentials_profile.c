/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
 #include <fluent-bit/flb_sds.h>
 #include <fluent-bit/flb_http_client.h>
 #include <fluent-bit/flb_aws_credentials.h>
 #include <fluent-bit/flb_aws_util.h>

 #include <jsmn/jsmn.h>
 #include <stdlib.h>
 #include <time.h>

 #include <sys/types.h>
 #include <sys/stat.h>
 #include <unistd.h>
 #include <ctype.h>

#define ACCESS_KEY_PROPERTY_NAME            "aws_access_key_id"
#define SECRET_KEY_PROPERTY_NAME            "aws_secret_access_key"
#define SESSION_TOKEN_PROPERTY_NAME         "aws_session_token"

#define AWS_PROFILE                         "AWS_PROFILE"
#define AWS_DEFAULT_PROFILE                 "AWS_DEFAULT_PROFILE"

#define AWS_SHARED_CREDENTIALS_FILE         "AWS_SHARED_CREDENTIALS_FILE"

/* Declarations */
struct flb_aws_provider_profile;
static int get_profile(struct flb_aws_provider_profile *implementation,
                       int debug_only);
static int parse_file(char *buf, char *profile, struct flb_aws_credentials *creds,
                      int debug_only);
static flb_sds_t parse_property_value(char *s, int debug_only);
static char *parse_property_line(char *line);
static int has_profile(char *line, char* profile, int debug_only);
static int is_profile_line(char *line);

/*
 * A provider that reads from the shared credentials file.
 */
struct flb_aws_provider_profile {
    struct flb_aws_credentials *creds;

    flb_sds_t profile;
    flb_sds_t path;
};

struct flb_aws_credentials *get_credentials_fn_profile(struct flb_aws_provider
                                                       *provider)
{
    struct flb_aws_credentials *creds;
    int ret;
    struct flb_aws_provider_profile *implementation = provider->implementation;

    flb_debug("[aws_credentials] Retrieving credentials for "
              "AWS Profile %s", implementation->profile);

    if (!implementation->creds) {
        ret = get_profile(implementation, FLB_FALSE);
        if (ret < 0) {
            flb_error("[aws_credentials] Failed to retrieve credentials for "
                      "AWS Profile %s", implementation->profile);
            return NULL;
        }
    }

    creds = flb_malloc(sizeof(struct flb_aws_credentials));
    if (!creds) {
        flb_errno();
        goto error;
    }

    creds->access_key_id = flb_sds_create(implementation->creds->access_key_id);
    if (!creds->access_key_id) {
        flb_errno();
        goto error;
    }

    creds->secret_access_key = flb_sds_create(implementation->
                                              creds->secret_access_key);
    if (!creds->secret_access_key) {
        flb_errno();
        goto error;
    }

    if (implementation->creds->session_token) {
        creds->session_token = flb_sds_create(implementation->
                                              creds->session_token);
        if (!creds->session_token) {
            flb_errno();
            goto error;
        }

    } else {
        creds->session_token = NULL;
    }

    return creds;

error:
    flb_aws_credentials_destroy(creds);
    return NULL;
}

int refresh_fn_profile(struct flb_aws_provider *provider)
{
    struct flb_aws_provider_profile *implementation = provider->implementation;
    flb_debug("[aws_credentials] Refresh called on the profile provider");
    return get_profile(implementation, FLB_FALSE);
}

int init_fn_profile(struct flb_aws_provider *provider)
{
    struct flb_aws_provider_profile *implementation = provider->implementation;
    flb_debug("[aws_credentials] Init called on the profile provider");
    return get_profile(implementation, FLB_TRUE);
}

/*
 * Sync and Async are no-ops for the profile provider because it does not
 * make network IO calls
 */
void sync_fn_profile(struct flb_aws_provider *provider)
{
    return;
}

void async_fn_profile(struct flb_aws_provider *provider)
{
    return;
}

void destroy_fn_profile(struct flb_aws_provider *provider)
{
    struct flb_aws_provider_profile *implementation = provider->implementation;

    if (implementation) {
        if (implementation->creds) {
            flb_aws_credentials_destroy(implementation->creds);
        }

        if (implementation->profile) {
            flb_sds_destroy(implementation->profile);
        }

        if (implementation->path) {
            flb_sds_destroy(implementation->path);
        }

        flb_free(implementation);
        provider->implementation = NULL;
    }

    return;
}

static struct flb_aws_provider_vtable profile_provider_vtable = {
    .get_credentials = get_credentials_fn_profile,
    .init = init_fn_profile,
    .refresh = refresh_fn_profile,
    .destroy = destroy_fn_profile,
    .sync = sync_fn_profile,
    .async = async_fn_profile,
};

struct flb_aws_provider *flb_profile_provider_create()
{
    struct flb_aws_provider *provider = NULL;
    struct flb_aws_provider_profile *implementation = NULL;
    char *path;
    char *profile;
    char *home;

    provider = flb_calloc(1, sizeof(struct flb_aws_provider));

    if (!provider) {
        flb_errno();
        return NULL;
    }

    implementation = flb_calloc(1,
                                sizeof(
                                struct flb_aws_provider_profile));

    if (!implementation) {
        flb_errno();
        goto error;
    }

    provider->provider_vtable = &profile_provider_vtable;
    provider->implementation = implementation;

    /* find the shared credentials file */
    path = getenv(AWS_SHARED_CREDENTIALS_FILE);
    if (path && strlen(path) > 0) {
        implementation->path = flb_sds_create(path);
        if (!implementation->path) {
            flb_errno();
            goto error;
        }
    } else {
        /* default path: $HOME/.aws/credentials */
        home = getenv("HOME");
        if (!home || strlen(home) == 0) {
            flb_warn("[aws_credentials] Failed to initialized profile provider: "
            "$HOME not set and AWS_SHARED_CREDENTIALS_FILE not set.");
            flb_aws_provider_destroy(provider);
            return NULL;
        }

        /* join file path */
        implementation->path = flb_sds_create(home);
        if (!implementation->path) {
            flb_errno();
            goto error;
        }
        if (home[strlen(home) - 1] == '/') {
            implementation->path = flb_sds_cat(implementation->path,
                                               ".aws/credentials", 16);
            if (!implementation->path) {
                flb_errno();
                goto error;
            }
        } else {
            implementation->path = flb_sds_cat(implementation->path,
                                               "/.aws/credentials", 17);
            if (!implementation->path) {
                flb_errno();
                goto error;
            }
        }
    }

    /* AWS profile name */
    profile = getenv(AWS_PROFILE);
    if (profile && strlen(profile) > 0) {
        goto set_profile;
    }

    profile = getenv(AWS_DEFAULT_PROFILE);
    if (profile && strlen(profile) > 0) {
        goto set_profile;
    }

    profile = "default";

set_profile:
    implementation->profile = flb_sds_create(profile);
    if (!implementation->profile) {
        flb_errno();
        goto error;
    }

    return provider;

error:
    flb_aws_provider_destroy(provider);
    return NULL;
}

static int is_profile_line(char *line) {
    if (strlen(line) > 1 && line[0] == '[') {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

/* Called on lines that have is_profile_line == True */
static int has_profile(char *line, char* profile, int debug_only) {
    char *end_bracket = strchr(line, ']');
    if (!end_bracket) {
        if (debug_only) {
            flb_debug("[aws_credentials] Profile header has no ending bracket:\n %s",
                     line);
        }
        else {
            flb_warn("[aws_credentials] Profile header has no ending bracket:\n %s",
                     line);
        }
        return FLB_FALSE;
    }
    *end_bracket = '\0';

    if (strcmp(&line[1], profile) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/*
 * Sets a null byte such that line becomes the property name
 * Returns a pointer to the rest of the line (the value), if successful.
 */
static char *parse_property_line(char *line) {
    int len = strlen(line);
    int found_delimeter = FLB_FALSE;
    int i = 0;

    if (isspace(line[0])) {
        /* property line can not start with whitespace */
        return NULL;
    }

    /*
     * Go through the line char by char, once we find whitespace/= we are
     * passed the property name. Return the first char of the property value.
     * There should be a single "=" separating name and value.
     */
    for (i=0; i < (len - 1); i++) {
        if (isspace(line[i])) {
            line[i] = '\0';
        } else if (found_delimeter == FLB_FALSE && line[i] == '=') {
            found_delimeter = FLB_TRUE;
            line[i] = '\0';
        } else if (found_delimeter == FLB_TRUE) {
            return &line[i];
        }
    }

    return NULL;
}

/* called on the rest of a line after parse_property_line is called */
static flb_sds_t parse_property_value(char *s, int debug_only) {
    int len = strlen(s);
    int i = 0;
    char *val = NULL;
    flb_sds_t prop;

    for (i=0; i < len; i++) {
        if (isspace(s[i])) {
            s[i] = '\0';
            continue;
        } else if (!val) {
            val = &s[i];
        }
    }

    if (!val) {
        if (debug_only == FLB_TRUE) {
            flb_debug("[aws_credentials] Could not parse credential value from"
                      "%s", s);
        }
        else {
            flb_error("[aws_credentials] Could not parse credential value from"
                      "%s", s);
        }
    }

    prop = flb_sds_create(val);
    if (!prop) {
        flb_errno();
        return NULL;
    }

    return prop;
}

/*
 * Parses a shared credentials file.
 * Expects the contents of 'creds' to be initialized to NULL (i.e use calloc).
 */
static int parse_file(char *buf, char *profile, struct flb_aws_credentials *creds,
                      int debug_only)
{
    char *line;
    char *line_end;
    char *prop_val = NULL;
    int found_profile = FLB_FALSE;

    line = buf;

    while (line[0] != '\0') {
        /* turn the line into a C string */
        line_end = strchr(line, '\n');
        if (line_end) {
            *line_end = '\0';
        }

        if (is_profile_line(line) == FLB_TRUE) {
            if (found_profile == FLB_TRUE) {
                break;
            }
            if (has_profile(line, profile, debug_only)) {
                found_profile = FLB_TRUE;
            }
        } else {
            prop_val = parse_property_line(line);
            if (prop_val && found_profile == FLB_TRUE) {
                if (strcmp(line, ACCESS_KEY_PROPERTY_NAME) == 0) {
                    creds->access_key_id = parse_property_value(prop_val,
                                                                debug_only);
                }
                if (strcmp(line, SECRET_KEY_PROPERTY_NAME) == 0) {
                    creds->secret_access_key = parse_property_value(prop_val,
                                                                    debug_only);
                }
                if (strcmp(line, SESSION_TOKEN_PROPERTY_NAME) == 0) {
                    creds->session_token = parse_property_value(prop_val,
                                                                debug_only);
                }
            }
        }

        /* advance to next line */
        if (line_end) {
            line = line_end + 1;
        } else {
            break;
        }
    }

    if (creds->access_key_id && creds->secret_access_key) {
        return 0;
    }
    if (debug_only == FLB_TRUE) {
        flb_debug("[aws_credentials] %s and %s keys not parsed in shared "
                  "credentials file for profile %s.", ACCESS_KEY_PROPERTY_NAME,
                  SECRET_KEY_PROPERTY_NAME, profile);
    }
    else {
        flb_error("[aws_credentials] %s and %s keys not parsed in shared "
                  "credentials file for profile %s.", ACCESS_KEY_PROPERTY_NAME,
                  SECRET_KEY_PROPERTY_NAME, profile);
    }
    return -1;
}

static int get_profile(struct flb_aws_provider_profile *implementation,
                       int debug_only)
{
    struct flb_aws_credentials *creds = NULL;
    int ret;
    char* buf = NULL;
    size_t size;

    flb_debug("[aws_credentials] Reading shared credentials file..");

    creds = flb_calloc(1, sizeof(struct flb_aws_credentials));
    if (!creds) {
        flb_errno();
        return -1;
    }

    ret = flb_read_file(implementation->path, &buf, &size);
    if (ret < 0) {
        if (debug_only == FLB_TRUE) {
            flb_debug("[aws_credentials] Could not read shared credentials file %s",
                      implementation->path);
        }
        else {
            flb_error("[aws_credentials] Could not read shared credentials file %s",
                      implementation->path);
        }
        goto error;
    }

    ret = parse_file(buf, implementation->profile, creds, debug_only);
    flb_free(buf);

    if (ret < 0) {
        if (debug_only == FLB_TRUE) {
            flb_debug("[aws_credentials] Could not parse shared credentials file: "
                      "valid profile with name '%s' not found",
                      implementation->profile);
        }
        else {
            flb_error("[aws_credentials] Could not parse shared credentials file: "
                      "valid profile with name '%s' not found",
                      implementation->profile);
        }
        goto error;
    }

    /* unset and free existing credentials */
    flb_aws_credentials_destroy(implementation->creds);
    implementation->creds = NULL;

    implementation->creds = creds;
    return 0;

error:
    flb_aws_credentials_destroy(creds);
    return -1;
}
