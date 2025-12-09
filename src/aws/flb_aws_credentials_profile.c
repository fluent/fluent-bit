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

#include "flb_aws_credentials_log.h"

#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

#define ACCESS_KEY_PROPERTY_NAME            "aws_access_key_id"
#define SECRET_KEY_PROPERTY_NAME            "aws_secret_access_key"
#define SESSION_TOKEN_PROPERTY_NAME         "aws_session_token"
#define CREDENTIAL_PROCESS_PROPERTY_NAME    "credential_process"

#define AWS_PROFILE                         "AWS_PROFILE"
#define AWS_DEFAULT_PROFILE                 "AWS_DEFAULT_PROFILE"

#define AWS_CONFIG_FILE                     "AWS_CONFIG_FILE"
#define AWS_SHARED_CREDENTIALS_FILE         "AWS_SHARED_CREDENTIALS_FILE"

#define DEFAULT_PROFILE "default"
#define CONFIG_PROFILE_PREFIX "profile "
#define CONFIG_PROFILE_PREFIX_LEN (sizeof(CONFIG_PROFILE_PREFIX)-1)

/* Declarations */
struct flb_aws_provider_profile;
static int refresh_credentials(struct flb_aws_provider_profile *implementation,
                               int debug_only);

static int get_aws_shared_file_path(flb_sds_t* field, char* env_var, char* home_aws_path);

static int parse_config_file(char *buf, char* profile, struct flb_aws_credentials** creds,
                             time_t* expiration, int debug_only);
static int parse_credentials_file(char *buf, char *profile,
                                  struct flb_aws_credentials *creds, int debug_only);

static int get_shared_config_credentials(char* config_path,
                                         char*profile,
                                         struct flb_aws_credentials** creds,
                                         time_t* expiration,
                                         int debug_only);
static int get_shared_credentials(char* credentials_path,
                                  char* profile,
                                  struct flb_aws_credentials** creds,
                                  int debug_only);

static flb_sds_t parse_property_value(char *s, int debug_only);
static char *parse_property_line(char *line);
static int has_profile(char *line, char* profile, int debug_only);
static int is_profile_line(char *line);
static int config_file_profile_matches(char *line, char *profile);

/*
 * A provider that reads from the shared credentials file.
 */
struct flb_aws_provider_profile {
    struct flb_aws_credentials *creds;
    time_t next_refresh;

    flb_sds_t profile;
    flb_sds_t config_path;
    flb_sds_t credentials_path;
};

struct flb_aws_credentials *get_credentials_fn_profile(struct flb_aws_provider
                                                       *provider)
{
    struct flb_aws_credentials *creds;
    int ret;
    struct flb_aws_provider_profile *implementation = provider->implementation;

    /*
     * If next_refresh <= 0, it means we don't know how long the credentials
     * are valid for. So we won't refresh them unless explicitly asked
     * via refresh_fn_profile.
     */
    if (!implementation->creds || (implementation->next_refresh > 0 &&
        time(NULL) >= implementation->next_refresh)) {
        AWS_CREDS_DEBUG("Retrieving credentials for AWS Profile %s",
                        implementation->profile);
        if (try_lock_provider(provider) == FLB_TRUE) {
            ret = refresh_credentials(implementation, FLB_FALSE);
            unlock_provider(provider);
            if (ret < 0) {
                AWS_CREDS_ERROR("Failed to retrieve credentials for AWS Profile %s",
                                implementation->profile);
                return NULL;
            }
        } else {
            AWS_CREDS_WARN("Another thread is refreshing credentials, will retry");
            return NULL;
        }
    }

    creds = flb_calloc(1, sizeof(struct flb_aws_credentials));
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
    int ret = -1;
    AWS_CREDS_DEBUG("Refresh called on the profile provider");
    if (try_lock_provider(provider) == FLB_TRUE) {
        ret = refresh_credentials(implementation, FLB_FALSE);
        unlock_provider(provider);
        return ret;
    }
    return ret;
}

int init_fn_profile(struct flb_aws_provider *provider)
{
    struct flb_aws_provider_profile *implementation = provider->implementation;
    int ret = -1;
    AWS_CREDS_DEBUG("Init called on the profile provider");
    if (try_lock_provider(provider) == FLB_TRUE) {
        ret = refresh_credentials(implementation, FLB_TRUE);
        unlock_provider(provider);
        return ret;
    }
    return ret;
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

void upstream_set_fn_profile(struct flb_aws_provider *provider,
                             struct flb_output_instance *ins)
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

        if (implementation->config_path) {
            flb_sds_destroy(implementation->config_path);
        }

        if (implementation->credentials_path) {
            flb_sds_destroy(implementation->credentials_path);
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
    .upstream_set = upstream_set_fn_profile,
};

struct flb_aws_provider *flb_profile_provider_create(char* profile)
{
    struct flb_aws_provider *provider = NULL;
    struct flb_aws_provider_profile *implementation = NULL;
    int result = -1;

    provider = flb_calloc(1, sizeof(struct flb_aws_provider));

    if (!provider) {
        flb_errno();
        goto error;
    }

    pthread_mutex_init(&provider->lock, NULL);

    implementation = flb_calloc(1,
                                sizeof(
                                struct flb_aws_provider_profile));

    if (!implementation) {
        flb_errno();
        goto error;
    }

    provider->provider_vtable = &profile_provider_vtable;
    provider->implementation = implementation;

    result = get_aws_shared_file_path(&implementation->config_path, AWS_CONFIG_FILE,
                                      "/.aws/config");
    if (result < 0) {
        goto error;
    }

    result = get_aws_shared_file_path(&implementation->credentials_path,
                                      AWS_SHARED_CREDENTIALS_FILE, "/.aws/credentials");
    if (result < 0) {
        goto error;
    }

    if (!implementation->config_path && !implementation->credentials_path) {
        AWS_CREDS_WARN("Failed to initialize profile provider: "
                       "HOME, %s, and %s not set.",
                       AWS_CONFIG_FILE, AWS_SHARED_CREDENTIALS_FILE);
        goto error;
    }

    /* AWS profile name. */
    if (profile == NULL) {
        profile = getenv(AWS_PROFILE);
    }
    if (profile && strlen(profile) > 0) {
        goto set_profile;
    }

    profile = getenv(AWS_DEFAULT_PROFILE);
    if (profile && strlen(profile) > 0) {
        goto set_profile;
    }

    profile = DEFAULT_PROFILE;

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


/*
 * Fetches the path of either the shared config file or the shared credentials file.
 * Returns 0 on success and < 0 on failure.
 * On success, the result will be stored in *field.
 * 
 * If the given environment variable is set, then its value will be used verbatim.
 * Else if $HOME is set, then it will be concatenated with home_aws_path.
 * If neither is set, then *field will be set to NULL. This is not considered a failure.
 * 
 * In practice, env_var will be "AWS_CONFIG_FILE" or "AWS_SHARED_CREDENTIALS_FILE",
 * and home_aws_path will be "/.aws/config" or "/.aws/credentials".
 */
static int get_aws_shared_file_path(flb_sds_t* field, char* env_var, char* home_aws_path)
{
    char* path = NULL;
    int result = -1;
    flb_sds_t value = NULL;

    path = getenv(env_var);
    if (path && *path) {
        value = flb_sds_create(path);
        if (!value) {
            flb_errno();
            goto error;
        }
    } else {
        path = getenv("HOME");
        if (path && *path) {
            value = flb_sds_create(path);
            if (!value) {
                flb_errno();
                goto error;
            }

            if (path[strlen(path) - 1] == '/') {
                home_aws_path++;
            }
            result = flb_sds_cat_safe(&value, home_aws_path, strlen(home_aws_path));
            if (result < 0) {
                flb_errno();
                goto error;
            }
        }
    }

    *field = value;
    return 0;

error:
    flb_sds_destroy(value);
    return -1;
}

static int is_profile_line(char *line) {
    if (line[0] == '[') {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

/* Called on lines that have is_profile_line == True */
static int has_profile(char *line, char* profile, int debug_only) {
    char *end_bracket = strchr(line, ']');
    if (!end_bracket) {
        if (debug_only) {
            AWS_CREDS_DEBUG("Profile header has no ending bracket:\n %s", line);
        }
        else {
            AWS_CREDS_WARN("Profile header has no ending bracket:\n %s", line);
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
        AWS_CREDS_ERROR_OR_DEBUG(debug_only, "Could not parse credential value from %s", s);
    }

    prop = flb_sds_create(val);
    if (!prop) {
        flb_errno();
        return NULL;
    }

    return prop;
}

static int config_file_profile_matches(char *line, char *profile) {
    char *current_profile = line + 1;
    char* current_profile_end = strchr(current_profile, ']');

    if (!current_profile_end) {
        return FLB_FALSE;
    }
    *current_profile_end = '\0';

    /*
     * Non-default profiles look like `[profile <name>]`.
     * The default profile can look like `[profile default]` or just `[default]`.
     * This is different than the credentials file, where everything is `[<name>]`.
     */
    if (strncmp(current_profile, CONFIG_PROFILE_PREFIX, CONFIG_PROFILE_PREFIX_LEN) != 0) {
        if (strcmp(current_profile, DEFAULT_PROFILE) != 0) {
            /* This is not a valid profile line. */
            return FLB_FALSE;
        }
    } else {
        current_profile += CONFIG_PROFILE_PREFIX_LEN;
    }

    if (strcmp(current_profile, profile) == 0) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

static int parse_config_file(char *buf, char* profile, struct flb_aws_credentials** creds,
                            time_t* expiration, int debug_only)
{
    char *line = NULL;
    char *line_end = NULL;
    char *prop_val = NULL;
    char *credential_process = NULL;
    int found_profile = FLB_FALSE;

    for (line = buf; line[0] != '\0'; line = buf) {
        /*
         * Find the next newline and replace it with a null terminator.
         * That way we can easily manipulate the current line as a string.
         */
        line_end = strchr(line, '\n');
        if (line_end) {
            *line_end = '\0';
            buf = line_end + 1;
        } else {
            buf = "";
        }

        if (found_profile != FLB_TRUE) {
            if (is_profile_line(line) != FLB_TRUE) {
                continue;
            }
            if (config_file_profile_matches(line, profile) != FLB_TRUE) {
                continue;
            }
            found_profile = FLB_TRUE;
        } else {
            if (is_profile_line(line) == FLB_TRUE) {
                break;
            }
            prop_val = parse_property_line(line);
            if (strcmp(line, CREDENTIAL_PROCESS_PROPERTY_NAME) == 0) {
                credential_process = prop_val;
            }
        }
    }

    if (credential_process) {
#ifdef FLB_HAVE_AWS_CREDENTIAL_PROCESS
        if (exec_credential_process(credential_process, creds, expiration) < 0) {
            return -1;
        }
#else
        AWS_CREDS_WARN("credential_process not supported for this platform");
        return -1;
#endif
    }

    return 0;
}

/*
 * Parses a shared credentials file.
 * Expects the contents of 'creds' to be initialized to NULL (i.e use calloc).
 */
static int parse_credentials_file(char *buf, char *profile,
                                  struct flb_aws_credentials *creds, int debug_only)
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
    AWS_CREDS_ERROR_OR_DEBUG(debug_only, "%s and %s keys not parsed in shared "
                  "credentials file for profile %s.", ACCESS_KEY_PROPERTY_NAME,
                  SECRET_KEY_PROPERTY_NAME, profile);
    return -1;
}

static int get_shared_config_credentials(char* config_path,
                                         char*profile,
                                         struct flb_aws_credentials** creds,
                                         time_t* expiration,
                                         int debug_only) {
    int result = -1;
    char* buf = NULL;
    size_t size;
    *creds = NULL;
    *expiration = 0;

    AWS_CREDS_DEBUG("Reading shared config file.");

    if (flb_read_file(config_path, &buf, &size) < 0) {
        if (errno == ENOENT) {
            AWS_CREDS_DEBUG("Shared config file %s does not exist", config_path);
            result = 0;
            goto end;
        }
        flb_errno();
        AWS_CREDS_ERROR_OR_DEBUG(debug_only, "Could not read shared config file %s",
                                 config_path);
        result = -1;
        goto end;
    }

    if (parse_config_file(buf, profile, creds, expiration, debug_only) < 0) {
        result = -1;
        goto end;
    }

    result = 0;

end:
    flb_free(buf);
    return result;
}

static int get_shared_credentials(char* credentials_path,
                                  char* profile,
                                  struct flb_aws_credentials** creds,
                                  int debug_only) {
    int result = -1;
    char* buf = NULL;
    size_t size;
    *creds = NULL;

    *creds = flb_calloc(1, sizeof(struct flb_aws_credentials));
    if (!*creds) {
        flb_errno();
        result = -1;
        goto end;
    }

    AWS_CREDS_DEBUG("Reading shared credentials file.");

    if (flb_read_file(credentials_path, &buf, &size) < 0) {
        if (errno == ENOENT) {
            AWS_CREDS_DEBUG("Shared credentials file %s does not exist", credentials_path);
        } else {
            flb_errno();
            AWS_CREDS_ERROR_OR_DEBUG(debug_only, "Could not read shared credentials file %s",
                                     credentials_path);
        }
        result = -1;
        goto end;
    }

    if (parse_credentials_file(buf, profile, *creds, debug_only) < 0) {
        AWS_CREDS_ERROR_OR_DEBUG(debug_only, "Could not parse shared credentials file: "
                                 "valid profile with name '%s' not found", profile);
        result = -1;
        goto end;
    }

    result = 0;

end:
    flb_free(buf);

    if (result < 0) {
        flb_aws_credentials_destroy(*creds);
        *creds = NULL;
    }

    return result;
}

static int refresh_credentials(struct flb_aws_provider_profile *implementation,
                               int debug_only)
{
    struct flb_aws_credentials *creds = NULL;
    time_t expiration = 0;
    int ret;

    if (implementation->config_path) {
        ret = get_shared_config_credentials(implementation->config_path,
                                            implementation->profile,
                                            &creds,
                                            &expiration,
                                            debug_only);
        if (ret < 0) {
            goto error;
        }
    }

    /*
     * If we did not find a credential_process in the shared config file, fall back to
     * the shared credentials file.
     */
    if (!creds) {
        if (!implementation->credentials_path) {
            AWS_CREDS_ERROR("shared config file contains no credential_process and "
                            "no shared credentials file was configured");
            goto error;
        }

        ret = get_shared_credentials(implementation->credentials_path,
                                     implementation->profile,
                                     &creds,
                                     debug_only);
        if (ret < 0) {
            goto error;
        }

        /* The shared credentials file does not record when the credentials expire. */
        expiration = 0;
    }

    /* unset and free existing credentials */
    flb_aws_credentials_destroy(implementation->creds);
    implementation->creds = creds;

    if (expiration > 0) {
        implementation->next_refresh = expiration - FLB_AWS_REFRESH_WINDOW;
    } else {
        implementation->next_refresh = 0;
    }

    return 0;

error:
    flb_aws_credentials_destroy(creds);
    return -1;
}
