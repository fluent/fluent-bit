 /* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#include <monkey/mk_api.h>
#include "base64.h"
#include "auth.h"
#include "conf.h"

/*
 * Register a users file into the main list, if the users
 * file already exists it just return the node in question,
 * otherwise add the node to the list and return the node
 * created.
 */
static struct users_file *mk_auth_conf_add_users(char *users_path)
{
    struct file_info finfo;
    struct mk_list *head;
    struct users_file *entry;
    struct user *cred;
    int i, sep, len;
    int offset = 0;
    size_t decoded_len;
    char *buf;

    mk_list_foreach(head, &users_file_list) {
        entry = mk_list_entry(head, struct users_file, _head);
        if (strcmp(entry->path, users_path) == 0) {
            return entry;
        }
    }

    if (mk_api->file_get_info(users_path, &finfo, MK_FILE_READ) != 0) {
        mk_warn("Auth: Invalid users file '%s'", users_path);
        return NULL;
    }

    if (finfo.is_directory == MK_TRUE) {
        mk_warn("Auth: Not a credentials file '%s'", users_path);
        return NULL;
    }

    if (finfo.read_access == MK_FALSE) {
        mk_warn("Auth: Could not read file '%s'", users_path);
        return NULL;
    }

    /* We did not find the path in our list, let's create a new node */
    entry  = mk_api->mem_alloc(sizeof(struct users_file));
    entry->last_updated = finfo.last_modification;
    entry->path = users_path;

    /* Read file and add users to the list */
    mk_list_init(&entry->_users);

    /* Read credentials file */
    buf = mk_api->file_to_buffer(users_path);
    if (!buf) {
        mk_warn("Auth: No users loaded '%s'", users_path);
        return NULL;
    }

    /* Read users list buffer lines */
    len = strlen(buf);
    for (i = 0; i < len; i++) {
        if (buf[i] == '\n' || (i) == len -1) {
            sep = mk_api->str_search(buf + offset, ":", 1);

            if (sep >= (int)sizeof(cred->user)) {
                mk_warn("Auth: username too long");
                offset = i + 1;
                continue;
            }
            if (i - offset - sep - 1 - 5 >= (int)sizeof(cred->passwd_raw)) {
                mk_warn("Auth: password hash too long");
                offset = i + 1;
                continue;
            }

            cred = mk_api->mem_alloc(sizeof(struct user));

            /* Copy username */
            strncpy(cred->user, buf + offset, sep);
            cred->user[sep] = '\0';

            /* Copy raw password */
            offset += sep + 1 + 5;
            strncpy(cred->passwd_raw,
                    buf + offset,
                    i - (offset));
            cred->passwd_raw[i - offset] = '\0';

            /* Decode raw password */
            cred->passwd_decoded = base64_decode((unsigned char *)(cred->passwd_raw),
                                                 strlen(cred->passwd_raw),
                                                 &decoded_len);

            offset = i + 1;

            if (!cred->passwd_decoded) {
                mk_warn("Auth: invalid user '%s' in '%s'",
                        cred->user, users_path);
                mk_api->mem_free(cred);
                continue;
            }
            mk_list_add(&cred->_head, &entry->_users);
        }
    }
    mk_api->mem_free(buf);

    /* Link node to global list */
    mk_list_add(&entry->_head, &users_file_list);

    return entry;
}

/*
 * Read all vhost configuration nodes and looks for users files under an [AUTH]
 * section, if present, it add that file to the unique list. It parse all user's
 * files mentioned to avoid duplicated lists in memory.
 */
int mk_auth_conf_init_users_list()
{
    /* Section data */
    char *location;
    char *title;
    char *users_path;
    /* auth vhost list */
    struct vhost *auth_vhost;

    /* vhost configuration */
    struct mk_list *head_hosts;
    struct mk_list *hosts = &mk_api->config->hosts;
    struct mk_list *head_sections;
    struct mk_vhost *entry_host;
    struct mk_rconf_section *section;

    /* vhost [AUTH] locations */
    struct location *loc;

    /* User files list */
    struct users_file *uf;

    PLUGIN_TRACE("Loading user's files");

    mk_list_foreach(head_hosts, hosts) {
        entry_host = mk_list_entry(head_hosts, struct mk_vhost, _head);
        if (!entry_host->config) {
            continue;
        }

        auth_vhost = mk_api->mem_alloc(sizeof(struct vhost));
        auth_vhost->host = entry_host;        /* link virtual host entry */
        mk_list_init(&auth_vhost->locations); /* init locations list */

        /*
         * check vhost 'config' and look for [AUTH] sections, we don't use
         * mk_config_section_get() because we can have multiple [AUTH]
         * sections.
         */
        mk_list_foreach(head_sections, &entry_host->config->sections) {
            section = mk_list_entry(head_sections, struct mk_rconf_section, _head);

            if (strcasecmp(section->name, "AUTH") == 0) {
                location = NULL;
                title = NULL;
                users_path = NULL;

                /* Get section keys */
                location = mk_api->config_section_get_key(section,
                                                          "Location",
                                                          MK_RCONF_STR);
                title = mk_api->config_section_get_key(section,
                                                       "Title",
                                                       MK_RCONF_STR);

                users_path = mk_api->config_section_get_key(section,
                                                            "Users",
                                                            MK_RCONF_STR);

                /* get or create users file entry */
                uf = mk_auth_conf_add_users(users_path);
                if (!uf) {
                    continue;
                }

                /* Location node */
                loc = mk_api->mem_alloc(sizeof(struct location));
                mk_api->pointer_set(&loc->path, location);
                mk_api->pointer_set(&loc->title, title);

                loc->auth_http_header.data = NULL;
                mk_api->str_build(&loc->auth_http_header.data,
                                  &loc->auth_http_header.len,
                                  MK_AUTH_HEADER_TITLE, title);

                loc->users = uf;

                /* Add new location to auth_vhost node */
                mk_list_add(&loc->_head, &auth_vhost->locations);
            }
        }

        /* Link auth_vhost node to global list vhosts_list */
        mk_list_add(&auth_vhost->_head, &vhosts_list);
    }

#ifdef TRACE
    struct mk_list *vh_head, *loc_head;
    struct vhost *vh_entry;
    struct location *loc_entry;

    mk_list_foreach(vh_head, &vhosts_list) {
        vh_entry = mk_list_entry(vh_head, struct vhost, _head);
        PLUGIN_TRACE("Auth VHost: %p", vh_entry->host);

        mk_list_foreach(loc_head, &vh_entry->locations) {
            loc_entry = mk_list_entry(loc_head, struct location, _head);
            PLUGIN_TRACE("---");
            PLUGIN_TRACE(" location: %s", loc_entry->path);
            PLUGIN_TRACE(" title   : %s", loc_entry->title);
            PLUGIN_TRACE(" users   : %s", loc_entry->users->path);
        }
    }
#endif

    return 0;
}
