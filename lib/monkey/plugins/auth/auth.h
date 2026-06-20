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

#ifndef MK_AUTH_H
#define MK_AUTH_H

#include <monkey/mk_api.h>

/* Header stuff */
#define MK_AUTH_HEADER_BASIC     "Basic "
#define MK_AUTH_HEADER_TITLE     "WWW-Authenticate: Basic realm=\"%s\""

/* Credentials length */
#define MK_AUTH_CREDENTIALS_LEN 256

/*
 * The plugin hold one struct per virtual host and link to the
 * locations and users file associated:
 *
 *                    +---------------------------------+
 *      struct vhost  >            vhost (1:N)          |
 *                    |     +---------+----------+      |
 *                    |     |         |          |      |
 *   struct location  > location  location    location  |
 *                    |     |         |          |      |
 *                    |     +----+----+          +      |
 *                    |          |               |      |
 *      struct users  >        users           users    |
 *                    +---------------------------------+
 *
 */

/* List of virtual hosts to handle locations */
struct mk_list vhosts_list;

/* main index for locations under a virtualhost */
struct vhost {
    struct mk_vhost *host;
    struct mk_list locations;
    struct mk_list _head;
};

/*
 * A location restrict a filesystem path with a list
 * of allowed users
 */
struct location {
    mk_ptr_t path;
    mk_ptr_t title;
    mk_ptr_t auth_http_header;

    struct users_file *users;
    struct mk_list _head;
};

/* Head index for user files list */
struct mk_list users_file_list;

/*
 * Represents a users file, each entry represents a physical
 * file and belongs to a node of the users_file_list list
 */
struct users_file {
    time_t last_updated;   /* last time this entry was modified */
    char *path;            /* file path */
    struct mk_list _users; /* list of users */
    struct mk_list _head;  /* head for main mk_list users_file_list */
};

/*
 * a list of users, this list belongs to a
 * struct location
 */
struct user {
    char user[128];
    char passwd_raw[256];
    unsigned char *passwd_decoded;

    struct mk_list _head;
};

struct mk_list users_file_list;

/* Thread key */
mk_ptr_t auth_header_request;
mk_ptr_t auth_header_basic;

#define SHA1_DIGEST_LEN 20

#endif
