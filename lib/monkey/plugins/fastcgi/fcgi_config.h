#ifndef _FCGI_CONFIG_H_
#define _FCGI_CONFIG_H_

#include <monkey/mk_api.h>
#include "regex.h" /* regex_t */

struct fcgi_server {
	char *name;
	char *path;
	char *addr;
	int port;

	int mpx_connection;

	unsigned int max_connections;
	unsigned int max_requests;
};

struct fcgi_location {
	char *name;
	regex_t match_regex;

	int keep_alive;

	unsigned int server_count;
	unsigned int *server_ids;
};

struct fcgi_config {
	unsigned int server_count;
	struct fcgi_server *servers;
	unsigned int location_count;
	struct fcgi_location *locations;
};

void fcgi_config_free(struct fcgi_config *config);

int fcgi_config_read(struct fcgi_config *config, char *confdir);

struct fcgi_location *fcgi_config_get_location(const struct fcgi_config *config,
		unsigned int location_id);

struct fcgi_server *fcgi_config_get_server(const struct fcgi_config *config,
		unsigned int server_id);

#endif // _FCGI_CONFIG_H
