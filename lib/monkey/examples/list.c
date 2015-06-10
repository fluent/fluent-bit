/* Monkey HTTP Daemon
 * ------------------
 * Copyright (C) 2012, Lauri Kasanen <cand@gmx.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <libmonkey.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * This example shows a directory listing of /tmp, with no access to files. Fun eh?
*/

enum {
	bufsize = 4096
};
static char buf[bufsize];

static int list(const mklib_session *sr, const char *vhost, const char *url,
		const char *get, unsigned long getlen,
		const char *post, unsigned long postlen,
		unsigned int *status, const char **content, unsigned long *content_len,
		char *header) {

	sprintf(buf, "<html><body><h2>Hello friend. You asked for %s.</h2>\n", url);
	strcat(buf, "<pre>");

	FILE *f = popen("ls -lh /tmp", "r");
	if (!f) exit(1);


	char mybuf[bufsize - 200];

	while (fgets(mybuf, bufsize - 200, f)) {
		// Note: this is dangerous. Only used for demonstration purposes.
		strcat(buf, mybuf);
	}
	pclose(f);

	strcat(buf, "</pre></body></html>");

	*content = buf;
	*content_len = strlen(buf);
	sprintf(header, "Content-type: text/html");

	// TRUE here means we handled this request.
	return MKLIB_TRUE;
}

/* The callback setting interface can't check the callback for compatibility.
 * This makes sure the callback function has the right arguments. */
static cb_data listf = list;

int main() {

	// Bind to all interfaces, port 2001, default plugins, no directory.
	// Lacking the directory means that no files can be accessed, just what we want.
	// We use the data callback.
	mklib_ctx ctx = mklib_init(NULL, 0, 0, NULL);
	if (!ctx) return 1;

	mklib_callback_set(ctx, MKCB_DATA, listf);

	// Start the server.
	mklib_start(ctx);

	// I'm now free to do my own things. I'm just going to wait for a keypress.
	printf("All set and running! Visit me, I default to localhost:2001.\n");
	printf("Press a key to exit.\n");
	getchar();

	mklib_stop(ctx);

	return 0;
}
