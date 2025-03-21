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
