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

#include "image.h"

/*
 * This example shows a simple quiz. It includes POST data handling, and
 * an image embedded in the code.
*/

enum {
	bufsize = 4096
};
static char buf[bufsize];

static void front() {

	sprintf(buf, "<html><body><center><h2>Hello friend."
			" Have you seen this guy?</h2>\n"
	"<br><br><img src=\"/image.png\">"
	"<br><br><form action=/ method=post>"
	"<input type=radio name=q1 value=yes>Why yes I have<br>"
	"<input type=radio name=q1 value=no>No, who's he?<br>"
	"<input type=radio name=q1 value=who>Canada<hr width='20%%'>"
	"<input type=submit>"
	"</form>"
	"</center></body></html>");

}

static void points() {

	sprintf(buf, "<html><body><center><h2>Correct!</h2>\n"
	"<br><br><a href='http://monkey-project.com'>Visit him.</a>"
	"</center></body></html>");

}

static void wrong() {

	sprintf(buf, "<html><body><center><h2>I'm a sad puppy.</h2>\n"
	"</center></body></html>");
}

static int list(const mklib_session *sr, const char *vhost, const char *url,
		const char *get, unsigned long getlen,
		const char *post, unsigned long postlen,
		unsigned int *status, const char **content, unsigned long *content_len,
		char *header) {

	if (strcmp(url, "/image.png") == 0) {
		*content = (char *) monkey_head_png;
		*content_len = sizeof(monkey_head_png);
		sprintf(header, "Content-type: image/png");

		return MKLIB_TRUE;
	}

	if (!post) {
		front();
	} else {
		if (strstr(post, "q1=who") || strstr(post, "q1=yes"))
			points();
		else
			wrong();
	}

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
