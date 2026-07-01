#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
	mkdir -p /var/log/monkey
	chown www-data:www-data /var/log/monkey
	chmod 0750 /var/log/monkey
	touch /var/log/monkey/master.log
	chown www-data:www-data /var/log/monkey/master.log
fi

#DEBHELPER#

exit 0
