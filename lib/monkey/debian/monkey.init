#!/bin/sh
#
# start/stop Monkey HTTP Daemon

### BEGIN INIT INFO
# Provides:          monkey
# Required-Start:    $remote_fs $network $syslog
# Required-Stop:     $remote_fs $network $syslog
# Should-Start:      $named
# Should-Stop:       $named
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start Monkey HTTP Daemon
# Description:       Start Monkey HTTP Daemon
### END INIT INFO

CONFDIR="/etc/monkey"
BINMONKEY="/usr/sbin/monkey"

PORT=$(sed -n '/^[ \t]*Port/s/^.* //p' "$CONFDIR/monkey.conf")
PIDFILE=$(sed -n '/^[ \t]*PidFile/s/^.* //p' "$CONFDIR/monkey.conf")."$PORT"

for arg in $*; do
	case "$arg" in
		-*=*) optarg=`echo "$arg" | sed 's/[-_a-zA-Z0-9]*=//'` ;;
		   *) optarg= ;;
	esac

	if  ! test -f $PIDFILE ; then
		STATUS="no"
	else
		PIDMONKEY=`cat $PIDFILE`
		if ! kill -0 $PIDMONKEY 2>/dev/null; then
			STATUS="no"
		else
			STATUS="yes"
		fi
	fi

	case "$arg" in
		start)
			if [ "$STATUS" = "yes"  ] ; then
				echo "Monkey is running... (PID=$PIDMONKEY)"
				exit 1
			fi
			if ! test -x $BINMONKEY ; then
				echo "Error: I can't run binary file"
				exit 1
			else
				if $BINMONKEY --daemon  2>/dev/null ; then
					echo "Running Monkey -> OK"
					exit 0
				fi
			fi
		;;
		stop)
			if  [ "$STATUS" = "no" ]; then
				echo "Monkey is not running."
				exit 0
			fi
			kill -9 $PIDMONKEY
			rm -rf $PIDFILE > /dev/null
			echo "Monkey stopped ($PIDMONKEY)"
			exit 0
			;;
		force-reload|restart)
			if  [ "$STATUS" = "yes" ]; then
				if ! kill $PIDMONKEY  > /dev/null ; then
					killall -9 monkey
				else
					echo -n "Stopping Monkey... "
				fi
			else
				echo -n "Monkey is not running... "
			fi
			if ! test -x $BINMONKEY ; then
				echo "Error: I can't run binary file"
				exit 1
			else
				$BINMONKEY --daemon > /dev/null
				echo "Restarting -> OK"
				exit 0
			fi
			;;
		status)
                        if  [ "$STATUS" = "yes" ]; then
				echo "Monkey is running... (PID=$PIDMONKEY)"
			else
                                echo "Monkey is not running... "
                        fi
			exit 0
			;;
		*)
			echo "Usage : monkey [start|stop|restart|status|help]"
			exit 1
		;;
	esac
done
echo "Usage : monkey [start|stop|restart|status|help]"

exit 0
