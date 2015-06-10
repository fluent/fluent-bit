
#!/bin/sh
TEST_FILES=`ls *.htt`
TOTAL_TESTS=`echo $TEST_FILES | wc -w`

# Server parameters file
CONFIG_FILE='__CONFIG'

LOGFILE='errors.log'

# Clear log file
:>$LOGFILE

# Should we stop at the first error? (yes | no)
STOP_AT_ERRORS=no

# httest error code for 'Connection refused'
CONN_REFUSED=111

# Enable colors in output :) (yes | no)
WITH_COLOR=yes

# httest command 
HTTEST_CMD='httest'

NTEST=1
TESTS_FAILED=0
TESTS_OK=0
TESTS_AVOIDED=0
CHECKLOGS=0

if [ "$1" = "-l" ]; then
    CHECKLOGS=1
    TOTAL_TESTS=`expr $TOTAL_TESTS \* 2`
fi

for test_file in $TEST_FILES; do
#	echo -ne "[TEST $NTEST/$TOTAL_TESTS]\t""case: $test_file\t\t"
	printf "[%3d/%d]  %-32s  " $NTEST $TOTAL_TESTS "$test_file"

	OUTPUT=`$HTTEST_CMD "$test_file" 2>&1`
	ERRCODE=$?	

	case $ERRCODE in
		0) 
			TESTS_OK=$((TESTS_OK+1))
			[ $WITH_COLOR = yes ] && echo -n "[1;32m"
			echo -n "=> [OK]"
			[ $WITH_COLOR = yes ] && echo -n "[m"
			;;

		$CONN_REFUSED)
			echo
			echo "Connection refused... (Is monkey running?)" >&2
			exit $CONN_REFUSED
			;;

		*)
			TESTS_FAILED=$((TESTS_FAILED+1))
			[ $WITH_COLOR = yes ] && echo -n "[1;31m"
			echo -n "=> [FAILED]"
			[ $WITH_COLOR = yes ] && echo -n "[m"

			perl -e 'print "-" x 78, "\n"' >>"$LOGFILE"
			echo "$OUTPUT" >>"$LOGFILE"
			perl -e 'print "-" x 78, "\n"' >>"$LOGFILE"

			[ $STOP_AT_ERRORS = yes ] && exit 1
	esac		

        # Check for logfiles rules
        NTEST=$((NTEST+1))

        if [ $CHECKLOGS = 0 ]; then
            echo
            continue
        fi

        echo
        test_file=`echo $test_file | sed 's/\.htt/\.log/g'`
        printf "[%3d/%d]  %-32s  " $NTEST $TOTAL_TESTS "$test_file"

        if [ ! -e "log_rules/$test_file" ]; then
            ERRCODE=2
        else
            # We need to sleep for a while as Monkey needs to flush
            # the logs, that happens every 3 seconds
            sleep 2
	    CHECKLOG=`./checklog -l log_rules/$test_file`
	    ERRCODE=$?
	fi

        case $ERRCODE in	
	    0)	
	        [ $WITH_COLOR = yes ] && echo -n "[1;32m"	
		echo "=> [OK]"
		[ $WITH_COLOR = yes ] && echo -n "[m"
                TESTS_OK=$((TESTS_OK+1))
		;;
	    1)
                [ $WITH_COLOR = yes ] && echo -n "[1;31m"
		echo "=> [FAILED]"
		echo $CHECKLOG
		[ $WITH_COLOR = yes ] && echo -n "[m"
                TESTS_FAILED=$((TESTS_FAILED+1))
		[ $STOP_AT_ERRORS = yes ] && exit 1
		;;

	    2)	[ $WITH_COLOR = yes ] && echo -n "[1;33m"
                echo "=> [NO RULES]"
		[ $WITH_COLOR = yes ] && echo -n "[m"
                TESTS_AVOIDED=$((TESTS_AVOIDED+1))
		;;
	esac

	NTEST=$((NTEST+1))
done

echo -e "\n$TESTS_OK test(s) succeeded, $TESTS_FAILED test(s) failed, $TESTS_AVOIDED test(s) avoided."
