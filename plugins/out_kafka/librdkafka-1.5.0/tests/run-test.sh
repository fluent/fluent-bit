#!/usr/bin/env bash
#

RED='\033[31m'
GREEN='\033[32m'
CYAN='\033[36m'
CCLR='\033[0m'

if [[ $1 == -h ]]; then
    echo "Usage: $0 [-..] [modes..]"
    echo ""
    echo "  Modes: bare valgrind helgrind drd gdb lldb bash"
    echo "  Options:"
    echo "   -..    - test-runner command arguments (pass thru)"
    exit 0
fi

ARGS=

while [[ $1 == -* ]]; do
    ARGS="$ARGS $1"
    shift
done

TEST=./test-runner

if [ ! -z "$1" ]; then
    MODES=$1
else
    MODES="bare"
    # Enable valgrind:
    #MODES="bare valgrind"
fi

FAILED=0

export RDKAFKA_GITVER="$(git rev-parse --short HEAD)@$(git symbolic-ref -q --short HEAD)"

# Enable valgrind suppressions for false positives
SUPP="--suppressions=librdkafka.suppressions"

# Uncomment to generate valgrind suppressions
#GEN_SUPP="--gen-suppressions=yes"

# Common valgrind arguments
VALGRIND_ARGS="--error-exitcode=3"

# Enable vgdb on valgrind errors.
#VALGRIND_ARGS="$VALGRIND_ARGS --vgdb-error=1"

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../src:../src-cpp
export DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH:../src:../src-cpp

echo -e "${CYAN}############## $TEST ################${CCLR}"

for mode in $MODES; do
    echo -e "${CYAN}### Running test $TEST in $mode mode ###${CCLR}"
    export TEST_MODE=$mode
    case "$mode" in
	valgrind)
	    valgrind $VALGRIND_ARGS --leak-check=full --show-leak-kinds=all \
		     --errors-for-leak-kinds=all \
		     --track-origins=yes \
		     $SUPP $GEN_SUPP \
		$TEST $ARGS
	    RET=$?
	    ;;
	helgrind)
	    valgrind $VALGRIND_ARGS --tool=helgrind \
                     --sim-hints=no-nptl-pthread-stackcache \
                     $SUPP $GEN_SUPP \
		$TEST	$ARGS
	    RET=$?
	    ;;
	drd)
	    valgrind $VALGRIND_ARGS --tool=drd $SUPP $GEN_SUPP \
		$TEST	$ARGS
	    RET=$?
	    ;;
        callgrind)
	    valgrind $VALGRIND_ARGS --tool=callgrind $SUPP $GEN_SUPP \
		$TEST	$ARGS
	    RET=$?
	    ;;
        gdb)
            grun=$(mktemp gdbrunXXXXXX.gdb)
            cat >$grun <<EOF
set \$_exitcode = -999
run $ARGS
if \$_exitcode != -999
 quit
end
EOF
            export ASAN_OPTIONS="$ASAN_OPTIONS:abort_on_error=1"
            gdb -x $grun $TEST
            RET=$?
            rm $grun
            ;;
	bare)
	    $TEST $ARGS
	    RET=$?
	    ;;
        lldb)
            lldb -b -o "process launch --environment DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH" -- $TEST $ARGS
            RET=$?
            ;;
	bash)
	    PS1="[run-test.sh] $PS1" bash
	    RET=$?
	    ;;
	*)
	    echo -e "${RED}### Unknown mode $mode for $TEST ###${CCLR}"
	    RET=1
	    ;;
    esac

    if [ $RET -gt 0 ]; then
	echo -e "${RED}###"
	echo -e "### Test $TEST in $mode mode FAILED! ###"
	echo -e "###${CCLR}"
	FAILED=1
    else
	echo -e "${GREEN}###"
	echo -e "### $Test $TEST in $mode mode PASSED! ###"
	echo -e "###${CCLR}"
    fi
done

exit $FAILED

