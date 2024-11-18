#!/bin/sh
# Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Purpose: This script is needed to start the services with
# one command. This is necessary as ctest - which is used to run the
# tests - isn't able to start multiple binaries for one testcase. Therefore
# the testcase simply executes this script. This script then runs the services
# and checks that all exit successfully.

FAIL=0

cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Running first test
*******************************************************************************
*******************************************************************************
End-of-message

# Rejecting offer of service instance whose hosting application is still
# alive:
# * start application which offers service
# * start two clients which continuously exchanges messages with the service
# * start application which offers the same service again -> should be
#   rejected and an error message should be printed.
# * Message exchange with client application should not be interrupted.

export VSOMEIP_CONFIGURATION=offer_test_local.json
# Start the services
./offer_test_service 1 &
PID_SERVICE_ONE=$!
./offer_test_client SUBSCRIBE &
CLIENT_PID_ONE=$!
./offer_test_client SUBSCRIBE &
CLIENT_PID_TWO=$!

./offer_test_service 2 &
PID_SERVICE_TWO=$!

# Wait until all clients are finished
# Fail gets incremented if a client exits with a non-zero exit code
wait $CLIENT_PID_ONE || FAIL=$(($FAIL+1))
wait $CLIENT_PID_TWO || FAIL=$(($FAIL+1))

# kill the services
kill $PID_SERVICE_TWO
kill $PID_SERVICE_ONE
sleep 1


cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Running second test
*******************************************************************************
*******************************************************************************
End-of-message

# Rejecting offer of service instance whose hosting application is still
# alive with daemon:
# * start daemon (needed as he has to ping the offering client)
# * start application which offers service
# * start two clients which continuously exchanges messages with the service
# * start application which offers the same service again -> should be
#   rejected and an error message should be printed.
# * Message exchange with client application should not be interrupted.

export VSOMEIP_CONFIGURATION=offer_test_local.json
# start daemon
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

# Start the services
./offer_test_service 2 &
PID_SERVICE_TWO=$!
./offer_test_client SUBSCRIBE &
CLIENT_PID_ONE=$!
./offer_test_client SUBSCRIBE &
CLIENT_PID_TWO=$!

./offer_test_service 3 &
PID_SERVICE_THREE=$!

# Wait until all clients are finished
# Fail gets incremented if a client exits with a non-zero exit code
wait $CLIENT_PID_ONE || FAIL=$(($FAIL+1))
wait $CLIENT_PID_TWO || FAIL=$(($FAIL+1))

# kill the services
kill $PID_SERVICE_THREE
kill $PID_SERVICE_TWO
sleep 1
kill $PID_VSOMEIPD
sleep 1


cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Running third test
*******************************************************************************
*******************************************************************************
End-of-message

# Accepting offer of service instance whose hosting application crashed
# with (send SIGKILL)
# * start daemon
# * start application which offers service
# * start client which exchanges messages with the service
# * kill application with SIGKILL
# * start application which offers the same service again -> should be
#   accepted.
# * start another client which exchanges messages with the service
# * Client should now communicate with new offerer.

export VSOMEIP_CONFIGURATION=offer_test_local.json
# start daemon
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!
# Start the service
./offer_test_service 2 &
PID_SERVICE_TWO=$!

# Start a client
./offer_test_client METHODCALL &
CLIENT_PID_ONE=$!

# Kill the service
sleep 1
kill -KILL $PID_SERVICE_TWO

# reoffer the service
./offer_test_service 3 &
PID_SERVICE_THREE=$!

# Start another client
./offer_test_client METHODCALL &
CLIENT_PID_TWO=$!

# Wait until all clients are finished
# Fail gets incremented if a client exits with a non-zero exit code
wait $CLIENT_PID_ONE || FAIL=$(($FAIL+1))
wait $CLIENT_PID_TWO || FAIL=$(($FAIL+1))

# kill the services
kill $PID_SERVICE_THREE
kill $PID_VSOMEIPD
sleep 1

cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Running fourth test
*******************************************************************************
*******************************************************************************
End-of-message

# Accepting offer of service instance whose hosting application became
# unresponsive (SIGSTOP)
# * start daemon
# * start application which offers service
# * Send a SIGSTOP to the service to make it unresponsive
# * start application which offers the same service again -> should be
#   marked as PENDING_OFFER and a ping should be sent to the paused
#   application.
# * After the timeout passed the new offer should be accepted.
# * start client which exchanges messages with the service
# * Client should now communicate with new offerer.

export VSOMEIP_CONFIGURATION=offer_test_local.json
# start daemon
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!
# Start the service
./offer_test_service 2 &
PID_SERVICE_TWO=$!

# Start a client
./offer_test_client METHODCALL &
CLIENT_PID_ONE=$!

# Pause the service
sleep 1
kill -STOP $PID_SERVICE_TWO

# reoffer the service
./offer_test_service 3 &
PID_SERVICE_THREE=$!

# Start another client
./offer_test_client METHODCALL &
CLIENT_PID_TWO=$!

# Wait until all clients are finished
# Fail gets incremented if a client exits with a non-zero exit code
wait $CLIENT_PID_ONE || FAIL=$(($FAIL+1))
wait $CLIENT_PID_TWO || FAIL=$(($FAIL+1))

# kill the services
kill -CONT $PID_SERVICE_TWO
kill $PID_SERVICE_TWO
kill $PID_SERVICE_THREE
kill $PID_VSOMEIPD
sleep 1

cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Running fifth test
*******************************************************************************
*******************************************************************************
End-of-message

# Rejecting offers for which there is already a pending offer
# * start daemon
# * start application which offers service
# * Send a SIGSTOP to the service to make it unresponsive
# * start application which offers the same service again -> should be
#   marked as PENDING_OFFER and a ping should be sent to the paused
#   application.
# * start application which offers the same service again -> should be
#   rejected as there is already a PENDING_OFFER pending.
# * After the timeout passed the new offer should be accepted.
# * start client which exchanges messages with the service
# * Client should now communicate with new offerer.

export VSOMEIP_CONFIGURATION=offer_test_local.json
# start daemon
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!
# Start the service
./offer_test_service 2 &
PID_SERVICE_TWO=$!

# Start a client
./offer_test_client METHODCALL &
CLIENT_PID_ONE=$!

# Pause the service
sleep 1
kill -STOP $PID_SERVICE_TWO

# reoffer the service
./offer_test_service 3 &
PID_SERVICE_THREE=$!

# reoffer the service again to provoke rejecting as there is
# already a pending offer
./offer_test_service 4 &
PID_SERVICE_FOUR=$!

# Start another client
./offer_test_client METHODCALL &
CLIENT_PID_TWO=$!

# Wait until all clients are finished
# Fail gets incremented if a client exits with a non-zero exit code
wait $CLIENT_PID_ONE || FAIL=$(($FAIL+1))
wait $CLIENT_PID_TWO || FAIL=$(($FAIL+1))

# kill the services
kill -CONT $PID_SERVICE_TWO
kill $PID_SERVICE_TWO
kill $PID_SERVICE_THREE
kill $PID_SERVICE_FOUR
kill $PID_VSOMEIPD


# Check if everything went well
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
