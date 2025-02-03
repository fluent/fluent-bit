Configuration Test
------------------
To start the configuration test from the build directory do:

./configuration-test -someip ../config/vsomeip-test.json

The expected output is:

2015-02-10 08:47:31.503874 [info] Test "HOST ADDRESS" succeeded.
2015-02-10 08:47:31.507609 [info] Test "HAS CONSOLE" succeeded.
2015-02-10 08:47:31.507865 [info] Test "HAS FILE" succeeded.
2015-02-10 08:47:31.508001 [info] Test "HAS DLT" succeeded.
2015-02-10 08:47:31.508143 [info] Test "LOGFILE" succeeded.
2015-02-10 08:47:31.508315 [info] Test "LOGLEVEL" succeeded.
2015-02-10 08:47:31.508456 [info] Test "RELIABLE_TEST_1234_0022" succeeded.
2015-02-10 08:47:31.508593 [info] Test "UNRELIABLE_TEST_1234_0022" succeeded.
2015-02-10 08:47:31.508759 [info] Test "RELIABLE_TEST_1234_0023" succeeded.
2015-02-10 08:47:31.508896 [info] Test "UNRELIABLE_TEST_1234_0023" succeeded.
2015-02-10 08:47:31.509032 [info] Test "RELIABLE_TEST_2277_0022" succeeded.
2015-02-10 08:47:31.509185 [info] Test "UNRELIABLE_TEST_2277_0022" succeeded.
2015-02-10 08:47:31.509330 [info] Test "RELIABLE_TEST_4466_0321" succeeded.
2015-02-10 08:47:31.509467 [info] Test "UNRELIABLE_TEST_4466_0321" succeeded.
2015-02-10 08:47:31.509602 [info] Test "RELIABLE_TEST_2277_0022" succeeded.
2015-02-10 08:47:31.509771 [info] Test "UNRELIABLE_TEST_2277_0022" succeeded.
2015-02-10 08:47:31.509915 [info] Test "ADDRESS_TEST_1234_0022" succeeded.
2015-02-10 08:47:31.510049 [info] Test "MIN_INITIAL_DELAY_TEST_1234_0022" succeeded.
2015-02-10 08:47:31.510354 [info] Test "MAX_INITIAL_DELAY_TEST_1234_0022" succeeded.
2015-02-10 08:47:31.510610 [info] Test "REPETITION_BASE_DELAY_TEST_1234_0022" succeeded.
2015-02-10 08:47:31.513978 [info] Test "REPETITION_MAX_TEST_1234_0022" succeeded.
2015-02-10 08:47:31.514177 [info] Test "CYCLIC_OFFER_DELAY_TEST_1234_0022" succeeded.
2015-02-10 08:47:31.514280 [info] Test "CYCLIC_REQUEST_DELAY_TEST_1234_0022" succeeded.
2015-02-10 08:47:31.514397 [info] Test "MIN_INITIAL_DELAY_TEST_1234_0023" succeeded.
2015-02-10 08:47:31.514618 [info] Test "MAX_INITIAL_DELAY_TEST_1234_0023" succeeded.
2015-02-10 08:47:31.514754 [info] Test "REPETITION_BASE_DELAY_TEST_1234_0023" succeeded.
2015-02-10 08:47:31.514901 [info] Test "REPETITION_MAX_TEST_1234_0023" succeeded.
2015-02-10 08:47:31.515052 [info] Test "CYCLIC_OFFER_DELAY_TEST_1234_0023" succeeded.
2015-02-10 08:47:31.515186 [info] Test "CYCLIC_REQUEST_DELAY_TEST_1234_0023" succeeded.
2015-02-10 08:47:31.515325 [info] Test "MIN_INITIAL_DELAY_TEST_2277_0022" succeeded.
2015-02-10 08:47:31.515395 [info] Test "MAX_INITIAL_DELAY_TEST_2277_0022" succeeded.
2015-02-10 08:47:31.515536 [info] Test "REPETITION_BASE_DELAY_TEST_2277_0022" succeeded.
2015-02-10 08:47:31.515691 [info] Test "REPETITION_MAX_TEST_2277_0022" succeeded.
2015-02-10 08:47:31.515834 [info] Test "CYCLIC_OFFER_DELAY_TEST_2277_0022" succeeded.
2015-02-10 08:47:31.515971 [info] Test "CYCLIC_REQUEST_DELAY_TEST_2277_0022" succeeded.
2015-02-10 08:47:31.516109 [info] Test "MIN_INITIAL_DELAY_TEST_2266_0022" succeeded.
2015-02-10 08:47:31.516279 [info] Test "MAX_INITIAL_DELAY_TEST_2266_0022" succeeded.
2015-02-10 08:47:31.516380 [info] Test "REPETITION_BASE_DELAY_TEST_2266_0022" succeeded.
2015-02-10 08:47:31.516512 [info] Test "REPETITION_MAX_TEST_2266_0022" succeeded.
2015-02-10 08:47:31.516610 [info] Test "CYCLIC_OFFER_DELAY_TEST_2266_0022" succeeded.
2015-02-10 08:47:31.516736 [info] Test "CYCLIC_REQUEST_DELAY_TEST_2266_0022" succeeded.
2015-02-10 08:47:31.516874 [info] Test "ADDRESS_TEST_4466_0321" succeeded.
2015-02-10 08:47:31.516974 [info] Test "SERVICE DISCOVERY PROTOCOL" succeeded.
2015-02-10 08:47:31.517106 [info] Test "SERVICE DISCOVERY PORT" succeeded.


Application test
----------------

This test tests starting and stopping a vsomeip application in various ways.

Automatic start from build directory:

ctest -V -R application_test

Manual start from sub folder test of build directory:

./application_test_starter.sh


Magic Cookies Test
------------------
To run the magic cookies test you need two devices on the same network. The network addresses within
the configuration files need to be adapted to match the devices addresses. 

To start the magic-cookies-test from the build-directory do:

Automatic start from build directory:

ctest -V -R magic_cookies_test

Manual start from sub folder test of build directory:

# On external host run
./magic_cookies_test_service_start.sh

# On local host run
./magic_cookies_test_client_start.sh


The expected result is an output like this on service side:

2015-02-10 08:42:07.317695 [info] Received a message with Client/Session [1343/0001]
2015-02-10 08:42:07.360105 [error] Detected Magic Cookie within message data. Resyncing.
2015-02-10 08:42:07.360298 [info] Received a message with Client/Session [1343/0003]
2015-02-10 08:42:07.360527 [error] Detected Magic Cookie within message data. Resyncing.
2015-02-10 08:42:07.360621 [error] Detected Magic Cookie within message data. Resyncing.
2015-02-10 08:42:07.360714 [info] Received a message with Client/Session [1343/0006]
2015-02-10 08:42:07.360850 [info] Received a message with Client/Session [1343/0007]
2015-02-10 08:42:07.361021 [error] Detected Magic Cookie within message data. Resyncing.
2015-02-10 08:42:07.361107 [error] Detected Magic Cookie within message data. Resyncing.
2015-02-10 08:42:07.361191 [error] Detected Magic Cookie within message data. Resyncing.
2015-02-10 08:42:07.361276 [info] Received a message with Client/Session [1343/000b]
2015-02-10 08:42:07.361434 [info] Received a message with Client/Session [1343/000c]
2015-02-10 08:42:07.361558 [info] Received a message with Client/Session [1343/000d]
2015-02-10 08:42:07.361672 [error] Detected Magic Cookie within message data. Resyncing.
2015-02-10 08:42:07.361761 [info] Received a message with Client/Session [1343/000f]

Header Factory Tests
--------------------

The following things are tested:
a) create request
    --> check  "Protocol Version" / "Message Type" / "Return Type" fields
b) create request, fill header, create response
    --> compare header fields of request & response
c) create notification
    --> check  "Protocol Version" / "Message Type" / "Return Type" fields
d) create message, fill header (service/instance/method/interface version/message type)
    --> send message 10 times
    --> receive message and check client id / session id

a) to c) are combined in one binary. d) is composed out of a client and service.

To start the header factory tests from the build directory do:

Automatic start from build directory:
ctest -V -R header_factory_test

Manual start from build directory:
cd test
./header_factory_test
# Start client and service separately
./header_factory_test_service_start.sh &
./header_factory_test_client_start.sh
# Alternatively start client and service with one script
./header_factory_test_send_receive_starter.sh

All tests should be marked as "passed".

Routing Tests
-------------

The following things are tested:
a) create a service instance
    - check that it is accessible from a local client but invisible for an external client
b) create a service instance, configure it to be externally visible
    - check that it is accessible from a local client and from a external client

a) and b) are composed out of a service each and one common client binary which is used
with different configuration files.

Automatic start from build directory:

ctest -V -R local_routing_test

A message will be shown when the external client should be started.

Manual start from build directory:
cd test
# First part with local client
# Start client and service with one script
./local_routing_test_starter.sh

# Alternatively start client and service separately
# Warning some checks are done within the *_starter.sh script.
# This should only be used for debugging
# Start the service
./local_routing_test_service_start.sh &
# Start the client
./local_routing_test_client_start.sh

# Second part with external client
# Start client and service with one script
./external_local_routing_test_starter.sh
# Start the external client from an external host when the message is displayed to start it
./external_local_routing_test_client_external_start.sh

# Alternatively start client and service separately
# Warning some checks are done within the *_starter.sh script.
# This should only be used for debugging
# Start the service
./external_local_routing_test_service_start.sh &
# Start the client
./local_routing_test_client_start.sh
# Start the external client from an external host after local client has finished
./external_local_routing_test_client_external_start.sh


All tests should be marked as "passed".

Payload Tests
-------------

The following things are tested:
a) create a local service
    - send messages with payloads of different size from a local client to the service
    - check that the messages are received correctly
    - measure the throughput
b) create a service instance, configure it to be externally visible
    - send messages with payloads of different size from a local client to the service
    - check that the messages are received correctly
    - measure the throughput
c) create a service instance, configure it to be externally visible
    - send messages with payloads of different size from an external client to the service
    - check that the messages are received correctly
    - measure the throughput
d) create a service instance, configure it to be externally visible
    - send messages with payloads of different size from a local client to the service
    - send messages with payloads of different size from an external client to the service
    - check that the messages are received correctly
    - measure the throughput

The tests a) to d) are composed out of a service and a client binary which are called
with different configuration files and parameters.

Automatic start from build directory:

ctest -V -R payload_test

A message will be shown when the external clients should be started.

Manual start from build directory:
cd test

# First part with local client
# start client and service with one script
./local_payload_test_starter.sh

# Alternatively start client and service separately
# Warning some checks are done within the *_starter.sh script.
# This should only be used for debugging
./local_payload_test_service_start.sh &
./local_payload_test_client_start.sh

# Second part with external visible service and local client
# start client and service with one script
./external_local_payload_test_client_local_starter.sh

# Alternatively start client and service separately
# Warning some checks are done within the *_starter.sh script.
# This should only be used for debugging
./external_local_payload_test_service_start.sh &
./external_local_payload_test_client_local_start.sh

# Third part with external visible service and external client
# start client and service with one script
./external_local_payload_test_client_external_starter.sh
# Start the external client from an external host if asked to
./external_local_payload_test_client_external_start.sh

# Alternatively start client and service separately
# Warning some checks are done within the *_starter.sh script.
# This should only be used for debugging
./external_local_payload_test_service_client_external_start.sh
# Start the external client from an external host
./external_local_payload_test_client_external_start.sh

# Fourth part with external visible service and local and external client
# start client and service with one script
./external_local_payload_test_client_local_and_external_starter.sh
# Start the external client from an external host if asked to
./external_local_payload_test_client_external_start.sh

# Alternatively start client and service separately
# Warning some checks are done within the *_starter.sh script.
# This should only be used for debugging
./external_local_payload_test_service_client_external_start.sh &
# Start the local client
VSOMEIP_APPLICATION_NAME=external_local_payload_test_client_local \
VSOMEIP_CONFIGURATION=external_local_payload_test_client_local.json \
./payload_test_client --dont-shutdown-service
# Start the external client after the local client is finished from an
# external host
./external_local_payload_test_client_external_start.sh

All tests should be marked as "passed".


Big payload tests
-----------------

This test tests the possibility to sent messages with bigger payloads
for local and TCP communication.

The test will send a messages with 600k payload from a client to a service.
The service will reply with a response containing 600k payload as well.
This is repeated 10 times.
There is a version for local and for TCP communication available.
Additionally there are test versions available which sent up to 10MiB big
messages and a version which tests the limitiation of message sizes configurable
via json file.

Automatic start from the build directory:

ctest -V -R big_payload_test_local

Manual start from sub folder test of build directory:

./big_payload_test_service_local_start.sh &
./big_payload_test_client_local_start.sh


Automatic start of the TCP version from the build directory:

ctest -V -R big_payload_test_external

Manual start from sub folder test of build directory:

./big_payload_test_client_start.sh

# On external host run
./big_payload_test_service_external_start.sh


Client ID tests
---------------

This tests tests communication over two nodes with multiple services on both
nodes.

The test setup is as followed:
* There are six services with one method each.
* Three of the services run on node 1.
* Three of the services run on node 2.
* Each of the services sends ten requests to the other services and waits
  until it received a response for every request.
* If all responses have been received, the service shutdown.

Automatic start from the build directory:

ctest -V -R client_id_test_diff_client_ids_diff_ports

Manual start from sub folder test of build directory:

./client_id_test_master_starter.sh client_id_test_diff_client_ids_diff_ports_master.json

Second version where all services on one node use the same port:

Automatic start from the build directory:

ctest -V -R client_id_test_diff_client_ids_same_ports

Manual start from sub folder test of build directory:

./client_id_test_master_starter.sh client_id_test_diff_client_ids_same_ports_master.json


Subscribe notify tests
----------------------
This tests tests subscribe notify mechanism over two nodes with multiple services
on both nodes.

The test setup is as followed:
* There are six services offering one event each.
* Three of the services run on node 1.
* Three of the services run on node 2.
* Each of the services waits until all other services are available.
* Each of the services subscribes to the offered event of all the other services.
* Each of the services then waits until the other services have subscribed to
  its event.
* Each of the services then starts to sent out ten notifications for its event.
* Each service waits until it received the correct amount of notifications from
  all other services.
* If all notifications have been received, the service shuts down.

Automatic start from the build directory (example):

ctest -V -R subscribe_notify_test_diff_client_ids_diff_ports_udp

Manual start from sub folder test of build directory:

./subscribe_notify_test_master_starter.sh UDP subscribe_notify_test_diff_client_ids_diff_ports_master.json

There are multiple versions of this test which differ in the used subscription
method and port setup (use ctest -N to see all). For manual start the desired
description method has to be passed to the starter script as first parameter.

The subscribe_notify_test_one_event_two_eventgroups_* tests are testing the
requirement that for events which are member of multiple eventgroups initial
events shall be sent per eventgroup. However normal updates of the event should
be sent only once even if a remote subscriber is subscribed to multiple of the
event's eventgroups (TR_SOMEIP_00570).


CPU load test
-------------
This test does a increasing number of synchronous function calls to the same
method of the service and measures CPU load for each batch of function calls.
All method calls transport a payload of 40 Bytes. The responses don't transport
any payload.

The CPU load is measured thorugh the proc fs.
If the test prints a message like:

    Synchronously sent 0890 messages. CPU load [%]: 12.68

This means that the test process consumed 12% of the jiffies consumed by
complete system while doing 890 methodcalls.

Automatic start from the build directory (example):

ctest -V -R cpu_load_test


Initial event tests
----------------------
This tests tests initial event mechanism over two nodes with multiple services
on both nodes.

The test setup is as followed:
* There are six services offering one event each.
* Three of the services run on node 1.
* Three of the services run on node 2.
* All of the services initially set their event to their service id and notify
  once
* On each node there are 20 client applications which subscribe to all of the
  services events which are started at different times
* Each client waits until it received one notification (the initial one) from
  all services and then exits.
* If all clients exited, the services are killed as well

Automatic start from the build directory (example):

ctest -V -R initial_event_test_diff_client_ids_diff_ports_udp

Manual start from sub folder test of build directory:
./initial_event_test_master_starter.sh UDP initial_event_test_diff_client_ids_diff_ports_master.json

There are multiple versions of this test which differ in the used subscription
method and port setup (use ctest -N to see all). For manual start the desired
description method has to be passed to the starter script as first parameter.

Offer tests
-----------
This tests test various cases of offering a service and error recovery
after an application became unresponsive

* Rejecting offer of service instance whose hosting application is
  still alive.
* Rejecting offer of service instance whose hosting application is
  still alive with daemon
* Accepting offer of service instance whose hosting application
  crashed with (send SIGKILL)
* Accepting offer of service instance whose hosting application became
  unresponsive (SIGSTOP)
* Rejecting offers for which there is already a pending offer
* Rejecting remote offer for which there is already a local offer
* Rejecting a local offer for which there is already a remote offer

Automatic start from the build directory (example):

ctest -V -R offer_tests

Manual start from sub folder test of build directory:
./offer_test_local_starter
./offer_test_external_master_starter.sh

Tests in detail:
Rejecting offer of service instance whose hosting application is still
alive:
* start application which offers service
* start client which continuously exchanges messages with the service
* start application which offers the same service again -> should be
  rejected and an error message should be printed.
* Message exchange with client application should not be interrupted.

Rejecting offer of service instance whose hosting application is still
alive with daemon
* start daemon (needed as he has to ping the offering client)
* start application which offers service
* start client which continuously exchanges messages with the service
* start application which offers the same service again -> should be
  rejected and an error message should be printed.
* Message exchange with client application should not be interrupted.

Accepting offer of service instance whose hosting application crashed
with (send SIGKILL)
* start daemon
* start application which offers service
* start client which exchanges messages with the service
* kill application with SIGKILL
* start application which offers the same service again -> should be
  accepted.
* start another client which exchanges messages with the service
* Client should now communicate with new offerer.

Accepting offer of service instance whose hosting application became
unresponsive (SIGSTOP)
* start daemon
* start application which offers service
* Send a SIGSTOP to the service to make it unresponsive
* start application which offers the same service again -> should be
  marked as PENDING_OFFER and a ping should be sent to the paused
  application.
* After the timeout passed the new offer should be accepted.
* start client which exchanges messages with the service
* Client should now communicate with new offerer.

Rejecting offers for which there is already a pending offer
* start daemon
* start application which offers service
* Send a SIGSTOP to the service to make it unresponsive
* start application which offers the same service again -> should be
  marked as PENDING_OFFER and a ping should be sent to the paused
  application.
* start application which offers the same service again -> should be
  rejected as there is already a PENDING_OFFER pending.
* After the timeout passed the new offer should be accepted.
* start client which exchanges messages with the service
* Client should now communicate with new offerer.

Rejecting a local offer for which there is already a remote offer:
* start daemon
* start application which offers service
* start daemon remotely
* start same application which offers the same service again remotely
  -> should be rejected as there is already a service instance
  running in the network

Rejecting remote offer for which there is already a local offer
* start application which offers service
* send SD message trying to offer the same service instance as already
  offered locally from a remote host -> should be rejected

nPDU tests
-----------------

This test is intended to test the functionality of the so called nPDU
feature. The test setup is as followed:

* There are two nodes, one hosting the services, one hosting the clients.
* On each of the nodes is a routing manager daemon (RMD) started whose only
  purpose is to provide routing manager functionality and shutdown the clients
  and services at the end.
* There are four services created. Each of the services has four methods.
* All services are listening on the same port. Therefore there only is:
    * one server endpoint created in the RMD on service side
    * one client endpoint created in the RMD on client side
* There are four clients created. Each of the clients will:
    * Create a thread for each service
    * Create a thread for each method of each service
    * Send multiple messages with increasing payload to each of the services'
      methods from the corresponding thread.
    * After sending the threads will sleep the correct amount of time to insure
      applicative debounce > debounce time + max retention time.
* After all messages have been sent to the services the clients will notify the
  RMD that they're finished. The RMD then instructs the RMD on service side to
  shutdown the services and exit afterwards. After that the RMD on client side
  exits as well.
* Upon receiving a method call the service will check if the debounce time
  specified in the json file for this method was undershot and print out a
  warning.
* The test first runs in synchronous mode and waits for a response of the
  service before sending the next message.
* After that the test runs in a mode where no response from the service are
  required (message type REQUEST_NO_RETURN) thus the clients send at maximum
  allowed frequency.

Automatic start from build directory:

ctest -V -R npdu_test_UDP
ctest -V -R npdu_test_TCP

A message will be shown when the external clients should be started.

Manual start:
# Service side
./npdu_test_service_npdu_start.sh

# Client side UDP mode
./npdu_test_client_npdu_start.sh UDP

# Client side TCP mode
./npdu_test_client_npdu_start.sh TCP
