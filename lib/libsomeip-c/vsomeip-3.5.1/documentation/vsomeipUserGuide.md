# Legal notice

## Copyright
Copyright (C) 2015-2024, Bayerische Motoren Werke Aktiengesellschaft (BMW AG)

## License

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

## Version

This documentation was generated for version 3.5 of vSomeIP.

# vSomeIP Overview

The vSomeIP stack implements the http://some-ip.com/[Scalable service-Oriented
MiddlewarE over IP (SOME/IP)] protocol. The stack consists out of:

* a shared library for SOME/IP (`libvsomeip.so`)
* a second shared library for SOME/IP's service discovery (`libvsomeip-sd.so`)
  which is loaded during runtime if the service discovery is enabled.

# Build Instructions

## Dependencies

* A C++17 enabled compiler is needed
* vSomeIP uses cmake as buildsystem.
* vSomeIP uses Boost >= 1.66:
    * Ubuntu 22.04:
        * `sudo apt-get install libboost-system1.74-dev libboost-thread1.74-dev libboost-log1.74-dev`
* For the tests Google's test framework
    https://github.com/google/googletest/releases
* To build the documentation doxygen and graphviz are needed:
    * `sudo apt-get install doxygen graphviz`

## Compilation

For compilation call:

```bash
mkdir build
cd build
cmake ..
make
```

To specify a installation directory (like `--prefix=` if you're used to
autotools) call cmake like:

```bash
cmake -DCMAKE_INSTALL_PREFIX:PATH=$YOUR_PATH ..
make
make install
```

### Compilation with predefined base path

To predefine the base path, the path that is used to create the local sockets,
call cmake like:

```bash
cmake -DBASE_PATH=<YOUR BASE PATH> ..
```

The default base path is /tmp.

### Compilation with predefined unicast and/or diagnosis address

To predefine the unicast address, call cmake like:

```bash
cmake -DUNICAST_ADDRESS=<YOUR IP ADDRESS> ..
```

To predefine the diagnosis address, call cmake like:

```bash
cmake -DDIAGNOSIS_ADDRESS=<YOUR DIAGNOSIS ADDRESS> ..
```

The diagnosis address is a single byte value.

### Compilation with custom default configuration folder

To change the default configuration folder, call cmake like:

```bash
cmake -DDEFAULT_CONFIGURATION_FOLDER=<DEFAULT CONFIGURATION FOLDER> ..
```

The default configuration folder is /etc/vsomeip.

### Compilation with custom default configuration file

To change the default configuration file, call cmake like:

```bash
cmake -DDEFAULT_CONFIGURATION_FILE=<DEFAULT CONFIGURATION FILE> ..
```

The default configuration file is /etc/vsomeip.json.

### Compilation with changed (maximimum) wait times for local TCP ports

If local communication is done via TCP, we depend on the availability
of the network. Therefore, server port creation and therefore port
assignment might fail. If the failure is causes by the port already
being in use, we use the next available port. For all other failure,
we wait for a wait time until we retry with the same port. If the
overall wait time of all retries exceeds the maximum wait time,
the endpoint creation is aborted. To configure wait time and maximum
wait time, call cmake with:

```bash
cmake -DLOCAL_TCP_PORT_WAIT_TIME=50 -DLOCAL_TCP_PORT_MAX_WAIT_TIME=2000 ..
```

The default values are a wait time of 100ms and a maximum wait time of 10000ms.
These configurations have no effect if local communication uses UDS (default).

### Compilation with signal handling

To compile vsomeip with signal handling (SIGINT/SIGTERM) enabled,
call cmake like:

```bash
cmake -DENABLE_SIGNAL_HANDLING=1 ..
```

In the default setting, the application has to take care of shutting
down vsomeip in case these signals are received.

### Compilation with user defined "READY" message

To compile vsomeip with a user defined message signal the IP routing
to be ready to send/receive messages, call cmake like:

```bash
cmake -DROUTING_READY_MESSAGE=<YOUR MESSAGE> ..
```


### Compilation with vSomeIP 2 compatibility layer

To compile vsomeip with enabled vSomeIP 2 compatibility layer, call
cmake like:

```bash
cmake -DENABLE_COMPAT=1 ..
```

### Compilation of examples

For compilation of the examples call:

```bash
mkdir build
cd build
cmake ..
make examples
```

### Compilation of tests

To compile the tests, first unzip gtest to location of your desire.
Some of the tests require a second node on the same network. There are two cmake
variables which are used to automatically adapt the json files to the used
network setup:

* `TEST_IP_MASTER`: The IP address of the interface which will act as test
  master.
* `TEST_IP_SLAVE`: The IP address of the interface of the second node which will
  act as test slave.

If one of this variables isn't specified, only the tests using local
communication exclusively will be runnable.

Additionally the unit tests require enabled signal handling which can be enabled
via the `ENABLE_SIGNAL_HANDLING` cmake variable.

Example, compilation of tests:

```bash
mkdir build
cd build
export GTEST_ROOT=$PATH_TO_GTEST/gtest-1.7.0/
cmake -DENABLE_SIGNAL_HANDLING=1 -DTEST_IP_MASTER=10.0.3.1 -DTEST_IP_SLAVE=10.0.3.125 ..
make check
```

Additional make targets for the tests:

* Call `make build_tests` to only compile the tests
* Call `ctest` in the build directory to execute the tests without a verbose
  output
* To run single tests call `ctest --verbose --tests-regex $TESTNAME` short
  form: `ctest -V -R $TESTNAME`
* To list all available tests run `ctest -N`.
* For further information about the tests please have a look at the
  `readme.txt` in the `test` subdirectory.

For development purposes two cmake variables exist which control if the
json files and test scripts are copied (default) or symlinked into the build
directory. These settings are ignored on Windows.

* `TEST_SYMLINK_CONFIG_FILES`: Controls if the json and scripts needed
  to run the tests are copied or symlinked into the build directory. (Default:
  OFF, ignored on Windows)
* `TEST_SYMLINK_CONFIG_FILES_RELATIVE`: Controls if the json and scripts needed
  to run the tests are symlinked relatively into the build directory.
  (Default: OFF, ignored on Windows)

Example cmake call:

```bash
cmake  -DTEST_SYMLINK_CONFIG_FILES=ON -DTEST_SYMLINK_CONFIG_FILES_RELATIVE=ON ..
```

For compilation of only a subset of tests (for a quick
functionality check) the cmake variable `TESTS_BAT` has
to be set:

Example cmake call:
```bash
cmake  -DTESTS_BAT=ON ..
```

### Compilation of vsomeip_ctrl

For compilation of the [vsomeip_ctrl](#vsomeip_ctrl) utility call:

```bash
mkdir build
cd build
cmake ..
make vsomeip_ctrl
```

### Generating the documentation

To generate the documentation call cmake as described in [Compilation](#compilation) and
then call `make doc`.
This will generate:

* The README file in html: `$BUILDDIR/documentation/README.html`
* A doxygen documentation in `$BUILDDIR/documentation/html/index.html`

# Starting vsomeip Applications / Used environment variables

On startup the following environment variables are read out:

* `VSOMEIP_APPLICATION_NAME`: This environment variable is used to specify the
  name of the application. This name is later used to map a client id to the
  application in the configuration file. It is independent from the
  application's binary name.
* `VSOMEIP_CONFIGURATION`: vsomeip uses the default configuration file `/etc/vsomeip.json`
   and/or the default configuration folder `/etc/vsomeip`. This can be overridden by a
   local configuration file `./vsomeip.json` and/or a local configuration folder `./vsomeip`.
   If `VSOMEIP_CONFIGURATION` is set to a valid file or directory path, this is used instead
   of the standard configuration (thus neither default nor local file/folder will be parsed).
* `VSOMEIP_CONFIGURATION_<application>`: Application-specific version of `VSOMEIP_CONFIGURATION`.
   Please note that <application> must be valid as part of an environment variable.
* `VSOMEIP_MANDATORY_CONFIGURATION_FILES`: vsomeip allows to specify mandatory configuration
   files to speed-up application startup. While mandatory configuration files are read by all
   applications, all other configuration files are only read by the application that is
   responsible for connections to external devices. If this configuration variable is not set,
   the default mandatory files vsomeip_std.json, vsomeip_app.json and vsomeip_plc.json are used.
* `VSOMEIP_CLIENTSIDELOGGING`: Set this variable to an empty string to enable logging of
   any received messages to DLT in all applications acting as routing manager proxies. For
   example add the following line to the  application's systemd service file:
   `Environment=VSOMEIP_CLIENTSIDELOGGING=""`
   To enable service-specific logs, provide a space- or colon-separated list of ServiceIDs (using
   4-digit hexadecimal notation, optionally followed by dot-separted InstanceID). For example:
   `Environment=VSOMEIP_CLIENTSIDELOGGING="b003.0001 f013.000a 1001 1002"`
   `Environment=VSOMEIP_CLIENTSIDELOGGING="b003.0001:f013.000a:1001:1002"`

NOTE: If the file/folder that is configured by `VSOMEIP_CONFIGURATION` does _not_ exist,
the default configuration locations will be used.

NOTE: vsomeip will parse and use the configuration from all files in a configuration folder
but will _not_ consider directories within the configuration folder.

In the following example the application `my_vsomeip_application` is started.
The settings are read from the file `my_settings.json` in the current working
directory. The client id for the application can be found under the name
`my_vsomeip_client` in the configuration file.

```bash
#!/bin/bash
export VSOMEIP_APPLICATION_NAME=my_vsomeip_client
export VSOMEIP_CONFIGURATION=my_settings.json
./my_vsomeip_application
```

# Configuration File Structure

The configuration files for vsomeip are [JSON](http://www.json.org)-Files and are
composed out of multiple key value pairs and arrays.

> * An object is an unordered set of name/value pairs. An object begins with `{
> (left brace)` and ends with `} (right brace)`. Each name is followed by `:
> (colon)` and the name/value pairs are separated by `, (comma)`.
>
> * An array is an ordered collection of values. An array begins with `[ (left
> bracket)` and ends with `] (right bracket)`. Values are separated by `,
> (comma)`.
>
> * A value can be a _string_ in double quotes, or a _number_, or `true` or `false`
> or `null`, or an _object_ or an _array_. These structures can be nested.

Configuration file element explanation:

* 'unicast'

    The IP address of the host system.

* 'netmask'

    The netmask to specify the subnet of the host system.

* 'device' (optional)

    If specified, IP endpoints will be bound to this device.

* 'diagnosis'

    The diagnosis address (byte) that will be used to build client identifiers. The
    diagnosis address is assigned to the most significant byte in all client
    identifiers if not specified otherwise (for example through a predefined client
    ID).

* 'diagnosis_mask'

    The diagnosis mask (2 byte) is used to control the maximum amount of allowed
    concurrent vsomeip clients on an ECU and the start value of the client IDs.

    The default value is `0xFF00` meaning
    the most significant byte of the client ID is reserved for the diagnosis
    address and the client IDs will start with the diagnosis address as specified.
    The maximum number of clients is 255 as the Hamming weight of the inverted mask
    is 8 (2^8 = 256 - 1 (for the routing manager) = 255). The resulting client ID
    range with a diagnosis address of for example 0x45 would be 0x4501 to 0x45ff.

    Setting the mask to `0xFE00` doubles client ID range to 511 clients as the
    Hamming weight of the inverted mask is greater by one.  With a diagnosis address
    of 0x45 the start value of client IDs is 0x4401 as bit 8 in 0x4500 is masked
    out. This then yields a client ID range of 0x4400 to 0x45ff.

* 'network'
    Network identifier used to support multiple routing managers on one host. This
    setting changes the name of the shared memory segment in `/dev/shm` and the name
    of the unix domain sockets in `/tmp/`. Defaults to `vsomeip` meaning the shared
    memory will be named `/dev/shm/vsomeip` and the unix domain sockets will be
    named `/tmp/vsomeip-$CLIENTID`

* 'logging'
    * 'level'

        Specifies the log level (valid values: _trace_, _debug_, _info_, _warning_,
        _error_, _fatal_).

    * 'console'

        Specifies whether logging via console is enabled (valid values: _true, false_).

    * 'file'

        * 'enable'

            Specifies whether a log file should be created (valid values: _true, false_).
        * 'path'

            The absolute path of the log file.

    * 'dlt'

        Specifies whether Diagnostic Log and Trace (DLT) is enabled (valid values:
        _true, false_).

    * 'version'

        Configures logging of the vsomeip version

        * 'enable'

            Enable or disable cyclic logging of vsomeip version, defaults to true (valid
            values: _true, false_)

        * 'interval'

            Configures interval in seconds to log the vsomeip version. Default value is 10.

    * 'memory_log_interval'

        Configures interval in seconds in which the routing manager logs its used
        memory. Setting a value greater than zero enables the logging.

    * 'status_log_interval'

        Configures interval in seconds in which the routing manager logs its internal
        status. Setting a value greater than zero enables the logging.

* 'tracing' (optional)<a id="tracing-anchor"></a>
    * 'enable'

        Specifies whether the tracing of the SOME/IP messages is enabled
        (valid values: _true, false_). Default value is _false_.
        If tracing is enabled, the messages will be forwarded to DLT by
        the [Trace Connector](#trace-connector)

    * 'sd_enable'

        Specifies whether the tracing of the SOME/IP service discovery messages is
        enabled (valid values: _true, false_). Default value is _false_.

    * 'channels (array)' (optional)

        Contains the channels to DLT.

        NOTE: You can set up multiple channels to DLT over that you can forward the
        messages.

        * 'name'

            The name of the channel.

        * 'id'

            The id of the channel.

    * 'filters (array)' (optional)

        Contains the filters that are applied on the messages.

        NOTE: You can apply filters respectively filter rules on the messages with
        specific criterias and expressions. So only the filtered messages are forwarded
        to DLT.

        * 'channel' (optional)

            The id of the channel over that the filtered messages are forwarded to DLT. If
            no channel is specified the default channel (TC) is used. If you want to use a
            filter in several different channels, you can provide an array of channel ids.

            NOTE: If you use a positive filter with multiple channels, the same message
            will be forwared multiple times to DLT.

        * 'matches' (optional)

            Specification of the criteria to include/exclude a message into/from the trace.
            You can either specify lists (array) or ranges of matching elements.

            A list may contain single identifiers which match all messages from/to all
            instances of the corresponding service or tuples consisting of service-,
            instance- and method-identifier. 'any' may be used as a wildcard for matching
            all services, instances or methods.

            A range is specified by two tuples "from" and "to", each consisting of
            service-, instance-and method-identifier. All messages with service-,
            instance-and method-identifiers that are greater than or equal to "from"
            and less than or equal to "to" are matched.

        * 'type' (optional)

            Specifies the filter type (valid values: "positive", "negative", "header-only"). 
            When a positive filter is used and a message matches one of the filter rules, 
            the message will be traced/forwarded to DLT. With a negative filter messages 
            can be excluded. So when a message matches one of the filter rules, the message 
            will not be traced/forwarded to DLT. Default value is "positive". The value
            "header-only" implies the filter is also considered "positive".

* 'applications (array)'

    Contains the applications of the host system that use this config file.

    * 'name'

        The name of the application.

    * 'id'

        The id of the application. Usually its high byte is equal to the diagnosis address. In this
        case the low byte must be different from zero. Thus, if the diagnosis address is 0x63, valid
        values range from 0x6301 until 0x63FF. It is also possible to use id values with a high byte
        different from the diagnosis address.

    * 'max_dispatchers' (optional)

        The maximum number of threads that shall be used to execute the application callbacks. Default is 10.

    * 'max_dispatch_time' (optional)

        The maximum time in ms that an application callback may consume before the callback is
        considered to be blocked (and an additional thread is used to execute pending
        callbacks if max_dispatchers is configured greater than 0). The default value if not specified is 100ms.

    * 'max_detached_thread_wait_time' (optional)

        The maximum time in seconds that an application will wait for a detached dispatcher thread
        to finish executing. The default value if not specified is 5s.

    * 'threads' (optional)

        The number of internal threads to process messages and events within an application.
        Valid values are 1-255. Default is 2.

    * 'io_thread_nice' (optional)

        The nice level for internal threads processing messages and events. POSIX/Linux only.
        For actual values refer to nice() documentation.

    * 'request_debounce_time' (optional)

        Specifies a debounce-time interval in ms in which request-service messages are sent to
        the routing manager. If an application requests many services in short same time
        the load of sent messages to the routing manager and furthermore the replies from the
        routing manager (which contains the routing info for the requested service if available)
        can be heavily reduced. The default value if not specified is 10ms.

    * 'plugins' (optional array)

        Contains the plug-ins that should be loaded to extend the functionality of vsomeip.

        * 'name'

            The name of the plug-in.

        * 'type'

            The plug-in type (valid values: _application_plugin_).

            An application plug-in extends the functionality on application level. It gets informed
            by vsomeip over the basic application states (INIT/START/STOP) and can, based on these
            notifications, access the standard "application"-API via the runtime.

* `services` (array)

    Contains the services of the service provider.

    * `service`

        The id of the service.

    * `instance`

        The id of the service instance.

    * `protocol` (optional)

        The protocol that is used to implement the service instance. The default setting
        is _someip_. If a different setting is provided, vsomeip does not open the specified
        port (server side) or does not connect to the specified port (client side). Thus,
        this option can be used to let the service discovery announce a service that is
        externally implemented.

    * `unicast` (optional)

        The unicast that hosts the service instance.

        NOTE: The unicast address is needed if external service instances shall be used,
        but service discovery is disabled. In this case, the provided unicast address
        is used to access the service instance.

    * `reliable`

        Specifies that the communication with the service is reliable respectively the
        TCP protocol is used for communication.

        * `port`

            The port of the TCP endpoint.

        * `enable-magic-cookies`

            Specifies whether magic cookies are enabled (valid values: _true_, _false_).

    * `unreliable`

        Specifies that the communication with the service is unreliable respectively the
        UDP protocol is used for communication (valid values: the _port_ of the UDP
        endpoint).

    * `events` (array)

        Contains the events of the service.

        * `event`

            The id of the event.

        * `is_field`

            Specifies whether the event is of type field.

            NOTE: A field is a combination of getter, setter and notification event. It
            contains at least a getter, a setter, or a notifier. The notifier sends an event
            message that transports the current value of a field on change.

        * `is_reliable`

            Specifies whether the communication is reliable respectively whether the event
            is sent with the TCP protocol (valid values: _true_,_false_).

            If the value is _false_ the UDP protocol will be used.

    * `eventgroups` (array)

        Events can be grouped together into on event group. For a client it is thus
        possible to subscribe for an event group and to receive the appropriate events
        within the group.

        * `eventgroup`

            The id of the event group.

        * `events` (array)

            Contains the ids of the appropriate events.

        * `multicast`

            Specifies the multicast that is used to publish the eventgroup.

            * `address`

                The multicast address.

            * `port`

                The multicast port.

        * `threshold`

            Specifies when to use multicast and when to use unicast to send a notification event.
            Must be set to a non-negative number. If it is set to zero, all events of the eventgroup
            will be sent by unicast. Otherwise, the events will be sent by unicast as long as the
            number of subscribers is lower than the threshold and by multicast if the number
            of subscribers is greater or equal. This means, a threshold of 1 will lead to all events
            being sent by multicast. The default value is _0_.

    * `debounce-times` (object)

        Used to configure the nPDU feature. This is described in detail in
        [vSomeIP nPDU feature](#vsomeip-npdu-feature).

    * `someip-tp` (object)

        Used to configure the SOME/IP-TP feature. There's an example available at
        [SOME/IP-TP](#someip-tp).

        * `service-to-client` (array)

            Contains the IDs for responses, fields and events which are sent from the node
            to a remote client which can be segmented via SOME/IP-TP if they exceed the
            maximum message size for UDP communication. If an ID isn't listed here the
            message will otherwise be dropped if the maximum message size is exceeded.

        * `client-to-service` (array)

            Contains the IDs for requests, which are sent from the node
            to a remote service which can be segmented via SOME/IP-TP if they exceed the
            maximum message size for UDP communication. If an ID isn't listed here the
            message will otherwise be dropped if the maximum message size is exceeded.

* `clients` (array)

    The client-side ports that shall be used to connect to a specific service.
    For each service, an array of ports to be used for reliable / unreliable
    communication can be specified. vsomeip will take the first free port of
    the list. If no free port can be found, the connection will fail. If
    vsomeip is asked to connect to a service instance without specified port(s),
    the port will be selected by the system. This implies that the user has
    to ensure that the ports configured here do not overlap with the ports
    automatically selected by the IP stack.

    * `service`
    * `instance`

        Together they specify the service instance the port configuration shall be applied to.

    * `reliable` (array)

        The list of client ports to be used for reliable (TCP) communication to the given
        service instance.

    * `unreliable` (array)

        The list of client ports to be used for unreliable (UDP) communication to the given
        service instance.

        Additionally there is the possibility to configure mappings between ranges of client
        ports and ranges of remote service ports.
        (If a client port is configured for a specific service / instance, the port range mapping is ignored)

    * `reliable_remote_ports`

        Specifies a range of reliable remote service ports

    * `unreliable_remote_ports`

        Specifies a range of unreliable remote service ports

    * `reliable_client_ports`

        Specifies the range of reliable client ports to be mapped to the reliable_remote_ports range

    * `unreliable_client_ports`

        Specifies the range of unreliable client ports to be mapped to the unreliable_remote_ports range

    * `first`

        Specifies the lower bound of a port range

    * `last`

        Specifies the upper bound of a port range

* `payload-sizes` (array)

    Array to limit the maximum allowed payload sizes per IP and port. If not
    specified otherwise the allowed payload sizes are unlimited. The settings in
    this array only affect communication over TCP. To limit the local payload size
    `max-payload-size-local` can be used.

    * `unicast` (optional)

        On client side: the IP of the remote service for which the payload size should
        be limited.

        On service side: the IP of the offered service for which the payload size for
        receiving and sending should be limited.

    * `ports` (array)

        Array which holds pairs of port and payload size statements.

        * `port`

            On client side: the port of the remote service for which the payload size should
            be limited.

            On service side: the port of the offered service for which the payload size for
            receiving and sending should be limited.

        * `max-payload-size`

            On client side: the payload size limit in bytes of a message sent to the
            remote service hosted on beforehand specified IP and port.

            On service side: the payload size limit in bytes of messages received and sent
            by the service offered on previously specified IP and port.

            If multiple services are hosted on the same port they all share the limit
            specified.

* `max-payload-size-local`

    The maximum allowed payload size for node internal communication in bytes. By
    default the payload size for node internal communication is unlimited. It can be
    limited via this setting.

* `max-payload-size-reliable`

    The maximum allowed payload size for TCP communication in
    bytes. By default the payload size for TCP communication is
    unlimited. It can be limited via this setting.

* `max-payload-size-unreliable`

    The maximum allowed payload size for UDP communication via SOME/IP-TP in
    bytes. By default the payload size for UDP via SOME/IP-TP communication is
    unlimited. It can be limited via this setting. This setting only applies for
    SOME/IP-TP enabled methods/events/fields (otherwise the UDP default of 1400
    bytes applies). See [SOME/IP-TP](#someip-tp) for an example configuration.

* `endpoint-queue-limits` (array)

    Array to limit the maximum allowed size in bytes of cached outgoing messages per
    IP and port (message queue size per endpoint). If not specified otherwise the
    allowed queue size is unlimited. The settings in this array only affect external
    communication. To limit the local queue size `endpoint-queue-limit-local` can
    be used.

    * `unicast`

        On client side: the IP of the remote service for which the queue size of sent
        requests should be limited.

        On service side: the IP of the offered service for which the queue size for
        sent responses should be limited. This IP address is therefore
        identical to the IP address specified via `unicast` setting on top level of the
        json file.

    * `ports` (array)

        Array which holds pairs of port and queue size statements.

        * `port`

            On client side: the port of the remote service for which the queue size of sent
            requests should be limited.

            On service side: the port of the offered service for which the queue size for
            send responses should be limited.

        * `queue-size-limit`

            On client side: the queue size limit in bytes of messages sent to the
            remote service hosted on beforehand specified IP and port.

            On service side: the queue size limit in bytes for responses sent by the service
            offered on previously specified IP and port.

            If multiple services are hosted on the same port they all share the limit
            specified.

* `endpoint-queue-limit-external`

    Setting to limit the maximum allowed size in bytes of cached outgoing messages
    for external communication (message queue size per endpoint). By default the
    queue size for external communication is unlimited. It can be limited via this
    setting. Settings done in the `endpoint-queue-limits` array override this
    setting.

* `endpoint-queue-limit-local`

    Setting to limit the maximum allowed size in bytes of cached outgoing messages
    for local communication (message queue size per endpoint). By default the queue
    size for node internal communication is unlimited. It can be limited via this
    setting.

* `buffer-shrink-threshold`

    The number of processed messages which are half the size or smaller than the
    allocated buffer used to process them before the memory for the buffer is
    released and starts to grow dynamically again. This setting can be useful in
    scenarios where only a small number of the overall messages are a lot bigger
    then the rest and the memory allocated to process them should be released in a
    timely manner. If the value is set to zero the buffer sizes aren't reseted and
    are as big as the biggest processed message. (default is 5)

    Example: `buffer-shrink-threshold` is set to 50. A message with 500 bytes has to
    be processed and the buffers grow accordingly. After this message 50 consecutive
    messages smaller than 250 bytes have to be processed before the buffer size is
    reduced and starts to grow dynamically again.

* `tcp-restart-aborts-max`

    Setting to limit the number of TCP client endpoint restart aborts due to unfinished TCP handshake.
    After the limit is reached, a forced restart of the TCP client endpoint is done if the connection attempt is still pending.

* `tcp-connect-time-max`

    Setting to define the maximum time until the TCP client endpoint connection attempt should be finished.
    If `tcp-connect-time-max` is elapsed, the TCP client endpoint is forcely restarted if the connection attempt is still pending.

* `udp-receive-buffer-size`

    Specifies the size of the socket receive buffer (`SO_RCVBUF`) used for
    UDP client and server endpoints in bytes. (default: 1703936)

* `internal_services` (optional array)

    Specifies service/instance ranges for pure internal service-instances.
    This information is used by vsomeip to avoid sending Find-Service messages
    via the Service-Discovery when a client is requesting a not available service-
    instance. Its can either be done on service/instance level or on service level
    only which then includes all instance from 0x0000-0xffff.

    * `first`

        The lowest entry of the internal service range.

        * `service`

            The lowest Service-ID in hex of the internal service range.

        * `instance` (optional)

            The lowest Instance-ID in hex of a internal service-instance range.
            If not specified the lowest Instance-ID is 0x0000.

    * `last`

        The highest entry of the internal service range.

        * `service`

            The highest Service-ID in hex of a internal service range.

        * `instance` (optional)

            The highest Instance-ID in hex of a internal service-instance range.
            If not specified the highest Instance-ID is 0xFFFF.

* `debounce` (optional array)

    Events/fields sent by external devices will be forwarded to the
    applications only if a configurable function evaluates to true. The
    function checks whether the event/field payload has changed and whether
    a specified interval has been elapsed since the last forwarding.

* `service`

    Service ID which hosts the events to be debounced.

    * `instance`

        Instance ID which hosts the events to be debounced.

    * `events`

        Array of events which shall be debounced based on the following
        configuration options.

        * `event`

            Event ID.

        * `on_change`

            Specifies whether the event is forwarded on
            payload change or not. (valid values: _true_, _false_).
            Default is _false_.

        * `ignore`

            Array of payload indexes with given bit mask (optional)
            to be ignored in payload change evaluation.
            Instead of specifying an index / bitmask pair, one can only define the payload index
            which shall be ignored in the evaluation.

            * `index`

                Payload index to be checked with given bitmask.

            * `mask`

                1Byte bitmask applied to byte at given payload index.
                Example mask: 0x0f ignores payload changes in low nibble of the byte at given index.

        * `interval`

            Specifies if the event shall be debounced based on elapsed time interval.
            (valid values: _time in ms_, _never_). Default is _never_.

        * `on_change_resets_interval` (optional)

            Specifies if interval timer is reset when payload change was detected.
            (valid values: _false_, _true_). Defaults to _false_.

        * `send_current_value_after` (optional)

            Specifies if last message should be sent after interval timeout.
            (valid values: _false_, _true_). Defaults to _false_.

* `routing` (optional)

    Specifies the properties of the routing. Either a string that specifies the application that hosts the
    routing component or a structure that specifies all properties of the routing. If the routing is not
    specified, the first started application will host the routing component.

    * `host`

        Properties of the routing manager.

        * `name`

            Name if the application that hosts the routing component.

        * `uid`

            User identifier of the process that runs the routing component. Must be specified if credential checks
            are enabled by _check_credentials_ set to true.

        * `gid`

            Group identifier of the process that runs the routing component. Must be specified if credential checks
            are enabled by _check_credentials_ set to true.

        * `unicast` (optional)

            The unicast address that shall be used by the routing manager, if the internal communication shall be done
            by using TCP connections.

        * `port` (optional)

            The port that shall be used by the routing manager, if the internal communication shall be done
            by using TCP connections.

    * `guests` (optional)

        Properties of all applications that do not host the routing component, if the internal communication shall be
        done using TCP connections.

        * `unicast`

            The unicast address that shall be used by the applications to connect to the routing manager.

        * `ports`

            A set of port ranges that shall be used to connect to the routing manager per user identifier/group identifier.
            Either specify uid, gid and ranges, or only a set of port ranges. If uid and gid are not explicitly specified,
            they default to any. Each client application requires two ports, one for receiving messages from other
            applications and one to send messages to other applications.

            * `uid`

                User identifier

            * `gid`

                Group identifier

            * `ranges`

                Set of port ranges. Each entry consists of a `first`, `last` pair that determines the first and the last port
                of a port range.

                * `first`

                    First port of a port range

                * `last`

                    Last port of a port range

                    NOTE: Each configured port range must contain an even number of ports. If an even port number is configured
                    to be the routing host port, the first port in the range must also be even. If an uneven port number is
                    configured to be the routing host port, the first port in the range must also be uneven.

* `routing-credentials` (deprecated)

    The UID / GID of the application acting as routing manager.
    (Must be specified if credentials checks are enabled using _check_credentials_ set to _true_ in order to successfully check the routing managers credentials passed on connect)

    * `uid`

        The routing managers UID.

    * `gid`

    The routing managers GID.

* `shutdown_timeout`

    Configures the time in milliseconds local clients wait for acknowledgement of
    their deregistration from the routing manager during shutdown. Defaults to
    5000ms.

* `warn_fill_level`

    The routing manager regulary checks the fill level of the send buffers to its
    clients. This variable defines the minimum fill level in percent that leads to
    a warning being logged. Defaults to 67.

* `service-discovery`

    Contains settings related to the Service Discovery of the host application.

    * `enable`

        Specifies whether the Service Discovery is enabled (valid values: _true_,
        _false_). The default value is _true_.

    * `multicast`

        The multicast address which the messages of the Service Discovery will be sent
        to. The default value is _224.0.0.1_.

    * `port`

        The port of the Service Discovery. The default setting is _30490_.

    * `protocol`

        The protocol that is used for sending the Service Discovery messages (valid
        values: _tcp_, _udp_). The default setting is _udp_.

    * `initial_delay_min`

        Minimum delay before first offer message.

    * `initial_delay_max`

        Maximum delay before first offer message.

    * `repetitions_base_delay`

        Base delay sending offer messages within the repetition phase.

    * `repetitions_max`

        Maximum number of repetitions for provided services within the
        repetition phase.

    * `ttl`

        Lifetime of entries for provided services as well as consumed services and eventgroups.

    * `ttl_factor_offers` (optional array)

        Array which holds correction factors for incoming remote offers. If a value
        greater than one is specified for a service instance, the TTL field of the
        corresponding service entry will be multiplied with the specified factor. +
        Example: An offer of a service is received with a TTL of 3 sec and the TTL
        factor is set to 5. The remote node stops offering the service w/o sending a
        StopOffer message. The service will then expire (marked as unavailable) 15 seconds
        after the last offer has been received.

        * `service`

            The id of the service.

        * `instance`

            The id of the service instance.

        * `ttl_factor`

            TTL correction factor

    * `ttl_factor_subscriptions` (optional array)

        Array which holds correction factors for incoming remote subscriptions. If a
        value greater than one is specified for a service instance, the TTL field of the
        corresponding eventgroup entry will be multiplied with the specified factor. +
        Example: A remote subscription to an offered service is received with a TTL of 3
        sec and the TTL factor is set to 5. The remote node stops resubscribing to the
        service w/o sending a StopSubscribeEventgroup message. The subscription will
        then expire 15 seconds after the last resubscription has been received.

        * `service`

            The id of the service.

        * `instance`

            The id of the service instance.

        * `ttl_factor`

            TTL correction factor

    * `cyclic_offer_delay`

        Cycle of the OfferService messages in the main phase.


    * `request_response_delay`

        Minimum delay of a unicast message to a multicast message for
        provided services and eventgroups.


    * `offer_debounce_time`

        Time which the stack collects new service offers before they enter the
        repetition phase. This can be used to reduce the number of
        sent messages during startup. The default setting is _500ms_.

* 'suppress_missing_event_logs'

    Used to filter the log message `deliver_notification: Event [1234.5678.80f3]
    is not registered. The message is dropped.` that occurs whenever vSomeIP
    receives an event without having a corresponding object being registered.

```json
...
"suppress_missing_event_logs" :
[
    {
        "service" : "0x0023",
        "instance" : "0x0001",
        "events" : [ "0x8001", "0x8002",
                    {
                        "first" : "0x8010",
                        "last" : "0x801f"
                    },
                    "0x8020" ]
    },
    {
        "service" : "0x0023",
        "instance" : "0x0002",
        "events" : [ "0x8005", "0x8006" ]
    },
    {
        "service" : "0x0023",
        "instance" : "0x0002",
        "events" : [ "0x8105", "0x8106" ]
    },
    {
        // no "events" --> ignore all(!) events of these services
        "service" : "any",
        "instance" : "0x00f2"
    },
    {
        "service" : "0x0102",
        "instance" : "any",
        "events" : [ "0x8005", "0x8006" ]
    }
]
```

* `watchdog` (optional)

    The Watchdog sends periodically pings to all known local clients.
    If a client isn't responding within a configurred time/amount of pongs
    the watchdog deregisters this application/client.
    If not configured the watchdog isn't activated.

    * `enable`

        Specifies whether the watchdog is enabled or disabled.
        (valid values: _true, false_), (default is _false_).

    * `timeout`

        Specifies the timeout in ms the watchdog gets activated if a ping
        isn't answered with a pong by a local client within that time.
        (valid values: _2 - 2^32_), (default is _5000_ ms).

    * `allowed_missing_pongs`

        Specifies the amount of allowed missing pongs.
        (valid values: _1 - 2^32_), (default is _3_ pongs).


* `supports_selective_broadcasts` (optional array)

    This nodes allow to add a list of IP addresses on which CAPI-Selective-Broadcasts feature is supported.
    If not specified the feature can't be used and the subscription behavior of the stack is same as with
    normal events.

    * `address`

        Specifies an IP-Address (in IPv4 or IPv6 notation) on which the "selective"-feature is supported.
        Multiple addresses can be configured.

# Security

vsomeip has a security implementation based on UNIX credentials.
If activated every local connection is authenticated during connect using the standard UNIX credential passing mechanism.
During authentication a client transfers its client identifier together with its credentials (UID / GID) to the server which is then matched against the configuration.
If received credentials don't match the policy the socket will be immediately closed by the server and an message is logged.
If accepted the client identifier is bound to the receiving socket and can therefore be used to do further security checks on incoming messages (vsomeip messages as well as internal commands).

In general clients can be configured to be allowed/denied to request (means communicate with) and offer different service instances.
Every incoming vsomeip message (request/response/notification) as well as offer service requests or local subscriptions are then checked against the policy.
If an incoming vsomeip message or another operation (e.g. offer/subscribe) violates the configured policies it is skipped and a message is logged.

Furthermore if an application receives informations about other clients/services in the system, it must be received from the authenticated routing manager.
This is to avoid malicious applications faking the routing manager and therefore being able to wrongly inform other clients about services running on the system.
Therefore, whenever the "security" tag is specified, the routing manager (e.g. routingmanagerd/vsomeipd) must be a configured application with a fixed client identifier.
See chapter "Configuration File Structure" on how to configure an application to use a specific client identifier.

Credential passing is only possible via Unix-Domain-Sockets and therefore only available for local communication.
However if security is activated method calls from remote clients to local services are checked as well which means remote clients needs to be explicitly allowed.
Such a policy looks same in case for local clients except the _credentials_ tag can be skipped.

## Security configuration

The available configuration switches for the security feature are:

* `security` (optional)

    NOTE: As long as no _security_ node exists, the security implementation is switched off. This also means,
    no external security library will be loaded and used.

    If specified the credential passing mechanism is activated. However no credential or security checks are done as long as
    _check_credentials_ isn't set to _true_, but the routing manager client ID must be configured if security tag is specified.
    If _check_credentials_ is set to _true_, the routing managers UID and GID needs to be specified using _routing-credentials_ tag.

    * `check_credentials` (optional)

        Specifies whether security checks are active or not. This includes credentials checks on connect as well as all policies checks configured in follow.
        (valid values: _true, false_), (default is _false_).

    * `allow_remote_clients` (optional)

        Specifies whether incoming remote requests / subscriptions are allowed to be sent to a local proxy / client.
        If not specified, all remote requests / subscriptions are allowed to be received by default.
        (valid values are 'true' and 'false')

    * `policies` (array)

        Specifies the security policies. Each policy at least needs to specify _allow_ or _deny_.

        * `credentials`

            Specifies the credentials for which a security policy will be applied.
            If _check_credentials_ is set to _true_ the credentials of a local application needs to be specified correctly to ensure local socket authentication can succeed.

            * `uid`

                Specifies the LINUX user id of the client application as decimal number.
                As a wildcard "any" can be used.

            * `gid`

                Specifies the LINUX group id of the client application as decimal number.
                As a wildcard "any" can be used.

            * `allow` / `deny` (optional)

                Specifies whether the LINUX user and group ids are allowed or denied for the policy.

                1. `uid` (array)

                Specifies a list of LINUX user ids. These may either be specified as decimal numbers or as ranges. Ranges
                are specified by the first and the last valid id (see example below).

                2. `gid` (array)

                Specifies a list of LINUX group ids. These may either be specified as decimal numbers or as ranges. Ranges
                are specified by the first and the last valid id (see example below).

        * `allow` / `deny`

            This tag specifies either _allow_ or _deny_ depending on white- or blacklisting is needed. Specifing _allow_ and _deny_ entries in one policy is therefore not allowed.
            With _allow_ a whitelisting of what is allowed can be done which means an empty _allow_ tag implies everything is denied.
            With _deny_ a blacklisting of what is allowed can be done which means an empty _deny_ tag implies everything is allowed.

            * `requests` (array)

                Specifies a set of service instance pairs which the above client application using the credentials above is allowed/denied to communicate with.

                1. `service`

                    Specifies a service for the _requests_.

                2. `instance` (deprecated)

                    Specifies a instance for the _requests_
                    As a wildcard "any" can be used which means a range from instance ID 0x01 to 0xFFFF
                    which also implies a method ID range from 0x01 to 0xFFFF.

                3. `instances` (array)

                    Specifies a set of instance ID and method ID range pairs which are allowed/denied to communicate with.
                    If the `ids` tag below is not used to specify allowed/denied requests on method ID level one can also
                    only specify a a set of instance ID ranges which are allowed/denied to be requested analogous to the
                    allowed/denied `offers` section.
                    If no method IDs are specified, the allowed/denied methods are by default a range from 0x01 to 0xFFFF.

                    1. `ids`

                        Specifies a set of instance ID ranges which are allowed/denied to communicate with.
                        It is also possible to specify a single instance ID as array element without giving an upper / lower range bound.
                        As a wildcard "any" can be used which means a range from instance ID 0x01 to 0xFFFF.

                        `first` - The lower bound of the instance range.

                        `last`  - The upper bound of the instance range.

                    2. `methods`

                        Specifies a set of method ID ranges which are allowed/denied to communicate with.
                        It is also possible to specify a single method ID as array element without giving an upper / lower range bound.
                        As a wildcard "any" can be used which means a range from method ID 0x01 to 0xFFFF.

                        `first` - The lower bound of the method range.

                        `last`  - The upper bound of the method range.

            * `offers` (array)

                Specifies a set of service instance pairs which are allowed/denied to be offered by the client application using the credentials above.

                1. `service`

                    Specifies a service for the _offers_.

                2. `instance` (deprecated)

                    Specifies a instance for the _offers_
                    As a wildcard "any" can be used which means a range from instance ID 0x01 to 0xFFFF.

                3. `instances` (array)

                    Specifies a set of instance ID ranges which are allowed/denied to be offered by the client application using the credentials above.
                    It is also possible to specify a single instance ID as array element without giving an upper / lower range bound.
                    As a wildcard "any" can be used which means a range from instance ID 0x01 to 0xFFFF.

                    1. `first`

                        The lower bound of the instance range.

                    2. `last`

                        The upper bound of the instance range.

---

## Security configuration example

```json
...
"security" :
{
    ...
    "policies" :
    [
        {
            ...
            "credentials" :
            {
                "uid" : "44",
                "gid" : "any"
             },
             "allow" :
             [
                 "requests" :
                 [
                     {
                         "service" : "0x6731",
                         "instance" : "0x0001"
                     }
                 ]
             ]
         },
         {
            "credentials" :
            {
                "deny" :
                [
                    {
                        "uid" : [ "1000", { "first" : "1002", "last" : "max" }],
                        "gid" : [ "0", { "first" : "100", "last" : "243" }, "300"]
                    },
                    {
                        "uid" : ["55"],
                        "gid" : ["55"]
                    }
                 ]
             },
             "allow" :
             [
                 "offers" :
                 [
                     {
                        "service" : "0x6728",
                        "instances" : [ "0x0001", { "first" : "0x0003", "last" : "0x0007" }, "0x0009"]
                     },
                     {
                        "service" : "0x6729",
                        "instances" : ["0x88"]
                     },
                     {
                        "service" : "0x6730",
                        "instance" : "any"
                     }
                 ],
                 "requests" :
                 [
                     {
                         "service" : "0x6732",
                         "instances" :
                         [
                             {
                                 "ids" : [ "0x0001", { "first" : "0x0003", "last" : "0x0007" }],
                                 "methods" : [ "0x0001", "0x0003", { "first" : "0x8001", "last" : "0x8006" } ]
                             },
                             {
                                 "ids" : [ "0x0009" ],
                                 "methods" : "any"
                             }
                         ]
                     },
                     {
                        "service" : "0x6733",
                        "instance" : "0x1"
                     },
                     {
                        "service" : "0x6733",
                        "instances" : [ "0x0002", { "first" : "0x0003", "last" : "0x0007" }, "0x0009"]
                     }
                 ]
             ]
         }
     ]
}
```

The config/ folder contains some addition vsomeip configuration files to run the vsomeip
examples with activated security checks.
Additionally there's a security test in the `test/` subfolder which can be used
for further reference. +
They give a basic overview how to use the security related configuration tags described
in this chapter to run a simple request/response or subscribe/notify example locally or
remotely.

## Security policy extensions

vsomeip policy extension configuration supports the definition of paths that contain additional
security policies to be loaded whenever a client with a yet unknown hostname connects to a local server endpoint.
The following configuration parameters are available and can be defined in a file named `vsomeip_policy_extensions.json`.

* `container_policies` (optional array)

    Specifies the additional configuration folders to be loaded for each container hostname / filesystem path pair.

    * `container`

        Specifies the linux hostname.

    * `path`

        Specifies a filesystem path (relative to vsomeip_policy_extensions.json or absolute) which contains
        $UID_$GID subfolders that hold a `vsomeip_security.json` file.

        NOTE: ($UID / $GID) is the UID /GID of the vsomeip client application
        to which a client from hostname defined with `container`connetcs to.

## Audit Mode

vsomeip's security implementation can be put in a so called 'Audit Mode' where
all security violations will be logged but allowed. This mode can be used to
build a security configuration.

To activate the 'Audit Mode' the 'security' object has to be included in the
json file but the 'check_credentials' switch has to be set to false. For
example:


```json
    [...]
    "services" :
    [
        [...]
    ],
    "security" :
    {
        "check_credentials" : "false"
    },
    "routing" : "service-sample",
    [...]
```

# Autoconfiguration

vsomeip supports the automatic configuration of client identifiers and the routing.
The first application that starts using vsomeip will automatically become the
routing manager if it is _not_ explicitly configured. The client identifiers
are generated from the diagnosis address that can be specified by defining
DIAGNOSIS_ADDRESS when compiling vsomeip. vsomeip will use the diagnosis address
as the high byte and enumerate the connecting applications within the low byte
of the client identifier.

Autoconfiguration of client identifiers isn't meant to be used together with vsomeip Security.
Every client running locally needs to have at least its own credentials configured when security is activated to ensure the credential checks can pass.
Practically that means if a client requests its identifier over the autoconfiguration for which no credentials are configured (at least it isn't known which client identifier is used beforehand) it is impossible for that client to establish a connection to a server endpoint.
However if the credentials for all clients are same it's possible to configure them for the overall (or DIAGNOSIS_ADDRESS) client identifier range to mix autoconfiguration together with activated security.

# routingmanagerd

The routingmanagerd is a minimal vsomeip application intended to offer routing
manager functionality on a node where one system wide configuration file is
present. It can be found in the examples folder.

Example: Starting the daemon on a system where the system wide configuration is
stored under `/etc/vsomeip.json`:

```bash
VSOMEIP_CONFIGURATION=/etc/vsomeip.json ./routingmanagerd
```

When using the daemon it should be ensured that:

* In the system wide configuration file the routingmanagerd is defined as
  routing manager, meaning it contains the line `"routing" : "routingmanagerd"`.
  If the default name is overridden the entry has to be adapted accordingly.
  The system wide configuration file should contain the information about all
  other offered services on the system as well.
* There's no other vsomeip configuration file used on the system which contains
  a `"routing"` entry. As there can only be one routing manager per system.

# vsomeip Hello World

In this paragraph a Hello World program consisting out of a client and a service
is developed. The client sends a message containing a string to the service.
The service appends the received string to the string `Hello` and sends it back
to the client.
Upon receiving a response from the service the client prints the payload of the
response ("Hello World").
This example is intended to be run on the same host.

All files listed here are contained in the `examples\hello_world` subdirectory.

## Build instructions

The example can build with its own CMakeFile, please compile the vsomeip stack
before hand as described in [Compilation](#compilation). Then compile the example starting
from the repository root directory as followed:

```bash
cd examples/hello_world
mkdir build
cd build
cmake ..
make
```

## Starting and expected output
### Starting and expected output of service

```bash
$ VSOMEIP_CONFIGURATION=../helloworld-local.json \
  VSOMEIP_APPLICATION_NAME=hello_world_service \
  ./hello_world_service
2015-04-01 11:31:13.248437 [info] Using configuration file: ../helloworld-local.json
2015-04-01 11:31:13.248766 [debug] Routing endpoint at /tmp/vsomeip-0
2015-04-01 11:31:13.248913 [info] Service Discovery disabled. Using static routing information.
2015-04-01 11:31:13.248979 [debug] Application(hello_world_service, 4444) is initialized.
2015-04-01 11:31:22.705010 [debug] Application/Client 5555 got registered!
```

### Starting and expected output of client

```bash
$ VSOMEIP_CONFIGURATION=../helloworld-local.json \
  VSOMEIP_APPLICATION_NAME=hello_world_client \
  ./hello_world_client
2015-04-01 11:31:22.704166 [info] Using configuration file: ../helloworld-local.json
2015-04-01 11:31:22.704417 [debug] Connecting to [0] at /tmp/vsomeip-0
2015-04-01 11:31:22.704630 [debug] Listening at /tmp/vsomeip-5555
2015-04-01 11:31:22.704680 [debug] Application(hello_world_client, 5555) is initialized.
Sending: World
Received: Hello World
```

## CMakeFile

[examples/hello_world/CMakeLists.txt](../examples/hello_world/CMakeLists.txt)

## Configuration File For Client and Service

[examples/hello_world/helloworld-local.json](../examples/hello_world/helloworld-local.json)

## Service

[examples/hello_world/hello_world_service_main.cpp](../examples/hello_world/hello_world_service_main.cpp)

The service example results in the following program execution:

### Main

1. *main()*

    First the application is initialized. After the initialization is
    finished the application is started.

### Initialization

2. *init()*

    The initialization contains the registration of a message
    handler and an event handler.

    The message handler declares a callback (__on_message_cbk__) for messages that
    are sent to the specific service (specifying the service id, the service
    instance id and the service method id).

    The event handler declares a callback (__on_event_cbk__) for events that occur.
    One event can be the successful registration of the application at the runtime.

### Start

3. *start()*

    The application will be started. This function only returns when the application
    will be stopped.

### Callbacks

4. *on_state_cbk()*

    This function is called by the application when an state change occurred. If
    the application was successfully registered at the runtime then the specific
    service is offered.

5. *on_message_cbk()*

    This function is called when a message/request from a client for the specified
    service was received.

    First a response based upon the request is created.
    Afterwards the string 'Hello' will be concatenated with the payload of the
    client's request.
    After that the payload of the response is created. The payload data is set with
    the previously concatenated string.
    Finally the response is sent back to the client and the application is stopped.

### Stop

6. *stop()*

    This function stops offering the service, unregister the message and the event
    handler and shuts down the application.

## Client

[examples/hello_world/hello_world_client_main.cpp](../examples/hello_world/hello_world_client_main.cpp)

The client example results in the following program execution:

### Main

1. *main()*

    First the application is initialized. After the initialization is finished the
    application is started.

### Initialization

2. *init()*

    The initialization contains the registration of a message handler, an event
    handler and an availability handler.

    The event handler declares again a callback (__on_state_cbk__) for state changes
    that occur.

    The message handler declares a callback (__on_message_cbk__) for messages that
    are received from any service, any service instance and any method.

    The availability handler declares a callback (__on_availability_cbk__) which is
    called when the specific service is available (specifying the service id and the
    service instance id).

### Start

3. *start()*

    The application will be started. This function only returns when the application
    will be stopped.

### Callbacks

4. *on_state_cbk()*

    This function is called by the application when an state change occurred. If the
    application was successfully registered at the runtime then the specific service
    is requested.

5. *on_availability_cbk()*

    This function is called when the requested service is available or no longer
    available.

    First there is a check if the change of the availability is related to the
    'hello world service' and the availability changed to true.
    If the check is successful a service request is created and the appropriate
    service information are set (service id, service instance id, service method
    id).
    After that the payload of the request is created. The data of the payload is
    'World' and will be set afterwards.
    Finally the request is sent to the service.

6. *on_message_cbk()*

    This function is called when a message/response was received.
    If the response is from the requested service, of type 'RESPONSE' and the return
    code is 'OK' then the payload of the response is printed. Finally the
    application is stopped.

### Stop

7. *stop()*

This function unregister the event and the message handler and shuts down the
application.

# Trace Connector
## Overview/Prerequisites

The Trace Connector is used to forward the internal messages that are sent over
the Unix Domain Sockets to DLT. +
Thus, it requires that DLT is installed and the DLT module can be found in the
context of CMake.

## Configuration
### Static Configuration

The Trace Connector can be configured statically over the *tracing* point of the
[Configuration File Structure](#tracing-anchor)

### Example 1 (Minimal Configuration)

```json
{
    ...

    "tracing" :
    {
        "enable" : "true"
    },

    ...
```

This is the minimal configuration of the Trace Connector. This just enables the
tracing and all of the sent internal messages will be traced/forwarded to DLT.

### Example 2 (Using Filters)

```json
{
    ...

    "tracing" :
    {
        "enable" : "true",
        "channels" :
        [
            {
                "name" : "My channel",
                "id" : "MC"
            }
        ],
        "filters" : [
            {
                "channel" : "MC",
                "matches" : [ { "service" : "0x1234", "instance" : "any", "method" : "0x80e8" } ],
                "type" : "positive"
            }
        ]
    },

    ...
```

As it is a positive filter, the example filter ensures that only messages
representing method '0x80e8' from instances of service '0x1234' will be
forwarded to the DLT. If it was specified as a negative filter, all messages
except messages representing method '0x80e8' from instances of service
'0x1234' would be forwarded to the DLT.

The general filter rules are:

* The default filter is a positive filter for all messages.
* The default filter is active on a channel as long as no other positive
filter is specified.
* Negative filters block matching messages. Negative filters overrule
positive filters. Thus, as soon as a messages matches a negative filter it
will not be forwarded.
* The identifier '0xffff' is a wildcard that matches any service, instance or method.
The keyword 'any' can be used as a replacement for '0xffff'.
* Wildcards must not be used within range filters.

### Dynamic Configuration

The Trace Connector can also be configured dynamically over its interfaces.
You need to include '<vsomeip/trace.hpp>' to access its public interface.

### Example:

```c++
    // get trace connector
    std::shared_ptr<vsomeip::trace::connector> its_connector
    = vsomeip::trace::connector::get();

    // add channel
    std::shared_ptr<vsomeip::trace::channel> its_channel
    = its_connector->create_channel("MC", "My channel");

    // add filter rule
    vsomeip::trace::match_t its_match
        = std::make_tuple(0x1234, 0xffff, 0x80e8);
    vsomeip::trace::filter_id_t its_filter_id
    = its_channel->add_filter(its_match, true);

    // init trace connector
    its_connector->init();

    // enable trace connector
    its_connector->set_enabled(true);

    // remove the filter
    its_channel->remove_filter(its_filter_id);
```

# vsomeip nPDU feature

This is the add-on documentation for the nPDU feature, aka. _Zugverfahren_.

The nPDU feature can be used to reduce network load as it enables the vsomeip
stack to combine multiple vsomeip messages in one single ethernet frame.

Some general _important_ things regarding the nPDU feature first:

* Due to its nature the nPDU feature trades lower network load for speed.
* As the nPDU feature requires some settings which are not transmitted
through the service discovery, it's *not* sufficient anymore to have an json
file without a "services" section on the client side.
* As the client- and server-endpoints of a node are managed by the routing
 manager (which is the application entered at "routing" in the json file)
 the nPDU feature settings *always* have to be defined in the json file used by
 the application acting as routing manager.
* The nPDU feature timings are defined in milliseconds.
* Node internal communication over UNIX domain sockets is not affected by the
  nPDU feature.
* If the debounce times configuration for a method in the json file is missing
  or incomplete the default values are used: 2ms debounce time and 5ms max
  retention time. The global default values can be overwritten via the
  `npdu-default-timings` json object.

## Configuration

There are two parameters specific for the nPDU feature:

* *debounce time*: minimal time between sending a message to the same method of
  a remote service over the same connection (src/dst address + src/dst port).
* *max retention time*: the maximum time which a message to the same method of a
  remote service over the same connection (src/dst address + src/dst port) is
  allowed to be buffered on sender side.

For more information please see the corresponding requirement documents.


The nPDU feature specific settings are configured in the json file in the
"services" section on service level in a special _debounce-times_ section:


```json
[...]
"services":
[
    {
        "service":"0x1000",
        "instance":"0x0001",
        "unreliable":"30509",
        "debounce-times":
        {
            // nPDU feature configuration for this
            // service here
        }
    }
],
[...]
```

Additionally nPDU default timings can be configured globally.

The global default timings can be overwritten via the `npdu-default-timings`
json object. For example the following configuration snippet shows how to set
all default timings to zero:

```json
{
    "unicast":"192.168.1.9",
    [...]
    "npdu-default-timings" : {
        "debounce-time-request" : "0",
        "debounce-time-response" : "0",
        "max-retention-time-request" : "0",
        "max-retention-time-response" : "0"
    },
    "routing":"[...]",
    "service-discovery": { [...] }
}
```

### Example 1: One service with one method offered over UDP

* The service is hosted on IP: 192.168.1.9.
* The service is offered on port 30509 via UDP.
* The service has the ID 0x1000
* The method has the ID 0x0001
* The client accesses the service from IP: 192.168.1.77

### Service side

* Debounce time for responses should have a:
    * debounce time of 10 milliseconds
    * maximum retention time of 100 milliseconds

```json
{
    "unicast":"192.168.1.9",
    "logging": { [...] },
    "applications": [ [...] ],
    "services":
    [
        {
            "service":"0x1000",
            "instance":"0x0001",
            "unreliable":"30509",
            "debounce-times":
            {
                "responses": {
                    "0x1001" : {
                        "debounce-time":"10",
                        "maximum-retention-time":"100"
                    }
                }
            }
        }
    ],
    "routing":"[...]",
    "service-discovery": { [...] }
}
```

#### Client side

* Debounce time for requests to the service on 192.168.1.9 should have a:
    * debounce time of 20 milliseconds
    * maximum retention time of 200 milliseconds

```json
{
    "unicast":"192.168.1.77",
    "logging": { [...] },
    "applications": [ [...] ],
    "services":
    [
        {
            "service":"0x1000",
            "instance":"0x0001",
            "unicast":"192.168.1.9", // required to mark service as external
            "unreliable":"30509",
            "debounce-times":
            {
                "requests": {
                    "0x1001" : {
                        "debounce-time":"20",
                        "maximum-retention-time":"200"
                    }
                }
            }
        }
    ],
    "routing":"[...]",
    "service-discovery": { [...] }
}
```

### Example 2: One service with two methods offered over UDP

* The service is hosted on IP: 192.168.1.9.
* The service is offered on port 30509 via UDP.
* The service has the ID 0x1000
* The method has the ID 0x0001
* The second method has the ID 0x0002
* The client accesses the service from IP: 192.168.1.77

#### Service side

* Debounce time for responses should have a:
    * debounce time of 10 milliseconds for method 0x1001 and 20 for 0x1002
    * maximum retention time of 100 milliseconds for method 0x1001 and 200 for 0x1002

```json
{
    "unicast":"192.168.1.9",
    "logging": { [...] },
    "applications": [ [...] ],
    "services":
    [
        {
            "service":"0x1000",
            "instance":"0x0001",
            "unreliable":"30509",
            "debounce-times":
            {
                "responses": {
                    "0x1001" : {
                        "debounce-time":"10",
                        "maximum-retention-time":"100"
                    },
                    "0x1002" : {
                        "debounce-time":"20",
                        "maximum-retention-time":"200"
                    }
                }
            }
        }
    ],
    "routing":"[...]",
    "service-discovery": { [...] }
}
```

#### Client side

* Debounce time for requests to the service on 192.168.1.9 should have a:
    * debounce time of 20 milliseconds for method 0x1001 and 40 for 0x1002
    * maximum retention time of 200 milliseconds for method 0x1001 and 400 for 0x1002

```json
{
    "unicast":"192.168.1.77",
    "logging": { [...] },
    "applications": [ [...] ],
    "services":
    [
        {
            "service":"0x1000",
            "instance":"0x0001",
            "unicast":"192.168.1.9", // required to mark service as external
            "unreliable":"30509",
            "debounce-times":
            {
                "requests": {
                    "0x1001" : {
                        "debounce-time":"20",
                        "maximum-retention-time":"200"
                    },
                    "0x1002" : {
                        "debounce-time":"40",
                        "maximum-retention-time":"400"
                    }
                }
            }
        }
    ],
    "routing":"[...]",
    "service-discovery": { [...] }
}
```

### Example 3: One service with one method offered over UDP and TCP

* The service is hosted on IP: 192.168.1.9.
* The service is offered on port 30509 via UDP.
* The service is offered on port 30510 via TCP.
* The service has the ID 0x1000
* The method has the ID 0x0001
* The client accesses the service from IP: 192.168.1.77

#### Service side

* Debounce time for responses should have a:
    * debounce time of 10 milliseconds
    * maximum retention time of 100 milliseconds
    * TCP should use the same settings as UDP

```json
{
    "unicast":"192.168.1.9",
    "logging": { [...] },
    "applications": [ [...] ],
    "services":
    [
        {
            "service":"0x1000",
            "instance":"0x0001",
            "unreliable":"30509",
            "reliable":
            {
                "port":"30510",
                "enable-magic-cookies":"false"
            },
            "debounce-times":
            {
                "responses": {
                    "0x1001" : {
                        "debounce-time":"10",
                        "maximum-retention-time":"100",
                    }
                }
            }
        }
    ],
    "routing":"[...]",
    "service-discovery": { [...] }
}
```

#### Client side

* Debounce time for requests to the service on 192.168.1.9 should have a:
    * debounce time of 20 milliseconds
    * maximum retention time of 200 milliseconds
    * TCP should use the same settings as UDP

```json
{
    "unicast":"192.168.1.77",
    "logging": { [...] },
    "applications": [ [...] ],
    "services":
    [
        {
            "service":"0x1000",
            "instance":"0x0001",
            "unicast":"192.168.1.9", // required to mark service as external
            "unreliable":"30509",
            "reliable":
            {
                "port":"30510",
                "enable-magic-cookies":"false"
            },
            "debounce-times":
            {
                "requests": {
                    "0x1001" : {
                        "debounce-time":"20",
                        "maximum-retention-time":"200",
                    }
                }
            }
        }
    ],
    "routing":"[...]",
    "service-discovery": { [...] }
}
```

# SOME/IP TP

With SOME/IP Transport Protocol (TP) it is possible to transport messages which
exceed the UDP payload size limit of 1400 byte. If enabled the message is
segmented and send in multiple UDP datagrams.

Example configuration:

* Service 0x1111/0x1 is hosted on 192.168.0.1 on UDP port 40000
* Client is running on 192.168.0.100
* The service has two methods with ID: 0x1 and 0x2 which require large requests
  and large responses. Additionally the service offers a field with ID 0x8001
  which requires a large payloads as well.
* The maximum payload size on service side should be limited to 5000 bytes.

Configuration service side:

```json
{
    "unicast":"192.168.0.1",
    "logging": { [...] },
    "applications": [ [...] ],
    "services":
    [
        {
            "service":"0x1000",
            "instance":"0x1",
            "unreliable":"40000",
            "someip-tp": {
                "service-to-client": [
                    "0x1", "0x2", "0x8001"
                ]
            }
        }
    ],
    "max-payload-size-unreliable" : "5000",
    "routing":"[...]",
    "service-discovery": { [...] }
}
```

Configuration client side:

```json
{
    "unicast":"192.168.0.100",
    "logging": { [...] },
    "applications": [ [...] ],
    "services":
    [
        {
            "service":"0x1000",
            "instance":"0x1",
            "unicast":"192.168.0.1", // required to mark service as external
            "unreliable":"40000", // required to mark service as external
            "someip-tp": {
                "client-to-service": [
                    "0x1", "0x2"
                ]
            }
        }
    ],
    "routing":"[...]",
    "service-discovery": { [...] }
}
```

# Tools
## vsomeip_ctrl

`vsomeip_ctrl` is a small utility which can be used to send SOME/IP messages
from the commandline. If a response arrives within 5 seconds the response will
be printed.

* It can be build via `vsomeip_ctrl` make target (`make vsomeip_ctrl`).
* The instance id of the target service has to be passed in hexadecimal
  notation.
* The complete message has to be passed in hexadecimal notation.
* See the `--help` parameter for available options.
* If `vsomeip_ctrl` is used to send messages to a remote service and no
 `routingmanagerd` is running on the local machine, make sure to pass a json
 configuration file where `vsomeip_ctrl` is set as routing manager via
 environment variable.
* If `vsomeip_ctrl` is used to send messages to a local service and no
 `routingmanagerd` is running on the local machine, make sure to use the same json
 configuration file as the local service.

Example: Calling method with method id 0x80e8 on service with service id 0x1234,
instance id 0x5678:

```bash
./vsomeip_ctrl --instance 5678 --message 123480e800000015134300030100000000000009efbbbf576f726c6400
```

Example: Sending a message to service with service id 0x1234, instance id
0x5678 and method id 0x0bb8 via TCP

```bash
./vsomeip_ctrl --tcp --instance 5678 --message 12340bb8000000081344000101010000
```
