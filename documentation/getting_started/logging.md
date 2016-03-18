# Logging

As of Fluent Bit v0.7, it provides one global mechanism of logging through several levels:

|level| type    | description |
|-----|---------|-----------------------------------------------------------|
| 1   | error   | an internal error has ocurred, recoverable state.|
| 2   | warning | a notification about an unexpected behavior.     |
| 3   | info    | informational messages.                          |
| 4   | debug   | common messages to debug application behavior.   |
| 5   | trace   | very detailed messages to trace application.     |

The default logging level is 3 (_info_), which includes _error_ and _warning_ messages. Optionally the verbose level can be increased using the __-v__ command line argument, if specified, it will increase the level to number 4 (_debug_), in the other side if increased one level more with __-vv__, it will set __trace__ level. All messages are written to the standard error stream (stderr).

Note that due to performance reasons, the inclusion of _trace_ level messages must be enabled at build time with _-DWITH\_TRACE=On_.
