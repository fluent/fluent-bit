.. _events:

Events
======

When using LwRB in the application, it may be useful to get notification on different events,
such as info when something has been written or read to/from buffer.

Library has support for events that get called each time there has been a modification
in the buffer data, that means on every read or write operation.

Some use cases:

* Notify application layer that LwRB operation has been executed and send debug message
* Unlock semaphore when sufficient amount of bytes have been written/read from/to buffer when application uses operating system
* Write notification to message queue at operating system level to wakeup another task

.. note:: Every operation that modified `read` or `write` internal pointers,
        is considered as read or write operation. An exception is *reset* event that sets
        both internal pointers to `0`

.. literalinclude:: ../examples_src/example_events.c
    :language: c
    :linenos:
    :caption: Example code for events

.. toctree::
    :maxdepth: 2