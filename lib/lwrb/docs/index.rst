LwRB |version| documentation
============================

Welcome to the documentation for version |version|.

LwRB is a generic *FIFO* (First In; First Out) buffer library optimized for embedded systems.

.. image:: static/images/logo.svg
    :align: center

.. rst-class:: center
.. rst-class:: index_links

	:ref:`download_library` :ref:`getting_started` `Open Github <https://github.com/MaJerle/lwrb>`_ `Donate <https://paypal.me/tilz0R>`_

Features
^^^^^^^^

* Written in ANSI C99, compatible with ``size_t`` for size data types
* Platform independent, no architecture specific code
* FIFO (First In First Out) buffer implementation
* No dynamic memory allocation, data is static array
* Uses optimized memory copy instead of loops to read/write data from/to memory
* Thread safe when used as pipe with single write and single read entries
* Interrupt safe when used as pipe with single write and single read entries
* Suitable for DMA transfers from and to memory with zero-copy overhead between buffer and application memory
* Supports data peek, skip for read and advance for write
* Implements support for event notifications
* User friendly MIT license

Requirements
^^^^^^^^^^^^

* C compiler
* Less than ``1kB`` of non-volatile memory

Contribute
^^^^^^^^^^

Fresh contributions are always welcome. Simple instructions to proceed:

#. Fork Github repository
#. Respect `C style & coding rules <https://github.com/MaJerle/c-code-style>`_ used by the library
#. Create a pull request to ``develop`` branch with new features or bug fixes

Alternatively you may:

#. Report a bug
#. Ask for a feature request

Example code
^^^^^^^^^^^^

Minimalistic example code to read and write data to buffer

.. literalinclude:: examples_src/example_index.c
    :language: c
    :linenos:
    :caption: Example code

License
^^^^^^^

.. literalinclude:: ../LICENSE

Table of contents
^^^^^^^^^^^^^^^^^

.. toctree::
    :maxdepth: 2
    :caption: Contents

    self
    get-started/index
    user-manual/index
    tips-tricks/index
    api-reference/index

.. toctree::
    :maxdepth: 2
    :caption: Other projects
    :hidden:

    LwDTC - DateTimeCron <https://github.com/MaJerle/lwdtc>
    LwESP - ESP-AT library <https://github.com/MaJerle/lwesp>
    LwEVT - Event manager <https://github.com/MaJerle/lwevt>
    LwGPS - GPS NMEA parser <https://github.com/MaJerle/lwgps>
    LwGSM - GSM-AT library <https://github.com/MaJerle/lwgsm>
    LwJSON - JSON parser <https://github.com/MaJerle/lwjson>
    LwMEM - Memory manager <https://github.com/MaJerle/lwmem>
    LwOW - OneWire with UART <https://github.com/MaJerle/lwow>
    LwPKT - Packet protocol <https://github.com/MaJerle/lwpkt>
    LwPRINTF - Printf <https://github.com/MaJerle/lwprintf>
    LwRB - Ring buffer <https://github.com/MaJerle/lwrb>
    LwSHELL - Shell <https://github.com/MaJerle/lwshell>
    LwUTIL - Utility functions <https://github.com/MaJerle/lwutil>