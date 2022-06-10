.. _tips_tricks:

Tips & tricks
=============

Application buffer size
^^^^^^^^^^^^^^^^^^^^^^^

Buffer size shall always be ``1`` byte bigger than anticipated data size.

When application uses buffer for some data block ``N`` times, it is advised to set buffer size to ``1`` byte more than ``N * block_size`` is.
This is due to ``R`` and ``W`` pointers alignment.

.. note:: 
    For more information, check :ref:`how_it_works`.

.. literalinclude:: ../examples_src/example_tt_buff_size.c
    :language: c
    :linenos:
    :caption: Application buffer size assignment

When the code is executed, it produces following output:

.. literalinclude:: ../examples_src/example_tt_buff_size_log.c
    :caption: Application buffer size assignment output

.. toctree::
    :maxdepth: 2