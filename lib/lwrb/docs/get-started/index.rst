.. _getting_started:

Getting started
===============

Getting started may be the most challenging part of every new library.
This guide is describing how to start with the library quickly and effectively

.. _download_library:

Download library
^^^^^^^^^^^^^^^^

Library is primarly hosted on `Github <https://github.com/MaJerle/lwrb>`_.

You can get it by:

* Downloading latest release from `releases area <https://github.com/MaJerle/lwrb/releases>`_ on Github
* Cloning ``main`` branch for latest stable version
* Cloning ``develop`` branch for latest development

Download from releases
**********************

All releases are available on Github `releases area <https://github.com/MaJerle/lwrb/releases>`_.

Clone from Github
*****************

First-time clone
""""""""""""""""

This is used when you do not have yet local copy on your machine.

* Make sure ``git`` is installed.
* Open console and navigate to path in the system to clone repository to. Use command ``cd your_path``
* Clone repository with one of available options below

  * Run ``git clone --recurse-submodules https://github.com/MaJerle/lwrb`` command to clone entire repository, including submodules
  * Run ``git clone --recurse-submodules --branch develop https://github.com/MaJerle/lwrb`` to clone `development` branch, including submodules
  * Run ``git clone --recurse-submodules --branch main https://github.com/MaJerle/lwrb`` to clone `latest stable` branch, including submodules

* Navigate to ``examples`` directory and run favourite example

Update cloned to latest version
"""""""""""""""""""""""""""""""

* Open console and navigate to path in the system where your repository is located. Use command ``cd your_path``
* Run ``git pull origin main`` command to get latest changes on ``main`` branch
* Run ``git pull origin develop`` command to get latest changes on ``develop`` branch
* Run ``git submodule update --init --remote`` to update submodules to latest version

.. note::
	This is preferred option to use when you want to evaluate library and run prepared examples.
	Repository consists of multiple submodules which can be automatically downloaded when cloning and pulling changes from root repository.

Add library to project
^^^^^^^^^^^^^^^^^^^^^^

At this point it is assumed that you have successfully download library, either cloned it or from releases page.
Next step is to add the library to the project, by means of source files to compiler inputs and header files in search path

* Copy ``lwrb`` folder to your project, it contains library files
* Add ``lwrb/src/include`` folder to `include path` of your toolchain. This is where `C/C++` compiler can find the files during compilation process. Usually using ``-I`` flag
* Add source files from ``lwrb/src/`` folder to toolchain build. These files are built by `C/C++` compilery
* Build the project

Minimal example code
^^^^^^^^^^^^^^^^^^^^

To verify proper library setup, minimal example has been prepared.
Run it in your main application file to verify its proper execution

.. literalinclude:: ../examples_src/example_minimal.c
    :language: c
    :linenos:
    :caption: Absolute minimum example