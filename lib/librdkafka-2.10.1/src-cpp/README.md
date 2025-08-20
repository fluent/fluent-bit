librdkafka C++ interface
========================

**See rdkafkacpp.h for the public C++ API**



Maintainer notes for the C++ interface:

 * The public C++ interface (rdkafkacpp.h) does not include the
   public C interface (rdkafka.h) in any way, this means that all
   constants, flags, etc, must be kept in sync manually between the two
   header files.
   A regression test should be implemented that checks this is true.

 * The public C++ interface is provided using pure virtual abstract classes.
