PKGNAME=	librdkafka
LIBNAME=	librdkafka++
LIBVER=		1

CXXSRCS=	RdKafka.cpp ConfImpl.cpp HandleImpl.cpp \
		ConsumerImpl.cpp ProducerImpl.cpp KafkaConsumerImpl.cpp \
		TopicImpl.cpp TopicPartitionImpl.cpp MessageImpl.cpp \
		HeadersImpl.cpp QueueImpl.cpp MetadataImpl.cpp

HDRS=		rdkafkacpp.h

OBJS=		$(CXXSRCS:%.cpp=%.o)



all: lib check

# No linker script/symbol hiding for C++ library
DISABLE_LDS=y

MKL_NO_SELFCONTAINED_STATIC_LIB=y
include ../mklove/Makefile.base

# Use C++ compiler as linker rather than the default C compiler
CC_LD=$(CXX)

# OSX and Cygwin requires linking required libraries
ifeq ($(_UNAME_S),Darwin)
	FWD_LINKING_REQ=y
endif
ifeq ($(_UNAME_S),AIX)
	FWD_LINKING_REQ=y
endif
ifeq ($(shell uname -o 2>/dev/null),Cygwin)
	FWD_LINKING_REQ=y
endif

# Ignore previously defined library dependencies for the C library,
# we'll get those dependencies through the C library linkage.
LIBS := -L../src -lrdkafka
MKL_PKGCONFIG_REQUIRES_PRIVATE := rdkafka
MKL_PKGCONFIG_REQUIRES := rdkafka

CHECK_FILES+= $(LIBFILENAME) $(LIBNAME).a


file-check: lib
check: file-check

install: lib-install
uninstall: lib-uninstall

clean: lib-clean

-include $(DEPS)
