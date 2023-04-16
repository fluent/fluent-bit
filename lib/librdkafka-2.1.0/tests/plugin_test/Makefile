LIBNAME=	plugin_test
LIBVER=		1

-include ../../Makefile.config

SRCS=		plugin_test.c

OBJS=		$(SRCS:.c=.o)

# For rdkafka.h
CPPFLAGS+=-I../../src

all: lib

include ../../mklove/Makefile.base

clean: lib-clean

-include $(DEPS)
