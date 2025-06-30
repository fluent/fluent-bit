PKGNAME=	interceptor_test
LIBNAME=	interceptor_test
LIBVER=		1

-include ../../Makefile.config

SRCS=		interceptor_test.c

OBJS=		$(SRCS:.c=.o)

# For rdkafka.h
CPPFLAGS+=-I../../src
LDFLAGS+=-L../../src
LIBS+=-lrdkafka

all: lib

include ../../mklove/Makefile.base

clean: lib-clean

-include $(DEPS)
