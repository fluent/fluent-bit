PKGNAME=	librdkafka
LIBNAME=	librdkafka
LIBVER=		1

-include ../Makefile.config

ifneq ($(wildcard ../.git),)
# Add librdkafka version string from git tag if this is a git checkout
CPPFLAGS += -DLIBRDKAFKA_GIT_VERSION="\"$(shell git describe --abbrev=6 --dirty --tags 2>/dev/null)\""
endif

SRCS_$(WITH_SASL_CYRUS) += rdkafka_sasl_cyrus.c
SRCS_$(WITH_SASL_SCRAM) += rdkafka_sasl_scram.c
SRCS_$(WITH_SASL_OAUTHBEARER) += rdkafka_sasl_oauthbearer.c
SRCS_$(WITH_SNAPPY) += snappy.c
SRCS_$(WITH_ZLIB) += rdgz.c
SRCS_$(WITH_ZSTD) += rdkafka_zstd.c
SRCS_$(WITH_HDRHISTOGRAM) += rdhdrhistogram.c
SRCS_$(WITH_SSL) += rdkafka_ssl.c

SRCS_LZ4 = rdxxhash.c
ifneq ($(WITH_LZ4_EXT), y)
# Use built-in liblz4
SRCS_LZ4 += lz4.c lz4frame.c lz4hc.c
endif
SRCS_y += rdkafka_lz4.c $(SRCS_LZ4)

SRCS_$(WITH_LIBDL) += rddl.c
SRCS_$(WITH_PLUGINS) += rdkafka_plugin.c

ifneq ($(HAVE_REGEX), y)
SRCS_y += regexp.c
endif

SRCS=		rdkafka.c rdkafka_broker.c rdkafka_msg.c rdkafka_topic.c \
		rdkafka_conf.c rdkafka_timer.c rdkafka_offset.c \
		rdkafka_transport.c rdkafka_buf.c rdkafka_queue.c rdkafka_op.c \
		rdkafka_request.c rdkafka_cgrp.c rdkafka_pattern.c \
		rdkafka_partition.c rdkafka_subscription.c \
		rdkafka_assignment.c \
		rdkafka_assignor.c rdkafka_range_assignor.c \
		rdkafka_roundrobin_assignor.c rdkafka_sticky_assignor.c \
		rdkafka_feature.c \
		rdcrc32.c crc32c.c rdmurmur2.c rdfnv1a.c \
		rdaddr.c rdrand.c rdlist.c \
		tinycthread.c tinycthread_extra.c \
		rdlog.c rdstring.c rdkafka_event.c rdkafka_metadata.c \
		rdregex.c rdports.c rdkafka_metadata_cache.c rdavl.c \
		rdkafka_sasl.c rdkafka_sasl_plain.c rdkafka_interceptor.c \
		rdkafka_msgset_writer.c rdkafka_msgset_reader.c \
		rdkafka_header.c rdkafka_admin.c rdkafka_aux.c \
		rdkafka_background.c rdkafka_idempotence.c rdkafka_cert.c \
		rdkafka_txnmgr.c rdkafka_coord.c \
		rdvarint.c rdbuf.c rdmap.c rdunittest.c \
		rdkafka_mock.c rdkafka_mock_handlers.c rdkafka_mock_cgrp.c \
		rdkafka_error.c \
		$(SRCS_y)

HDRS=		rdkafka.h rdkafka_mock.h

OBJS=		$(SRCS:.c=.o)


all: lib check

include ../mklove/Makefile.base

CHECK_FILES+= $(LIBFILENAME) $(LIBNAME).a

file-check: lib
check: file-check
	@(printf "%-30s " "Symbol visibility" ; \
		(($(SYMDUMPER) $(LIBFILENAME) | grep rd_kafka_new >/dev/null) && \
		($(SYMDUMPER) $(LIBFILENAME) | grep -v rd_kafka_destroy >/dev/null) && \
		printf "$(MKL_GREEN)OK$(MKL_CLR_RESET)\n") || \
		printf "$(MKL_RED)FAILED$(MKL_CLR_RESET)\n")

install: lib-install
uninstall: lib-uninstall

clean: lib-clean

# Compile LZ4 with -O3
$(SRCS_LZ4:.c=.o): CFLAGS:=$(CFLAGS) -O3

ifeq ($(WITH_LDS),y)
# Enable linker script if supported by platform
LIB_LDFLAGS+= $(LDFLAG_LINKERSCRIPT)$(LIBNAME_LDS)

$(LIBNAME_LDS): $(HDRS)
	@(printf "$(MKL_YELLOW)Generating linker script $@ from $(HDRS)$(MKL_CLR_RESET)\n" ; \
	  cat $(HDRS) | ../lds-gen.py > $@)
endif

-include $(DEPS)
