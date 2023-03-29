#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

CC = gcc
CFLAGS := -Wall -g

# Add this to make compiler happy
CFLAGS += -DWASM_ENABLE_INTERP=1

host_api_c=../../../../host-agent/host-api-c
attr_container_dir=../../../../wamr/core/app-framework/app-native-shared
coap_dir=../../../../host-agent/coap
shared_dir=../../../../wamr/core/shared

# core
INCLUDE_PATH = -I$(host_api_c)/src -I$(attr_container_dir)/ \
               -I$(coap_dir)/er-coap -I$(coap_dir)/er-coap/extension \
               -I$(shared_dir)/include \
               -I$(shared_dir)/utils \
               -I$(shared_dir)/platform/include/ \
               -I$(shared_dir)/platform/linux/

LIB := $(host_api_c)/src/libhostapi.a
EXE := ./hostapp

App_C_Files := host_app_sample.c

OBJS := $(App_C_Files:.c=.o)

all: $(EXE)

%.o: %.c
	@$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDE_PATH)

$(EXE): $(OBJS)
	@rm -f $(EXE)
	@$(CC) $(OBJS) -o $(EXE) $(LIB) -lpthread -lrt
	@rm -f $(OBJS)

.PHONY: clean
clean:
	rm -f $(OBJS) $(EXE)
