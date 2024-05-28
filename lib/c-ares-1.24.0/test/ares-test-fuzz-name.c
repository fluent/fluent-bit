/*
 * Copyright (C) The c-ares project
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ares.h"
// Include ares internal file for DNS protocol constants
#include "ares_nameser.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);

// Entrypoint for Clang's libfuzzer, exercising query creation.
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
  // Null terminate the data.
  char          *name   = malloc(size + 1);
  unsigned char *buf    = NULL;
  int            buflen = 0;
  name[size]            = '\0';
  memcpy(name, data, size);

  ares_create_query(name, C_IN, T_AAAA, 1234, 0, &buf, &buflen, 1024);
  free(buf);
  free(name);
  return 0;
}
