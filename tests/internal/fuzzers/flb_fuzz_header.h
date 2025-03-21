/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdint.h>
#include <string.h>

#define GET_MOD_EQ(max, idx) (data[0] % max) == idx
#define MOVE_INPUT(offset) data += offset; size -= offset;

#define TIMEOUT_GUARD if (size > 32768) return 0;

char *get_null_terminated(size_t size, const uint8_t **data,
                          size_t *total_data_size)
{
  char *tmp = flb_malloc(size+1);
  if (tmp == NULL) {
    tmp = malloc(size+1);
  }
  memcpy(tmp, *data, size);
  tmp[size] = '\0';

  /* Modify the fuzz variables */
  *total_data_size -= size;
  *data += size;

  return tmp;
}
