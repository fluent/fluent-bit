#include <stdint.h>
#include <string.h>

#define GET_MOD_EQ(max, idx) (data[0] % max) == idx
#define MOVE_INPUT(offset) data += offset; size -= offset;

char *get_null_terminated(size_t size, const uint8_t **data, 
                          size_t *total_data_size) 
{
  char *tmp = flb_malloc(size+1);
  memcpy(tmp, *data, size);
  tmp[size] = '\0';

  /* Modify the fuzz variables */
  *total_data_size -= size;
  *data += size;

  return tmp;
}
