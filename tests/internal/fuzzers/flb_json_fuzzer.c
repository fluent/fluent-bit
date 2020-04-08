#include <stdint.h>
#include <stdlib.h>

int flb_pack_json(char*, int, char**, size_t*, int*);

int LLVMFuzzerTestOneInput(unsigned char *data, size_t size)
{
	// json packer
	char *out_buf = NULL;
	size_t out_size;
	int root_type;
	int ret = flb_pack_json((char*)data, size, &out_buf, &out_size, &root_type);
    
    if (ret == 0)
        free(out_buf);
    
	return 0;
}
