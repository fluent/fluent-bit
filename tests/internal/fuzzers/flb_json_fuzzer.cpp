#include <stdint.h>
#include <stdlib.h>

extern "C" {
    int flb_pack_json(char*, int, char**, size_t*, int*);
}

extern "C" int LLVMFuzzerTestOneInput(unsigned char *data, size_t size)
{
	// json packer
	char *out_buf = NULL;
	size_t out_size;
	int root_type;
	flb_pack_json((char*)data, size, &out_buf, &out_size, &root_type);
    
    if (out_buf != NULL)
        free(out_buf);

	return 0;
}
