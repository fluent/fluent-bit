/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

static unsigned char *
read_file_to_buffer(const char *filename, int *ret_size)
{
    unsigned char *buffer;
    FILE *file;
    int file_size, read_size;

    if (!(file = fopen(filename, "rb")))
        return NULL;

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (!(buffer = malloc(file_size))) {
        fclose(file);
        return NULL;
    }

    read_size = fread(buffer, 1, file_size, file);
    fclose(file);

    if (read_size < file_size) {
        free(buffer);
        return NULL;
    }

    *ret_size = file_size;

    return buffer;
}

static int
print_help()
{
    printf("Usage: binarydump -o <file> -n <name> input_file\n");
    printf("Options:\n");
    printf("  -o <file>      Place the output into <file>\n");
    printf("  -n <name>      The name of array <file>\n");

    return -1;
}

static bool
bin_file_dump(const unsigned char *file, int size, const char *bin_file_output,
              const char *array_name)
{
    unsigned i = 0;
    const unsigned char *p = file, *p_end = file + size;
    FILE *file_output = fopen(bin_file_output, "wb+");

    if (!file_output)
        return false;

    fprintf(file_output, "\nunsigned char __aligned(4) %s[] = {\n  ",
            array_name);

    while (p < p_end) {
        fprintf(file_output, "0x%02X", *p++);

        if (p == p_end)
            break;

        fprintf(file_output, ",");

        if ((++i % 12) != 0)
            fprintf(file_output, " ");
        else
            fprintf(file_output, "\n  ");
    }

    fprintf(file_output, "\n};\n");

    fclose(file_output);
    return true;
}

int
main(int argc, char *argv[])
{
    unsigned char *file;
    int size;
    bool ret;
    const char *bin_file_input, *array_file_output = NULL, *array_name = NULL;

    for (argc--, argv++; argc > 0 && argv[0][0] == '-'; argc--, argv++) {
        if (!strcmp(argv[0], "-o")) {
            ++argv;
            if (--argc == 0)
                return print_help();
            array_file_output = *argv;
        }
        else if (!strcmp(argv[0], "-n")) {
            ++argv;
            if (--argc == 0)
                return print_help();
            array_name = *argv;
        }
        else
            return print_help();
    }

    if (!array_file_output || !array_name)
        return print_help();

    bin_file_input = *argv;

    if (!(file = read_file_to_buffer(bin_file_input, &size)))
        return -1;

    ret = bin_file_dump(file, size, array_file_output, array_name);

    free(file);

    return ret ? 0 : -1;
}
