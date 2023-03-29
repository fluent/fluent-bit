/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define PATH_TEST_FILE "test.txt"
#define FILE_TEXT "Hello, world!"
#define WORLD_OFFSET 7
#define NAME_REPLACMENT "James"
#define NAME_REPLACMENT_LEN (sizeof(NAME_REPLACMENT) - 1)
#define ADDITIONAL_SPACE 10

int
main(int argc, char **argv)
{
    FILE *file;
    const char *text = FILE_TEXT;
    char buffer[1000];
    int ret;

    // Test: File opening (fopen)
    printf("Opening a file..\n");
    file = fopen(PATH_TEST_FILE, "w+");
    if (file == NULL) {
        printf("Error! errno: %d\n", errno);
    }
    assert(file != NULL);
    printf("[Test] File opening passed.\n");

    // Test: Writing to a file (fprintf)
    printf("Writing to the file..\n");
    ret = fprintf(file, "%s", text);
    assert(ret == strlen(text));
    printf("[Test] File writing passed.\n");

    // Test: Reading from a file (fseek)
    printf("Moving the cursor to the start of the file..\n");
    ret = fseek(file, 0, SEEK_SET);
    assert(ret == 0);

    printf("Reading from the file, up to 1000 characters..\n");
    fread(buffer, 1, sizeof(buffer), file);
    printf("Text read: %s\n", buffer);
    assert(strncmp(text, buffer, strlen(text)) == 0);
    printf("[Test] File reading passed.\n");

    // Test: end of file detection (feof)
    printf("Determine whether we reach the end of the file..\n");
    int is_end_of_file = feof(file);
    printf("Is the end of file? %d\n", is_end_of_file);
    assert(is_end_of_file == 1);
    printf("[Test] End of file detection passed.\n");

    // Test: retrieving file offset (ftell)
    printf("Getting the plaintext size..\n");
    long plaintext_size = ftell(file);
    printf("The plaintext size is %ld.\n", plaintext_size);
    assert(plaintext_size == 13);
    printf("[Test] Retrieving file offset passed.\n");

    // Test: persist changes on disk (fflush)
    printf("Force actual write of all the cached data to the disk..\n");
    ret = fflush(file);
    assert(ret == 0);
    printf("[Test] Retrieving file offset passed.\n");

    // Test: writing at specified offset (pwrite)
    printf("Writing 5 characters at offset %d..\n", WORLD_OFFSET);
    ret = pwrite(fileno(file), NAME_REPLACMENT, NAME_REPLACMENT_LEN,
                 WORLD_OFFSET);
    printf("File current offset: %ld\n", ftell(file));
    assert(ret == NAME_REPLACMENT_LEN);
    assert(ftell(file) == strlen(FILE_TEXT));
    printf("[Test] Writing at specified offset passed.\n");

    // Test: reading at specified offset (pread)
    printf("Reading %ld characters at offset %d..\n", NAME_REPLACMENT_LEN,
           WORLD_OFFSET);
    buffer[NAME_REPLACMENT_LEN] = '\0';
    pread(fileno(file), buffer, NAME_REPLACMENT_LEN, WORLD_OFFSET);
    printf("Text read: %s\n", buffer);
    printf("File current offset: %ld\n", ftell(file));
    assert(strcmp(NAME_REPLACMENT, buffer) == 0);
    assert(ftell(file) == strlen(FILE_TEXT));
    printf("[Test] Reading at specified offset passed.\n");

    // Test: allocate more space to the file (posix_fallocate)
    printf("Allocate more space to the file..\n");
    posix_fallocate(fileno(file), ftell(file), ADDITIONAL_SPACE);
    printf("File current offset: %ld\n", ftell(file));
    printf("Moving to the end..\n");
    fseek(file, 0, SEEK_END);
    printf("File current offset: %ld\n", ftell(file));
    assert(ftell(file) == strlen(text) + ADDITIONAL_SPACE);
    printf("[Test] Allocation or more space passed.\n");

    // Test: allocate more space to the file (ftruncate)
    printf("Extend the file size of 10 bytes using ftruncate..\n");
    ftruncate(fileno(file), ftell(file) + 10);
    assert(ftell(file) == strlen(text) + ADDITIONAL_SPACE);
    printf("File current offset: %ld\n", ftell(file));
    printf("Moving to the end..\n");
    fseek(file, 0, SEEK_END);
    printf("File current offset: %ld\n", ftell(file));
    assert(ftell(file) == strlen(text) + 2 * ADDITIONAL_SPACE);
    printf("[Test] Extension of the file size passed.\n");

    // Test: closing the file (fclose)
    printf("Closing from the file..\n");
    ret = fclose(file);
    assert(ret == 0);
    printf("[Test] Closing file passed.\n");

    // Display some debug information
    printf("Getting the size of the file on disk..\n");
    struct stat st;
    stat(PATH_TEST_FILE, &st);
    printf("The file size is %lld.\n", st.st_size);

    printf("All the tests passed!\n");

    return 0;
}
