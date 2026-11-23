#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_sds.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <fluent-bit/flb_utils.h>
#ifdef FLB_SYSTEM_WINDOWS
#include <io.h>
#else
#include <unistd.h>
#endif

#include "flb_tests_internal.h"
#include "fluent-bit/stream_processor/flb_sp.h"

#define TEXT_FILE    FLB_TESTS_DATA_PATH "/data/file/text_file.txt"
#define EMPTY_FILE    FLB_TESTS_DATA_PATH "/data/file/empty_file.txt"

static void check_equals(flb_sds_t result, const char *expected)
{
    size_t expected_len = strlen(expected);
    size_t result_len = flb_sds_len(result);
    TEST_CHECK(expected_len == result_len);
    TEST_MSG("Expected length: %zu", expected_len);
    TEST_MSG("Actual length:   %zu", result_len);
    TEST_CHECK(memcmp(result, expected, expected_len) == 0);
    TEST_MSG("Expected: %s", expected);
    TEST_MSG("Actual:   %s", result);
}

static void test_file_read_text_file()
{
    flb_sds_t result = flb_file_read(TEXT_FILE);
    /* In Windows, \n is replaced with \r\n by git settings. */
    if (strstr(result, "\r\n") != NULL) {
      check_equals(result, "Some text file\r\n\r\nline 3\r\n\r\nline 5\r\n");
    }
    else {
      check_equals(result, "Some text file\n\nline 3\n\nline 5\n");
    }
    flb_sds_destroy(result);
}

static void test_file_read_empty_file()
{
    flb_sds_t result = flb_file_read(EMPTY_FILE);
    check_equals(result, "");
    flb_sds_destroy(result);
}

static void test_file_read_missing()
{
    flb_sds_t result = flb_file_read(TEXT_FILE ".missing");
    TEST_CHECK(result == NULL);
}

#ifdef FLB_SYSTEM_WINDOWS
static void test_file_windows_mkdir(void)
{
    char directory[MAX_PATH];
    char path[MAX_PATH];
    DWORD length;

    length = GetTempPathA(sizeof(directory), directory);
    TEST_ASSERT(length > 0 && length < sizeof(directory));
    TEST_ASSERT(GetTempFileNameA(directory, "flb", 0, path) != 0);
    TEST_CHECK(flb_file_mkdir_safe("", 0755) == -1);
    TEST_CHECK(errno == EINVAL);
    TEST_CHECK(flb_file_mkdir_safe(path, 0755) == -1);
    TEST_ASSERT(DeleteFileA(path) != 0);
    TEST_CHECK(flb_file_mkdir_safe(path, 0755) == 0);
    TEST_CHECK(flb_file_mkdir_safe(path, 0755) == 0);
    TEST_CHECK(RemoveDirectoryA(path) != 0);
}

static void test_file_windows_root_join(void)
{
    char directory[MAX_PATH];
    char filename[MAX_PATH];
    char extended_root[MAX_PATH + 8];
    char oversized_root[MAX_PATH + 1];
    char oversized_path[MAX_PATH + 1];
    char *name;
    DWORD length;
    int fd;

    length = GetTempPathA(sizeof(directory), directory);
    TEST_ASSERT(length > 0 && length < sizeof(directory));
    TEST_ASSERT(GetTempFileNameA(directory, "flb", 0, filename) != 0);
    name = strrchr(filename, '\\');
    TEST_ASSERT(name != NULL);
    name++;

    /* GetTempPathA supplies a trailing backslash. */
    fd = flb_file_open_safe(directory, name, O_RDONLY, 0, 0);
    TEST_CHECK(fd >= 0);
    if (fd >= 0) {
        close(fd);
    }
    directory[length - 1] = '/';
    fd = flb_file_open_safe(directory, name, O_RDONLY, 0, 0);
    TEST_CHECK(fd >= 0);
    if (fd >= 0) {
        close(fd);
    }
    directory[length - 1] = '\0';
    fd = flb_file_open_safe(directory, name, O_RDONLY, 0, 0);
    TEST_CHECK(fd >= 0);
    if (fd >= 0) {
        close(fd);
    }

    if (strncmp(directory, "\\\\", 2) == 0) {
        snprintf(extended_root, sizeof(extended_root), "\\\\?\\UNC\\%s", directory + 2);
    }
    else {
        snprintf(extended_root, sizeof(extended_root), "\\\\?\\%s", directory);
    }
    fd = flb_file_open_safe(extended_root, name, O_RDONLY, 0, 0);
    TEST_CHECK(fd >= 0);
    if (fd >= 0) {
        close(fd);
    }
    TEST_CHECK(DeleteFileA(filename) != 0);

    memset(oversized_root, 'a', sizeof(oversized_root) - 1);
    oversized_root[sizeof(oversized_root) - 1] = '\0';
    TEST_CHECK(flb_file_open_safe(oversized_root, "file", O_RDONLY, 0, 0) == -1);
    TEST_CHECK(errno == ENAMETOOLONG);

    memset(oversized_path, 'b', sizeof(oversized_path) - 1);
    oversized_path[sizeof(oversized_path) - 1] = '\0';
    TEST_CHECK(flb_file_open_safe(directory, oversized_path, O_RDONLY, 0, 0) == -1);
    TEST_CHECK(errno == ENAMETOOLONG);

    /* Each component fits alone, but the joined path needs space for its NUL. */
    oversized_root[MAX_PATH - 3] = '\0';
    TEST_CHECK(flb_file_open_safe(oversized_root, "ab", O_RDONLY, 0, 0) == -1);
    TEST_CHECK(errno == ENAMETOOLONG);
    oversized_root[MAX_PATH - 4] = FLB_DIRCHAR;
    TEST_CHECK(flb_file_open_safe(oversized_root, "abc", O_RDONLY, 0, 0) == -1);
    TEST_CHECK(errno == ENAMETOOLONG);
    TEST_CHECK(flb_file_open_safe("", "file", O_RDONLY, 0, 0) == -1);
    TEST_CHECK(errno == EINVAL);
    TEST_CHECK(flb_file_open_safe("C:", "file", O_RDONLY, 0, 0) == -1);
    TEST_CHECK(errno == EINVAL);
    TEST_CHECK(flb_file_open_safe(directory, NULL, O_RDONLY, 0, 0) == -1);
    TEST_CHECK(errno == EINVAL);
}

static void test_file_windows_multibyte_root(void)
{
    char directory[MAX_PATH];
    char root[MAX_PATH];
    char joined_root[MAX_PATH];
    char sibling[MAX_PATH];
    char buffer[8] = {0};
    const char *separators[] = {"", "/", "\\"};
    DWORD length;
    size_t index;
    FILE *stream;

    if (GetACP() != 932) {
        TEST_MSG("Requires Windows ANSI code page 932");
        return;
    }
    length = GetTempPathA(sizeof(directory), directory);
    TEST_ASSERT(length > 0 && length < sizeof(directory));
    TEST_ASSERT(GetTempFileNameA(directory, "flb", 0, root) != 0);
    TEST_ASSERT(DeleteFileA(root) != 0);
    TEST_ASSERT(CreateDirectoryA(root, NULL) != 0);
    snprintf(directory, sizeof(directory), "%s", root);
    /* U+8868 (表) ends in byte 0x5c under code page 932. */
    snprintf(root, sizeof(root), "%s/\x95\x5c", directory);
    TEST_ASSERT(CreateDirectoryA(root, NULL) != 0);
    snprintf(sibling, sizeof(sibling), "%sfile", root);
    stream = fopen(sibling, "wb");
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(fwrite("secret", 1, 6, stream) == 6);
    fclose(stream);

    for (index = 0; index < sizeof(separators) / sizeof(separators[0]); index++) {
        snprintf(joined_root, sizeof(joined_root), "%s%s", root, separators[index]);
        stream = flb_file_fopen_safe(joined_root, "file", "wb", 0);
        TEST_ASSERT(stream != NULL);
        fclose(stream);
        snprintf(joined_root, sizeof(joined_root), "%s/file", root);
        TEST_CHECK(DeleteFileA(joined_root) != 0);
        stream = fopen(sibling, "rb");
        TEST_ASSERT(stream != NULL);
        TEST_CHECK(fread(buffer, 1, sizeof(buffer), stream) == 6);
        TEST_CHECK(strcmp(buffer, "secret") == 0);
        fclose(stream);
    }
    TEST_CHECK(DeleteFileA(sibling) != 0);
    TEST_CHECK(RemoveDirectoryA(root) != 0);
    TEST_CHECK(RemoveDirectoryA(directory) != 0);
}

static void test_file_windows_mutations(void)
{
    char directory[MAX_PATH];
    char root[MAX_PATH];
    char source[MAX_PATH];
    char destination[MAX_PATH];
    char buffer[8] = {0};
    DWORD length;
    FILE *stream;

    length = GetTempPathA(sizeof(directory), directory);
    TEST_ASSERT(length > 0 && length < sizeof(directory));
    TEST_ASSERT(GetTempFileNameA(directory, "flb", 0, root) != 0);
    TEST_ASSERT(DeleteFileA(root) != 0);
    snprintf(source, sizeof(source), "%s/nested/source", root);
    snprintf(destination, sizeof(destination), "%s/nested/destination", root);

    stream = flb_file_fopen_safe(NULL, source, "wb", 0755);
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(fwrite("first", 1, 5, stream) == 5);
    fclose(stream);
    TEST_CHECK(flb_file_fopen_safe(NULL, source, "wx", 0) == NULL);
    TEST_CHECK(errno == EINVAL);
    stream = flb_file_fopen_safe(NULL, source, "ab", 0);
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(fwrite("+", 1, 1, stream) == 1);
    fclose(stream);

    stream = flb_file_fopen_safe(NULL, destination, "wb", 0);
    TEST_ASSERT(stream != NULL);
    fclose(stream);
    TEST_CHECK(flb_file_rename_safe(source, destination) == 0);
    stream = flb_file_fopen_safe(root, "nested/destination", "rb", 0);
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(fread(buffer, 1, sizeof(buffer), stream) == 6);
    TEST_CHECK(strcmp(buffer, "first+") == 0);
    fclose(stream);

    TEST_CHECK(flb_file_open_safe(root, "../escape", O_RDONLY, 0, 0) == -1);
    TEST_CHECK(flb_file_open_safe(root, "/escape", O_RDONLY, 0, 0) == -1);
    TEST_CHECK(flb_file_open_safe(root, "destination:stream", O_RDONLY, 0, 0) == -1);
    TEST_CHECK(flb_file_unlink_safe(destination) == 0);
    stream = flb_file_fopen_safe(NULL, source, "wb", 0);
    TEST_ASSERT(stream != NULL);
    fclose(stream);
    TEST_CHECK(flb_file_remove_tree_safe(root) == 0);
    TEST_CHECK(GetFileAttributesA(root) == INVALID_FILE_ATTRIBUTES);
}

static void test_file_windows_remove_depth(void)
{
    char directory[MAX_PATH];
    char root[MAX_PATH];
    char path[MAX_PATH];
    DWORD length;
    int depth;

    length = GetTempPathA(sizeof(directory), directory);
    TEST_ASSERT(length > 0 && length < sizeof(directory));
    TEST_ASSERT(GetTempFileNameA(directory, "flb", 0, root) != 0);
    TEST_ASSERT(DeleteFileA(root) != 0);
    length = (DWORD) strlen(root);
    TEST_ASSERT(length + 2 * 64 < sizeof(path));
    strcpy(path, root);
    for (depth = 0; depth < 64; depth++) {
        strcat(path, "/d");
    }
    TEST_ASSERT(flb_file_mkdir_safe(path, 0755) == 0);
    TEST_CHECK(flb_file_remove_tree_safe(root) == -1);
    TEST_CHECK(errno == ELOOP);
    TEST_CHECK(GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES);
    TEST_CHECK(RemoveDirectoryA(path) != 0);
    TEST_CHECK(flb_file_remove_tree_safe(root) == 0);
}
#else
static void test_file_containment(void)
{
    char template[] = "/tmp/flb-file-safe-XXXXXX";
    char directory[PATH_MAX];
    char path[PATH_MAX + 32];
    char other[PATH_MAX + 32];
    char victim[PATH_MAX + 32];
    char content[8] = {0};
    char *buffer;
    size_t size;
    int fd;
    FILE *stream;

    TEST_ASSERT(mkdtemp(template) != NULL);
    TEST_ASSERT(realpath(template, directory) != NULL);
    TEST_CHECK(flb_file_mkdir_safe("", 0700) == -1);
    TEST_CHECK(errno == EINVAL);
    stream = flb_file_fopen_safe(directory, "regular", "w+", 0);
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(fwrite("secret", 1, 6, stream) == 6);
    fclose(stream);
    TEST_CHECK(flb_file_fopen_safe(directory, "regular", "wx", 0) == NULL);
    TEST_CHECK(errno == EINVAL);

    snprintf(path, sizeof(path), "%s/link", directory);
    TEST_CHECK(symlink("regular", path) == 0);
    TEST_CHECK(flb_file_fopen_safe(directory, "link", "w", 0) == NULL);
    TEST_CHECK(flb_utils_read_file_offset_safe(path, 0, 0, &buffer, &size) == -1);
    TEST_ASSERT(flb_utils_read_file_offset(path, 0, 0, &buffer, &size) == 0);
    TEST_CHECK(size == 6);
    TEST_CHECK(memcmp(buffer, "secret", 6) == 0);
    flb_free(buffer);
    TEST_CHECK(unlink(path) == 0);
    TEST_CHECK(symlink("missing", path) == 0);
    TEST_CHECK(flb_file_fopen_safe(directory, "link", "w", 0) == NULL);
    TEST_CHECK(unlink(path) == 0);

    snprintf(other, sizeof(other), "%s-other", directory);
    TEST_ASSERT(mkdir(other, 0700) == 0);
    snprintf(victim, sizeof(victim), "%s-other/victim", directory);
    stream = fopen(victim, "wb");
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(fwrite("secret", 1, 6, stream) == 6);
    fclose(stream);
    TEST_CHECK(symlink(other, path) == 0);
    TEST_CHECK(flb_file_fopen_safe(directory, "link/new/file", "w", 0700) == NULL);
    TEST_CHECK(flb_file_fopen_safe(directory, "../escape", "w", 0700) == NULL);
    TEST_CHECK(flb_file_fopen_safe(directory, other, "w", 0700) == NULL);
    TEST_CHECK(flb_file_mkdir_safe(path, 0700) == -1);
    TEST_CHECK(flb_file_open_safe(directory, "link", O_RDONLY | O_DIRECTORY, 0, 0) == -1);
    snprintf(path, sizeof(path), "%s/link/victim", directory);
    TEST_CHECK(flb_file_unlink_safe(path) == -1);
    stream = fopen(victim, "rb");
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(fread(content, 1, sizeof(content), stream) == 6);
    TEST_CHECK(strcmp(content, "secret") == 0);
    fclose(stream);
    snprintf(other, sizeof(other), "%s/regular", directory);
    TEST_CHECK(flb_file_rename_safe(other, path) == -1);
    snprintf(path, sizeof(path), "%s/link", directory);
    snprintf(other, sizeof(other), "%s-other", directory);
    TEST_CHECK(unlink(path) == 0);
    TEST_CHECK(unlink(victim) == 0);
    TEST_CHECK(rmdir(other) == 0);

    stream = flb_file_fopen_safe(directory, "nested/file", "a+", 0700);
    TEST_ASSERT(stream != NULL);
    fclose(stream);
    snprintf(path, sizeof(path), "%s/nested//file", directory);
    snprintf(other, sizeof(other), "%s///renamed", directory);
    TEST_CHECK(flb_file_rename_safe(path, other) == 0);
    TEST_CHECK(flb_file_unlink_safe(other) == 0);
    snprintf(path, sizeof(path), "%s/nested", directory);
    TEST_CHECK(rmdir(path) == 0);

    snprintf(path, sizeof(path), "%s/fifo", directory);
    TEST_ASSERT(mkfifo(path, 0600) == 0);
    TEST_CHECK(flb_file_open_safe(NULL, path, O_RDONLY, 0, 0) == -1);
    TEST_CHECK(unlink(path) == 0);

    fd = flb_file_open_safe(directory, "regular", O_RDONLY, 0, 0);
    TEST_ASSERT(fd >= 0);
    TEST_CHECK(read(fd, content, sizeof(content)) == 6);
    TEST_CHECK(strcmp(content, "secret") == 0);
    close(fd);
    snprintf(path, sizeof(path), "%s/regular", directory);
    TEST_CHECK(unlink(path) == 0);
    TEST_CHECK(rmdir(directory) == 0);
}
#endif

TEST_LIST = {
#ifdef FLB_SYSTEM_WINDOWS
    { "file_windows_mkdir", test_file_windows_mkdir },
    { "file_windows_root_join", test_file_windows_root_join },
    { "file_windows_multibyte_root", test_file_windows_multibyte_root },
    { "file_windows_mutations", test_file_windows_mutations },
    { "file_windows_remove_depth", test_file_windows_remove_depth },
#else
    { "file_containment", test_file_containment },
#endif
    { "file_read_text_file" , test_file_read_text_file},
    { "file_read_empty_file" , test_file_read_empty_file},
    { "file_read_missing" , test_file_read_missing},
    { 0 }
};
