/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include "azure_kusto_store.h"
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_fstore.h>
#include <fluent-bit/flb_time.h>

/**
 * Generates a unique store filename based on a given tag and the current time.
 *
 * This function creates a unique filename by computing a hash from the provided
 * tag and combining it with a hash derived from the current time. The resulting
 * filename is intended to be used for storing data in a way that ensures
 * uniqueness and avoids collisions.
 *
 * Parameters:
 * - tag: A constant character pointer representing the tag for which the
 *   filename is being generated. This tag is used as part of the hash
 *   computation to ensure that filenames are unique to each tag.
 *
 * Returns:
 * - A dynamically allocated `flb_sds_t` string containing the generated
 *   filename. The caller is responsible for freeing this string using
 *   `flb_sds_destroy` when it is no longer needed.
 * - Returns `NULL` if memory allocation fails during the process.
 *
 * Behavior:
 * - The function first retrieves the current time using `flb_time_get`.
 * - It then computes a hash from the input tag using the DJB2 algorithm.
 * - A secondary hash is computed using the current time's seconds and
 *   nanoseconds to further ensure uniqueness.
 * - The function formats these hashes into a string using `flb_sds_printf`,
 *   ensuring that the resulting filename is unique for each tag and time
 *   combination.
 * - If any memory allocation fails, the function logs an error using
 *   `flb_errno` and returns `NULL`.
 */

static flb_sds_t gen_store_filename(const char *tag)
{
    int c;
    unsigned long hash = 5381;
    unsigned long hash2 = 5381;
    flb_sds_t hash_str;
    flb_sds_t tmp;
    struct flb_time tm;

    /* get current time */
    flb_time_get(&tm);

    /* compose hash */
    while ((c = *tag++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    hash2 = (unsigned long) hash2 * tm.tm.tv_sec * tm.tm.tv_nsec;

    /* flb_sds_printf allocs if the incoming sds is not at least 64 bytes */
    hash_str = flb_sds_create_size(64);
    if (!hash_str) {
        flb_errno();
        return NULL;
    }
    tmp = flb_sds_printf(&hash_str, "%lu-%lu", hash, hash2);
    if (!tmp) {
        flb_errno();
        flb_sds_destroy(hash_str);
        return NULL;
    }
    hash_str = tmp;

    return hash_str;
}


/**
 * Retrieve a candidate buffer file using the tag.
 *
 * This function searches through the list of active files in the current
 * Azure Kusto plugin context to find a file that matches the specified tag. The
 * tag is used as a lookup pattern to identify the appropriate file for
 * storing incoming data.
 *
 * The function iterates over the list of files associated with the active
 * stream in the context. For each file, it performs the following checks:
 *
 * 1. **Null Data Check**: If a file's data reference is NULL, it logs a
 *    warning and attempts to delete the file, as it indicates a partially
 *    initialized chunk.
 *
 * 2. **Meta Size Check**: Compares the size of the file's metadata with
 *    the length of the provided tag. If they do not match, the file is
 *    skipped.
 *
 * 3. **Locked File Check**: If the file is locked, it logs a debug message
 *    and skips the file, as locked files are not eligible for selection.
 *
 * 4. **Tag Comparison**: Compares the file's metadata buffer with the
 *    provided tag. If they match, it logs a debug message indicating a
 *    successful match and breaks out of the loop.
 *
 * If a matching file is found, the function returns a pointer to the
 * `azure_kusto_file` structure associated with the file. If no match is
 * found, it returns NULL.
 *
 * @param ctx     Pointer to the Azure Kusto plugin context containing the active
 *                stream and file list.
 * @param tag     The tag used as a lookup pattern to find the matching file.
 * @param tag_len The length of the tag.
 *
 * @return A pointer to the `azure_kusto_file` structure if a matching file
 *         is found; otherwise, NULL.
 */
struct azure_kusto_file *azure_kusto_store_file_get(struct flb_azure_kusto *ctx, const char *tag,
                                                    int tag_len)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_fstore_file *fsf = NULL;
    struct azure_kusto_file *azure_kusto_file;
    int found = 0;

    /*
     * Based in the current ctx->stream_name, locate a candidate file to
     * store the incoming data using as a lookup pattern the content Tag.
     */
    mk_list_foreach_safe(head, tmp, &ctx->stream_active->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);

        /* skip and warn on partially initialized chunks */
        if (fsf->data == NULL) {
            flb_plg_warn(ctx->ins, "BAD: found flb_fstore_file with NULL data reference, tag=%s, file=%s, will try to delete", tag, fsf->name);
            flb_fstore_file_delete(ctx->fs, fsf);
        }

        if (fsf->meta_size != tag_len) {
            fsf = NULL;
            continue;
        }

        /* skip locked chunks */
        azure_kusto_file = fsf->data;
        if (azure_kusto_file->locked == FLB_TRUE) {
            flb_plg_debug(ctx->ins, "File '%s' is locked, skipping", fsf->name);
            fsf = NULL;
            continue;
        }


        /* compare meta and tag */
        if (strncmp((char *) fsf->meta_buf, tag, tag_len) == 0 ) {
            flb_plg_debug(ctx->ins, "Found matching file '%s' for tag '%.*s'", fsf->name, tag_len, tag);
            found = 1;
            break;
        }
    }

    if (!found) {
        return NULL;
    }
    else {
        return fsf->data;
    }
}

/**
 * Append data to a new or existing fstore file.
 *
 * This function is responsible for appending data to a file in the Azure Kusto
 * buffer storage system. It handles both the creation of new files and the appending
 * of data to existing files. The function ensures that the buffer does not
 * exceed the specified storage limit and manages file metadata and context.
 *
 * Parameters:
 * - ctx: A pointer to the flb_azure_kusto context, which contains configuration
 *   and state information for the Azure Kusto storage system.
 * - azure_kusto_file: A pointer to an existing azure_kusto_file structure. If
 *   NULL, a new file will be created.
 * - tag: A string representing the tag associated with the data. This is used
 *   for metadata purposes.
 * - tag_len: The length of the tag string.
 * - data: The data to be appended to the file.
 * - bytes: The size of the data in bytes.
 *
 * Returns:
 * - 0 on success, indicating that the data was successfully appended to the
 *   file.
 * - -1 on failure, indicating an error occurred during the process, such as
 *   exceeding the buffer limit, file creation failure, or metadata writing
 *   failure.
 *
 * The function performs the following steps:
 * 1. Checks if adding the new data would exceed the storage directory limit.
 * 2. If no target file is provided, it generates a new file name and creates
 *    a new file in the storage system.
 * 3. Writes the tag as metadata to the newly created file.
 * 4. Allocates a new buffer file context and associates it with the file.
 * 5. Appends the data to the target file.
 * 6. Updates the file and buffer sizes.
 * 7. Warns the user if the buffer is nearing its capacity.
 */
int azure_kusto_store_buffer_put(struct flb_azure_kusto *ctx, struct azure_kusto_file *azure_kusto_file,
                                 flb_sds_t tag, size_t tag_len,
                                 flb_sds_t data, size_t bytes) {
    int ret;
    flb_sds_t name;
    struct flb_fstore_file *fsf;
    size_t space_remaining;

    if (ctx->store_dir_limit_size > 0 && ctx->current_buffer_size + bytes >= ctx->store_dir_limit_size) {
        flb_plg_error(ctx->ins, "Buffer is full: current_buffer_size=%zu, new_data=%zu, store_dir_limit_size=%zu bytes",
                      ctx->current_buffer_size, bytes, ctx->store_dir_limit_size);
        return -1;
    }

    /* If no target file was found, create a new one */
    if (azure_kusto_file == NULL) {
        name = gen_store_filename(tag);
        if (!name) {
            flb_plg_error(ctx->ins, "could not generate chunk file name");
            return -1;
        }

        flb_plg_debug(ctx->ins, "[azure_kusto] new buffer file: %s", name);

        /* Create the file */
        fsf = flb_fstore_file_create(ctx->fs, ctx->stream_active, name, bytes);
        if (!fsf) {
            flb_plg_error(ctx->ins, "could not create the file '%s' in the store",
                          name);
            flb_sds_destroy(name);
            return -1;
        }

        /* Write tag as metadata */
        ret = flb_fstore_file_meta_set(ctx->fs, fsf, (char *) tag, tag_len);
        if (ret == -1) {
            flb_plg_warn(ctx->ins, "Deleting buffer file because metadata could not be written");
            flb_fstore_file_delete(ctx->fs, fsf);
            return -1;
        }

        /* Allocate local context */
        azure_kusto_file = flb_calloc(1, sizeof(struct azure_kusto_file));
        if (!azure_kusto_file) {
            flb_errno();
            flb_plg_warn(ctx->ins, "Deleting buffer file because azure_kusto context creation failed");
            flb_fstore_file_delete(ctx->fs, fsf);
            return -1;
        }
        azure_kusto_file->fsf = fsf;
        azure_kusto_file->create_time = time(NULL);
        azure_kusto_file->size = 0; /* Initialize size to 0 */

        /* Use fstore opaque 'data' reference to keep our context */
        fsf->data = azure_kusto_file;
        flb_sds_destroy(name);

    }
    else {
        fsf = azure_kusto_file->fsf;
    }

    /* Append data to the target file */
    ret = flb_fstore_file_append(azure_kusto_file->fsf, data, bytes);

    if (ret != 0) {
        flb_plg_error(ctx->ins, "error writing data to local azure_kusto file");
        return -1;
    }

    azure_kusto_file->size += bytes;
    ctx->current_buffer_size += bytes;

    flb_plg_debug(ctx->ins, "[azure_kusto] new file size: %zu", azure_kusto_file->size);
    flb_plg_debug(ctx->ins, "[azure_kusto] current_buffer_size: %zu", ctx->current_buffer_size);

    /* if buffer is 95% full, warn user */
    if (ctx->store_dir_limit_size > 0) {
        space_remaining = ctx->store_dir_limit_size - ctx->current_buffer_size;
        if ((space_remaining * 20) < ctx->store_dir_limit_size) {
            flb_plg_warn(ctx->ins, "Buffer is almost full: current_buffer_size=%zu, store_dir_limit_size=%zu bytes",
                         ctx->current_buffer_size, ctx->store_dir_limit_size);
        }
    }
    return 0;
}

/**
 * Set Files in Azure Kusto Plugin Buffer Context
 *
 * This function iterates over the file streams associated with the context,
 * excluding the currently active stream and the multi-upload stream. For each file in
 * these streams, it checks if the file's data context is uninitialized. If so, it allocates
 * a new `azure_kusto_file` structure to serve as the file's context.
 *
 * The function performs the following steps:
 * 1. Iterate over each file stream in the context's file store, skipping the active and
 *    multi-upload streams.
 * 2. For each file in the stream, check if the file's data context is already set.
 *    - If the data context is set, continue to the next file.
 * 3. Allocate memory for a new `azure_kusto_file` structure to serve as the file's context.
 *    - If memory allocation fails, log an error and continue to the next file.
 * 4. Initialize the `azure_kusto_file` structure with the current file and the current time.
 * 5. Assign the newly created `azure_kusto_file` structure to the file's data context.
 *
 * This function ensures that each file in the relevant streams has an associated context
 * for further processing, which is crucial for managing file operations within the Azure
 * Kusto environment.
 *
 * Parameters:
 * - ctx: A pointer to the `flb_azure_kusto` structure, which contains the file store and
 *        other relevant context information.
 *
 * Returns:
 * - Always returns 0, indicating successful execution.
 */
static int set_files_context(struct flb_azure_kusto *ctx)
{
    struct mk_list *head;
    struct mk_list *f_head;
    struct flb_fstore_stream *fs_stream;
    struct flb_fstore_file *fsf;
    struct azure_kusto_file *azure_kusto_file;

    mk_list_foreach(head, &ctx->fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);

        /* skip current stream since it's new */
        if (fs_stream == ctx->stream_active) {
            continue;
        }

        /* skip multi-upload */
        if (fs_stream == ctx->stream_upload) {
            continue;
        }

        mk_list_foreach(f_head, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);
            if (fsf->data) {
                continue;
            }

            /* Allocate local context */
            azure_kusto_file = flb_calloc(1, sizeof(struct azure_kusto_file));
            if (!azure_kusto_file) {
                flb_errno();
                flb_plg_error(ctx->ins, "cannot allocate azure_kusto file context");
                continue;
            }
            azure_kusto_file->fsf = fsf;
            azure_kusto_file->create_time = time(NULL);

            /* Use fstore opaque 'data' reference to keep our context */
            fsf->data = azure_kusto_file;
        }
    }

    return 0;
}

/**
 * Initialize the filesystem storage for the Azure Kusto plugin.
 *
 * This function is responsible for setting up the storage context and creating
 * a new stream for data storage. It ensures that the Azure Kusto plugin can
 * differentiate between new data generated during the current process run and
 * backlog data from previous runs.
 *
 * Key Steps:
 * 1. **Set Storage Type**: The storage type is set to `FLB_FSTORE_FS`, indicating
 *    that the storage will be filesystem-based.
 *
 * 2. **Initialize Storage Context**:
 *    - Constructs a path for the storage context using the `buffer_dir` and
 *      `azure_kusto_buffer_key` from the context (`ctx`).
 *    - Creates the storage context using `flb_fstore_create`. If this fails,
 *      the function returns an error.
 *
 * 3. **Stream Creation**:
 *    - On each start, a new stream is created. This stream is a directory named
 *      with the current date and time (formatted as `YYYY-MM-DDTHH:MM:SS`), which
 *      stores all new data generated during the current process run.
 *    - The plugin differentiates between new and older buffered data, with older
 *      data considered as backlog.
 *
 * 4. **Platform-Specific Considerations**:
 *    - On Windows, the function replaces colons (`:`) with hyphens (`-`) in the
 *      stream name because colons are not allowed in directory names on Windows.
 *
 * 5. **Error Handling**:
 *    - If the stream creation fails, the function logs an error, destroys the
 *      storage context, and returns an error code.
 *
 * 6. **Finalization**:
 *    - If successful, the function sets the active stream in the context and
 *      calls `set_files_context` to finalize the setup.
 *
 * @param ctx A pointer to the `flb_azure_kusto` structure containing the plugin
 *            context and configuration.
 *
 * @return Returns 0 on success, or -1 on failure.
 */
int azure_kusto_store_init(struct flb_azure_kusto *ctx)
{
    int type;
    time_t now;
    char tmp[64];
    struct tm *tm;
    struct flb_fstore *fs;
    struct flb_fstore_stream *fs_stream;

    /* Set the storage type */
    type = FLB_FSTORE_FS;

    /* Initialize the storage context */
    if (ctx->buffer_dir[strlen(ctx->buffer_dir) - 1] == '/') {
        snprintf(tmp, sizeof(tmp), "%s%s", ctx->buffer_dir, ctx->azure_kusto_buffer_key);
    }
    else {
        snprintf(tmp, sizeof(tmp), "%s/%s", ctx->buffer_dir, ctx->azure_kusto_buffer_key);
    }

    /* Initialize the storage context */
    fs = flb_fstore_create(tmp, type);
    if (!fs) {
        return -1;
    }
    ctx->fs = fs;

    /*
     * On every start we create a new stream, this stream in the file system
     * is directory with the name using the date like '2020-10-03T13:00:02'. So
     * all the 'new' data that is generated on this process is stored there.
     *
     * Note that previous data in similar directories from previous runs is
     * considered backlog data, in the azure_kusto plugin we need to differentiate the
     * new v/s the older buffered data.
     *
     * Compose a stream name...
     */
    now = time(NULL);
    tm = localtime(&now);

#ifdef FLB_SYSTEM_WINDOWS
    /* Windows does not allow ':' in directory names */
    strftime(tmp, sizeof(tmp) - 1, "%Y-%m-%dT%H-%M-%S", tm);
#else
    strftime(tmp, sizeof(tmp) - 1, "%Y-%m-%dT%H:%M:%S", tm);
#endif

    /* Create the stream */
    fs_stream = flb_fstore_stream_create(ctx->fs, tmp);
    if (!fs_stream) {
        /* Upon exception abort */
        flb_plg_error(ctx->ins, "could not initialize active stream: %s", tmp);
        flb_fstore_destroy(fs);
        ctx->fs = NULL;
        return -1;
    }
    ctx->stream_active = fs_stream;

    set_files_context(ctx);
    return 0;
}

/**
 * azure_kusto_store_exit - Cleans up and releases resources associated with
 * the Kusto plugin storage context.
 *
 * This function is responsible for releasing any local resources associated
 * with the Kusto plugin storage context (`ctx`). It iterates over the file
 * streams in the context's file store (`ctx->fs`) and frees any allocated
 * memory for non-multi upload files. Finally, it destroys the file store
 * if it exists.
 *
 * Parameters:
 *   ctx - A pointer to the `flb_azure_kusto` structure representing the
 *         Kusto plugin storage context.
 *
 * Returns:
 *   An integer value, always returns 0 indicating successful cleanup.
 */
int azure_kusto_store_exit(struct flb_azure_kusto *ctx)
{
    struct mk_list *head;
    struct mk_list *f_head;
    struct flb_fstore_stream *fs_stream;
    struct flb_fstore_file *fsf;
    struct azure_kusto_file *azure_kusto_file;

    if (!ctx->fs) {
        return 0;
    }

    /* release local context on non-multi upload files */
    mk_list_foreach(head, &ctx->fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        if (fs_stream == ctx->stream_upload) {
            continue;
        }

        mk_list_foreach(f_head, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);
            if (fsf->data != NULL) {
                azure_kusto_file = fsf->data;
                flb_free(azure_kusto_file);
            }
        }
    }

    if (ctx->fs) {
        flb_fstore_destroy(ctx->fs);
    }
    return 0;
}

/**
 * azure_kusto_store_has_data - Check if there is any data in the Azure Kusto store.
 * @ctx: Pointer to the Kusto plugin context structure.
 *
 * This function checks whether there is any data stored in the file storage
 * associated with the Kusto plugin context. It iterates over each stream in the
 * file storage, excluding the stream used for uploads, and checks if there are
 * any files present. If files are found, it logs their names and returns true.
 * If no files are found in any stream, it logs this information and returns false.
 *
 * Returns:
 * FLB_TRUE if there is data in any stream other than the upload stream,
 * FLB_FALSE otherwise.
 */
int azure_kusto_store_has_data(struct flb_azure_kusto *ctx)
{
    struct mk_list *head;
    struct flb_fstore_stream *fs_stream;

    /* Check if the file storage context is initialized */
    if (!ctx->fs) {
        flb_plg_debug(ctx->ins, "File storage context is not initialized");
        return FLB_FALSE;
    }

    /* Iterate over each stream in the file storage */
    mk_list_foreach(head, &ctx->fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);

        /* Log the name of the current stream being processed */
        flb_plg_debug(ctx->ins, "Processing stream: '%s'", fs_stream->name);

        /* Check if the current stream is the one used for uploads */
        if (fs_stream == ctx->stream_upload) {
            flb_plg_debug(ctx->ins, "Skipping upload stream: '%s'", fs_stream->name);
            continue;
        }

        /* Log the number of files in the current stream */
        int file_count = mk_list_size(&fs_stream->files);
        flb_plg_debug(ctx->ins, "Stream '%s' has %d files", fs_stream->name, file_count);

        /* If there are files, log their names and return true */
        if (file_count > 0) {
            struct mk_list *file_head;
            struct flb_fstore_file *fs_file;

            mk_list_foreach(file_head, &fs_stream->files) {
                fs_file = mk_list_entry(file_head, struct flb_fstore_file, _head);
                flb_plg_debug(ctx->ins, "File in stream '%s': '%s'", fs_stream->name, fs_file->name);
            }

            return FLB_TRUE;
        }
    }

    /* Log if no data was found in any stream */
    flb_plg_debug(ctx->ins, "No data found in any stream");
    return FLB_FALSE;
}

/**
 * Checks if there are any files in the upload stream of the Kusto plugin context.
 *
 * This function verifies whether the given Kusto plugin context has any files
 * queued for upload. It performs the following checks:
 *
 * 1. Validates that the context and the upload stream are initialized.
 * 2. Checks the number of files in the upload stream.
 * 3. Returns true if there are files present, otherwise returns false.
 *
 * @param ctx A pointer to the Kusto plugin context structure.
 * @return FLB_TRUE if there are files in the upload stream, FLB_FALSE otherwise.
 */
int azure_kusto_store_has_uploads(struct flb_azure_kusto *ctx)
{
    if (!ctx || !ctx->stream_upload) {
        return FLB_FALSE;
    }

    if (mk_list_size(&ctx->stream_upload->files) > 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/**
 * azure_kusto_store_file_inactive - Marks a file as inactive in the Kusto plugin storage context.
 * @ctx: Pointer to the Kusto plugin context structure.
 * @azure_kusto_file: Pointer to the Azure Kusto file structure to be marked inactive.
 *
 * This function is responsible for marking a specific file as inactive within the
 * Kusto plugin storage context. It first retrieves the file store file structure
 * associated with the buffer file, then frees the memory allocated for the
 * file structure. Finally, it calls the function to mark the file
 * as inactive in the file store and returns the result of this operation.
 *
 * Returns:
 * The return value of the flb_fstore_file_inactive function, indicating success
 * or failure of marking the file as inactive.
 */
int azure_kusto_store_file_inactive(struct flb_azure_kusto *ctx, struct azure_kusto_file *azure_kusto_file)
{
    int ret;
    struct flb_fstore_file *fsf;

    fsf = azure_kusto_file->fsf;

    flb_free(azure_kusto_file);
    ret = flb_fstore_file_inactive(ctx->fs, fsf);

    return ret;
}

/**
 * azure_kusto_store_file_cleanup - Cleans up and permanently deletes a file from Kusto plugin buffer storage.
 * @ctx: Pointer to the Kusto plugin context structure.
 * @azure_kusto_file: Pointer to the Kusto plugin buffer file structure to be cleaned up.
 *
 * This function retrieves the file store structure from the given buffer file,
 * performs a permanent deletion of the file from the file store, and then frees the memory
 * allocated for the file structure. It returns 0 upon successful completion.
 *
 * Returns:
 * 0 on successful cleanup and deletion of the file.
 */
int azure_kusto_store_file_cleanup(struct flb_azure_kusto *ctx, struct azure_kusto_file *azure_kusto_file)
{
    struct flb_fstore_file *fsf;

    fsf = azure_kusto_file->fsf;

    /* permanent deletion */
    flb_fstore_file_delete(ctx->fs, fsf);
    flb_free(azure_kusto_file);

    return 0;
}

/**
 * azure_kusto_store_file_delete - Deletes a file from Kusto plugin byffer storage.
 * @ctx: Pointer to the Kusto plugin context structure.
 * @azure_kusto_file: Pointer to the Kusto plugin file structure to be deleted.
 *
 * This function performs the permanent deletion of a file from the Kusto plugin buffer
 * storage. It first retrieves the file store structure associated with the
 * file. Then, it updates the current buffer size in the context by
 * subtracting the size of the file being deleted. Finally, it deletes the file
 * from the file store and frees the memory allocated for the buffer file
 * structure.
 *
 * Returns 0 on successful deletion.
 */
int azure_kusto_store_file_delete(struct flb_azure_kusto *ctx, struct azure_kusto_file *azure_kusto_file)
{
    struct flb_fstore_file *fsf;

    fsf = azure_kusto_file->fsf;
    ctx->current_buffer_size -= azure_kusto_file->size;

    /* permanent deletion */
    flb_fstore_file_delete(ctx->fs, fsf);
    flb_free(azure_kusto_file);

    return 0;
}

/**
 * azure_kusto_store_file_upload_read - Reads the content of a file from the Azure Kusto store.
 * @ctx: Pointer to the Kusto plugin context structure.
 * @fsf: Pointer to the file store structure representing the file to be read.
 * @out_buf: Pointer to a buffer where the file content will be stored.
 * @out_size: Pointer to a variable where the size of the file content will be stored.
 *
 * This function copies the content of the specified file from the Azure Kusto store
 * into a buffer. The buffer and its size are returned through the out parameters.
 *
 * Returns:
 *   0 on success, or a negative error code on failure.
 */
int azure_kusto_store_file_upload_read(struct flb_azure_kusto *ctx, struct flb_fstore_file *fsf,
                                       char **out_buf, size_t *out_size)
{
    int ret;

    ret = flb_fstore_file_content_copy(ctx->fs, fsf,
                                       (void **) out_buf, out_size);
    return ret;
}

/**
 * Retrieves metadata for a specified file in the Kusto plugin buffer context.
 *
 * This function is a wrapper around the `flb_fstore_file_meta_get` function,
 * which fetches metadata for a given file within the file storage system.
 *
 * @param ctx A pointer to the `flb_azure_kusto` structure, which contains
 *            the context for Azure Kusto operations, including the file storage system.
 * @param fsf A pointer to the `flb_fstore_file` structure representing the file
 *            for which metadata is to be retrieved.
 *
 * @return The result of the `flb_fstore_file_meta_get` function call, which
 *         typically indicates success or failure of the metadata retrieval operation.
 */
int azure_kusto_store_file_meta_get(struct flb_azure_kusto *ctx, struct flb_fstore_file *fsf)
{
    return flb_fstore_file_meta_get(ctx->fs, fsf);
}

/**
 * Locks the specified buffer file.
 *
 * This function sets the `locked` attribute of the given `azure_kusto_file`
 * structure to `FLB_TRUE`, indicating that the file is currently locked.
 *
 * @param azure_kusto_file A pointer to the `azure_kusto_file` structure
 *                         representing the file to be locked.
 */
void azure_kusto_store_file_lock(struct azure_kusto_file *azure_kusto_file)
{
    azure_kusto_file->locked = FLB_TRUE;
}

/**
 * Unlocks the specified buffer file.
 *
 * This function sets the `locked` attribute of the given `azure_kusto_file`
 * structure to `FLB_FALSE`, indicating that the file is currently unlocked.
 *
 * @param azure_kusto_file A pointer to the `azure_kusto_file` structure
 *                         representing the file to be unlocked.
 */
void azure_kusto_store_file_unlock(struct azure_kusto_file *azure_kusto_file)
{
    azure_kusto_file->locked = FLB_FALSE;
}