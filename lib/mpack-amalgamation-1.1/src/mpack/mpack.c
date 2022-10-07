/**
 * The MIT License (MIT)
 * 
 * Copyright (c) 2015-2021 Nicholas Fraser and the MPack authors
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

/*
 * This is the MPack 1.1 amalgamation package.
 *
 * http://github.com/ludocode/mpack
 */

#define MPACK_INTERNAL 1
#define MPACK_EMIT_INLINE_DEFS 1

#include "mpack.h"


/* mpack/mpack-platform.c.c */


// We define MPACK_EMIT_INLINE_DEFS and include mpack.h to emit
// standalone definitions of all (non-static) inline functions in MPack.

#define MPACK_INTERNAL 1
#define MPACK_EMIT_INLINE_DEFS 1

/* #include "mpack-platform.h" */
/* #include "mpack.h" */

MPACK_SILENCE_WARNINGS_BEGIN

#if MPACK_DEBUG

#if MPACK_STDIO
void mpack_assert_fail_format(const char* format, ...) {
    char buffer[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    buffer[sizeof(buffer) - 1] = 0;
    mpack_assert_fail_wrapper(buffer);
}

void mpack_break_hit_format(const char* format, ...) {
    char buffer[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    buffer[sizeof(buffer) - 1] = 0;
    mpack_break_hit(buffer);
}
#endif

#if !MPACK_CUSTOM_ASSERT
void mpack_assert_fail(const char* message) {
    MPACK_UNUSED(message);

    #if MPACK_STDIO
    fprintf(stderr, "%s\n", message);
    #endif
}
#endif

// We split the assert failure from the wrapper so that a
// custom assert function can return.
void mpack_assert_fail_wrapper(const char* message) {

    #ifdef MPACK_GCOV
    // gcov marks even __builtin_unreachable() as an uncovered line. this
    // silences it.
    (mpack_assert_fail(message), __builtin_unreachable());

    #else
    mpack_assert_fail(message);

    // mpack_assert_fail() is not supposed to return. in case it does, we
    // abort.

    #if !MPACK_NO_BUILTINS
    #if defined(__GNUC__) || defined(__clang__)
    __builtin_trap();
    #elif defined(WIN32)
    __debugbreak();
    #endif
    #endif

    #if (defined(__GNUC__) || defined(__clang__)) && !MPACK_NO_BUILTINS
    __builtin_abort();
    #elif MPACK_STDLIB
    abort();
    #endif

    MPACK_UNREACHABLE;
    #endif
}

#if !MPACK_CUSTOM_BREAK

// If we have a custom assert handler, break wraps it by default.
// This allows users of MPack to only implement mpack_assert_fail() without
// having to worry about the difference between assert and break.
//
// MPACK_CUSTOM_BREAK is available to define a separate break handler
// (which is needed by the unit test suite), but this is not offered in
// mpack-config.h for simplicity.

#if MPACK_CUSTOM_ASSERT
void mpack_break_hit(const char* message) {
    mpack_assert_fail_wrapper(message);
}
#else
void mpack_break_hit(const char* message) {
    MPACK_UNUSED(message);

    #if MPACK_STDIO
    fprintf(stderr, "%s\n", message);
    #endif

    #if defined(__GNUC__) || defined(__clang__) && !MPACK_NO_BUILTINS
    __builtin_trap();
    #elif defined(WIN32) && !MPACK_NO_BUILTINS
    __debugbreak();
    #elif MPACK_STDLIB
    abort();
    #endif
}
#endif

#endif

#endif



// The below are adapted from the C wikibook:
//     https://en.wikibooks.org/wiki/C_Programming/Strings

#ifndef mpack_memcmp
int mpack_memcmp(const void* s1, const void* s2, size_t n) {
     const unsigned char *us1 = (const unsigned char *) s1;
     const unsigned char *us2 = (const unsigned char *) s2;
     while (n-- != 0) {
         if (*us1 != *us2)
             return (*us1 < *us2) ? -1 : +1;
         us1++;
         us2++;
     }
     return 0;
}
#endif

#ifndef mpack_memcpy
void* mpack_memcpy(void* MPACK_RESTRICT s1, const void* MPACK_RESTRICT s2, size_t n) {
    char* MPACK_RESTRICT dst = (char *)s1;
    const char* MPACK_RESTRICT src = (const char *)s2;
    while (n-- != 0)
        *dst++ = *src++;
    return s1;
}
#endif

#ifndef mpack_memmove
void* mpack_memmove(void* s1, const void* s2, size_t n) {
    char *p1 = (char *)s1;
    const char *p2 = (const char *)s2;
    if (p2 < p1 && p1 < p2 + n) {
        p2 += n;
        p1 += n;
        while (n-- != 0)
            *--p1 = *--p2;
    } else
        while (n-- != 0)
            *p1++ = *p2++;
    return s1;
}
#endif

#ifndef mpack_memset
void* mpack_memset(void* s, int c, size_t n) {
    unsigned char *us = (unsigned char *)s;
    unsigned char uc = (unsigned char)c;
    while (n-- != 0)
        *us++ = uc;
    return s;
}
#endif

#ifndef mpack_strlen
size_t mpack_strlen(const char* s) {
    const char* p = s;
    while (*p != '\0')
        p++;
    return (size_t)(p - s);
}
#endif



#if defined(MPACK_MALLOC) && !defined(MPACK_REALLOC)
void* mpack_realloc(void* old_ptr, size_t used_size, size_t new_size) {
    if (new_size == 0) {
        if (old_ptr)
            MPACK_FREE(old_ptr);
        return NULL;
    }

    void* new_ptr = MPACK_MALLOC(new_size);
    if (new_ptr == NULL)
        return NULL;

    mpack_memcpy(new_ptr, old_ptr, used_size);
    MPACK_FREE(old_ptr);
    return new_ptr;
}
#endif

MPACK_SILENCE_WARNINGS_END

/* mpack/mpack-common.c.c */

#define MPACK_INTERNAL 1

/* #include "mpack-common.h" */

MPACK_SILENCE_WARNINGS_BEGIN

const char* mpack_error_to_string(mpack_error_t error) {
    #if MPACK_STRINGS
    switch (error) {
        #define MPACK_ERROR_STRING_CASE(e) case e: return #e
        MPACK_ERROR_STRING_CASE(mpack_ok);
        MPACK_ERROR_STRING_CASE(mpack_error_io);
        MPACK_ERROR_STRING_CASE(mpack_error_invalid);
        MPACK_ERROR_STRING_CASE(mpack_error_unsupported);
        MPACK_ERROR_STRING_CASE(mpack_error_type);
        MPACK_ERROR_STRING_CASE(mpack_error_too_big);
        MPACK_ERROR_STRING_CASE(mpack_error_memory);
        MPACK_ERROR_STRING_CASE(mpack_error_bug);
        MPACK_ERROR_STRING_CASE(mpack_error_data);
        MPACK_ERROR_STRING_CASE(mpack_error_eof);
        #undef MPACK_ERROR_STRING_CASE
    }
    mpack_assert(0, "unrecognized error %i", (int)error);
    return "(unknown mpack_error_t)";
    #else
    MPACK_UNUSED(error);
    return "";
    #endif
}

const char* mpack_type_to_string(mpack_type_t type) {
    #if MPACK_STRINGS
    switch (type) {
        #define MPACK_TYPE_STRING_CASE(e) case e: return #e
        MPACK_TYPE_STRING_CASE(mpack_type_missing);
        MPACK_TYPE_STRING_CASE(mpack_type_nil);
        MPACK_TYPE_STRING_CASE(mpack_type_bool);
        MPACK_TYPE_STRING_CASE(mpack_type_float);
        MPACK_TYPE_STRING_CASE(mpack_type_double);
        MPACK_TYPE_STRING_CASE(mpack_type_int);
        MPACK_TYPE_STRING_CASE(mpack_type_uint);
        MPACK_TYPE_STRING_CASE(mpack_type_str);
        MPACK_TYPE_STRING_CASE(mpack_type_bin);
        MPACK_TYPE_STRING_CASE(mpack_type_array);
        MPACK_TYPE_STRING_CASE(mpack_type_map);
        #if MPACK_EXTENSIONS
        MPACK_TYPE_STRING_CASE(mpack_type_ext);
        #endif
        #undef MPACK_TYPE_STRING_CASE
    }
    mpack_assert(0, "unrecognized type %i", (int)type);
    return "(unknown mpack_type_t)";
    #else
    MPACK_UNUSED(type);
    return "";
    #endif
}

int mpack_tag_cmp(mpack_tag_t left, mpack_tag_t right) {

    // positive numbers may be stored as int; convert to uint
    if (left.type == mpack_type_int && left.v.i >= 0) {
        left.type = mpack_type_uint;
        left.v.u = (uint64_t)left.v.i;
    }
    if (right.type == mpack_type_int && right.v.i >= 0) {
        right.type = mpack_type_uint;
        right.v.u = (uint64_t)right.v.i;
    }

    if (left.type != right.type)
        return ((int)left.type < (int)right.type) ? -1 : 1;

    switch (left.type) {
        case mpack_type_missing: // fallthrough
        case mpack_type_nil:
            return 0;

        case mpack_type_bool:
            return (int)left.v.b - (int)right.v.b;

        case mpack_type_int:
            if (left.v.i == right.v.i)
                return 0;
            return (left.v.i < right.v.i) ? -1 : 1;

        case mpack_type_uint:
            if (left.v.u == right.v.u)
                return 0;
            return (left.v.u < right.v.u) ? -1 : 1;

        case mpack_type_array:
        case mpack_type_map:
            if (left.v.n == right.v.n)
                return 0;
            return (left.v.n < right.v.n) ? -1 : 1;

        case mpack_type_str:
        case mpack_type_bin:
            if (left.v.l == right.v.l)
                return 0;
            return (left.v.l < right.v.l) ? -1 : 1;

        #if MPACK_EXTENSIONS
        case mpack_type_ext:
            if (left.exttype == right.exttype) {
                if (left.v.l == right.v.l)
                    return 0;
                return (left.v.l < right.v.l) ? -1 : 1;
            }
            return (int)left.exttype - (int)right.exttype;
        #endif

        // floats should not normally be compared for equality. we compare
        // with memcmp() to silence compiler warnings, but this will return
        // equal if both are NaNs with the same representation (though we may
        // want this, for instance if you are for some bizarre reason using
        // floats as map keys.) i'm not sure what the right thing to
        // do is here. check for NaN first? always return false if the type
        // is float? use operator== and pragmas to silence compiler warning?
        // please send me your suggestions.
        // note also that we don't convert floats to doubles, so when this is
        // used for ordering purposes, all floats are ordered before all
        // doubles.
        case mpack_type_float:
            return mpack_memcmp(&left.v.f, &right.v.f, sizeof(left.v.f));
        case mpack_type_double:
            return mpack_memcmp(&left.v.d, &right.v.d, sizeof(left.v.d));
    }

    mpack_assert(0, "unrecognized type %i", (int)left.type);
    return false;
}

#if MPACK_DEBUG && MPACK_STDIO
static char mpack_hex_char(uint8_t hex_value) {
    // Older compilers (e.g. GCC 4.4.7) promote the result of this ternary to
    // int and warn under -Wconversion, so we have to cast it back to char.
    return (char)((hex_value < 10) ? (char)('0' + hex_value) : (char)('a' + (hex_value - 10)));
}

static void mpack_tag_debug_complete_bin_ext(mpack_tag_t tag, size_t string_length, char* buffer, size_t buffer_size,
        const char* prefix, size_t prefix_size)
{
    // If at any point in this function we run out of space in the buffer, we
    // bail out. The outer tag print wrapper will make sure we have a
    // null-terminator.

    if (string_length == 0 || string_length >= buffer_size)
        return;
    buffer += string_length;
    buffer_size -= string_length;

    size_t total = mpack_tag_bytes(&tag);
    if (total == 0) {
        strncpy(buffer, ">", buffer_size);
        return;
    }

    strncpy(buffer, ": ", buffer_size);
    if (buffer_size < 2)
        return;
    buffer += 2;
    buffer_size -= 2;

    size_t hex_bytes = 0;
    size_t i;
    for (i = 0; i < MPACK_PRINT_BYTE_COUNT && i < prefix_size && buffer_size > 2; ++i) {
        uint8_t byte = (uint8_t)prefix[i];
        buffer[0] = mpack_hex_char((uint8_t)(byte >> 4));
        buffer[1] = mpack_hex_char((uint8_t)(byte & 0xfu));
        buffer += 2;
        buffer_size -= 2;
        ++hex_bytes;
    }

    if (buffer_size != 0)
        mpack_snprintf(buffer, buffer_size, "%s>", (total > hex_bytes) ? "..." : "");
}

static void mpack_tag_debug_pseudo_json_bin(mpack_tag_t tag, char* buffer, size_t buffer_size,
        const char* prefix, size_t prefix_size)
{
    mpack_assert(mpack_tag_type(&tag) == mpack_type_bin);
    size_t length = (size_t)mpack_snprintf(buffer, buffer_size, "<binary data of length %u", tag.v.l);
    mpack_tag_debug_complete_bin_ext(tag, length, buffer, buffer_size, prefix, prefix_size);
}

#if MPACK_EXTENSIONS
static void mpack_tag_debug_pseudo_json_ext(mpack_tag_t tag, char* buffer, size_t buffer_size,
        const char* prefix, size_t prefix_size)
{
    mpack_assert(mpack_tag_type(&tag) == mpack_type_ext);
    size_t length = (size_t)mpack_snprintf(buffer, buffer_size, "<ext data of type %i and length %u",
            mpack_tag_ext_exttype(&tag), mpack_tag_ext_length(&tag));
    mpack_tag_debug_complete_bin_ext(tag, length, buffer, buffer_size, prefix, prefix_size);
}
#endif

static void mpack_tag_debug_pseudo_json_impl(mpack_tag_t tag, char* buffer, size_t buffer_size,
        const char* prefix, size_t prefix_size)
{
    switch (tag.type) {
        case mpack_type_missing:
            mpack_snprintf(buffer, buffer_size, "<missing!>");
            return;
        case mpack_type_nil:
            mpack_snprintf(buffer, buffer_size, "null");
            return;
        case mpack_type_bool:
            mpack_snprintf(buffer, buffer_size, tag.v.b ? "true" : "false");
            return;
        case mpack_type_int:
            mpack_snprintf(buffer, buffer_size, "%" PRIi64, tag.v.i);
            return;
        case mpack_type_uint:
            mpack_snprintf(buffer, buffer_size, "%" PRIu64, tag.v.u);
            return;
        case mpack_type_float:
            #if MPACK_FLOAT
            mpack_snprintf(buffer, buffer_size, "%f", tag.v.f);
            #else
            mpack_snprintf(buffer, buffer_size, "<float>");
            #endif
            return;
        case mpack_type_double:
            #if MPACK_DOUBLE
            mpack_snprintf(buffer, buffer_size, "%f", tag.v.d);
            #else
            mpack_snprintf(buffer, buffer_size, "<double>");
            #endif
            return;

        case mpack_type_str:
            mpack_snprintf(buffer, buffer_size, "<string of %u bytes>", tag.v.l);
            return;
        case mpack_type_bin:
            mpack_tag_debug_pseudo_json_bin(tag, buffer, buffer_size, prefix, prefix_size);
            return;
        #if MPACK_EXTENSIONS
        case mpack_type_ext:
            mpack_tag_debug_pseudo_json_ext(tag, buffer, buffer_size, prefix, prefix_size);
            return;
        #endif

        case mpack_type_array:
            mpack_snprintf(buffer, buffer_size, "<array of %u elements>", tag.v.n);
            return;
        case mpack_type_map:
            mpack_snprintf(buffer, buffer_size, "<map of %u key-value pairs>", tag.v.n);
            return;
    }

    mpack_snprintf(buffer, buffer_size, "<unknown!>");
}

void mpack_tag_debug_pseudo_json(mpack_tag_t tag, char* buffer, size_t buffer_size,
        const char* prefix, size_t prefix_size)
{
    mpack_assert(buffer_size > 0, "buffer size cannot be zero!");
    buffer[0] = 0;

    mpack_tag_debug_pseudo_json_impl(tag, buffer, buffer_size, prefix, prefix_size);

    // We always null-terminate the buffer manually just in case the snprintf()
    // function doesn't null-terminate when the string doesn't fit.
    buffer[buffer_size - 1] = 0;
}

static void mpack_tag_debug_describe_impl(mpack_tag_t tag, char* buffer, size_t buffer_size) {
    switch (tag.type) {
        case mpack_type_missing:
            mpack_snprintf(buffer, buffer_size, "missing");
            return;
        case mpack_type_nil:
            mpack_snprintf(buffer, buffer_size, "nil");
            return;
        case mpack_type_bool:
            mpack_snprintf(buffer, buffer_size, tag.v.b ? "true" : "false");
            return;
        case mpack_type_int:
            mpack_snprintf(buffer, buffer_size, "int %" PRIi64, tag.v.i);
            return;
        case mpack_type_uint:
            mpack_snprintf(buffer, buffer_size, "uint %" PRIu64, tag.v.u);
            return;
        case mpack_type_float:
            #if MPACK_FLOAT
            mpack_snprintf(buffer, buffer_size, "float %f", tag.v.f);
            #else
            mpack_snprintf(buffer, buffer_size, "float");
            #endif
            return;
        case mpack_type_double:
            #if MPACK_DOUBLE
            mpack_snprintf(buffer, buffer_size, "double %f", tag.v.d);
            #else
            mpack_snprintf(buffer, buffer_size, "double");
            #endif
            return;
        case mpack_type_str:
            mpack_snprintf(buffer, buffer_size, "str of %u bytes", tag.v.l);
            return;
        case mpack_type_bin:
            mpack_snprintf(buffer, buffer_size, "bin of %u bytes", tag.v.l);
            return;
        #if MPACK_EXTENSIONS
        case mpack_type_ext:
            mpack_snprintf(buffer, buffer_size, "ext of type %i, %u bytes",
                    mpack_tag_ext_exttype(&tag), mpack_tag_ext_length(&tag));
            return;
        #endif
        case mpack_type_array:
            mpack_snprintf(buffer, buffer_size, "array of %u elements", tag.v.n);
            return;
        case mpack_type_map:
            mpack_snprintf(buffer, buffer_size, "map of %u key-value pairs", tag.v.n);
            return;
    }

    mpack_snprintf(buffer, buffer_size, "unknown!");
}

void mpack_tag_debug_describe(mpack_tag_t tag, char* buffer, size_t buffer_size) {
    mpack_assert(buffer_size > 0, "buffer size cannot be zero!");
    buffer[0] = 0;

    mpack_tag_debug_describe_impl(tag, buffer, buffer_size);

    // We always null-terminate the buffer manually just in case the snprintf()
    // function doesn't null-terminate when the string doesn't fit.
    buffer[buffer_size - 1] = 0;
}
#endif



#if MPACK_READ_TRACKING || MPACK_WRITE_TRACKING

#ifndef MPACK_TRACKING_INITIAL_CAPACITY
// seems like a reasonable number. we grow by doubling, and it only
// needs to be as long as the maximum depth of the message.
#define MPACK_TRACKING_INITIAL_CAPACITY 8
#endif

mpack_error_t mpack_track_init(mpack_track_t* track) {
    track->count = 0;
    track->capacity = MPACK_TRACKING_INITIAL_CAPACITY;
    track->elements = (mpack_track_element_t*)MPACK_MALLOC(sizeof(mpack_track_element_t) * track->capacity);
    if (track->elements == NULL)
        return mpack_error_memory;
    return mpack_ok;
}

mpack_error_t mpack_track_grow(mpack_track_t* track) {
    mpack_assert(track->elements, "null track elements!");
    mpack_assert(track->count == track->capacity, "incorrect growing?");

    size_t new_capacity = track->capacity * 2;

    mpack_track_element_t* new_elements = (mpack_track_element_t*)mpack_realloc(track->elements,
            sizeof(mpack_track_element_t) * track->count, sizeof(mpack_track_element_t) * new_capacity);
    if (new_elements == NULL)
        return mpack_error_memory;

    track->elements = new_elements;
    track->capacity = new_capacity;
    return mpack_ok;
}

mpack_error_t mpack_track_push(mpack_track_t* track, mpack_type_t type, uint32_t count) {
    mpack_assert(track->elements, "null track elements!");
    mpack_log("track pushing %s count %i\n", mpack_type_to_string(type), (int)count);

    // grow if needed
    if (track->count == track->capacity) {
        mpack_error_t error = mpack_track_grow(track);
        if (error != mpack_ok)
            return error;
    }

    // insert new track
    track->elements[track->count].type = type;
    track->elements[track->count].left = count;
    track->elements[track->count].builder = false;
    track->elements[track->count].key_needs_value = false;
    ++track->count;
    return mpack_ok;
}

// TODO dedupe this
mpack_error_t mpack_track_push_builder(mpack_track_t* track, mpack_type_t type) {
    mpack_assert(track->elements, "null track elements!");
    mpack_log("track pushing %s builder\n", mpack_type_to_string(type));

    // grow if needed
    if (track->count == track->capacity) {
        mpack_error_t error = mpack_track_grow(track);
        if (error != mpack_ok)
            return error;
    }

    // insert new track
    track->elements[track->count].type = type;
    track->elements[track->count].left = 0;
    track->elements[track->count].builder = true;
    track->elements[track->count].key_needs_value = false;
    ++track->count;
    return mpack_ok;
}

static mpack_error_t mpack_track_pop_impl(mpack_track_t* track, mpack_type_t type, bool builder) {
    mpack_assert(track->elements, "null track elements!");
    mpack_log("track popping %s\n", mpack_type_to_string(type));

    if (track->count == 0) {
        mpack_break("attempting to close a %s but nothing was opened!", mpack_type_to_string(type));
        return mpack_error_bug;
    }

    mpack_track_element_t* element = &track->elements[track->count - 1];

    if (element->type != type) {
        mpack_break("attempting to close a %s but the open element is a %s!",
                mpack_type_to_string(type), mpack_type_to_string(element->type));
        return mpack_error_bug;
    }

    if (element->key_needs_value) {
        mpack_assert(type == mpack_type_map, "key_needs_value can only be true for maps!");
        mpack_break("attempting to close a %s but an odd number of elements were written",
                mpack_type_to_string(type));
        return mpack_error_bug;
    }

    if (element->left != 0) {
        mpack_break("attempting to close a %s but there are %i %s left",
                mpack_type_to_string(type), element->left,
                (type == mpack_type_map || type == mpack_type_array) ? "elements" : "bytes");
        return mpack_error_bug;
    }

    if (element->builder != builder) {
        mpack_break("attempting to pop a %sbuilder but the open element is %sa builder",
                builder ? "" : "non-",
                element->builder ? "" : "not ");
        return mpack_error_bug;
    }

    --track->count;
    return mpack_ok;
}

mpack_error_t mpack_track_pop(mpack_track_t* track, mpack_type_t type) {
    return mpack_track_pop_impl(track, type, false);
}

mpack_error_t mpack_track_pop_builder(mpack_track_t* track, mpack_type_t type) {
    return mpack_track_pop_impl(track, type, true);
}

mpack_error_t mpack_track_peek_element(mpack_track_t* track, bool read) {
    MPACK_UNUSED(read);
    mpack_assert(track->elements, "null track elements!");

    // if there are no open elements, that's fine, we can read/write elements at will
    if (track->count == 0)
        return mpack_ok;

    mpack_track_element_t* element = &track->elements[track->count - 1];

    if (element->type != mpack_type_map && element->type != mpack_type_array) {
        mpack_break("elements cannot be %s within an %s", read ? "read" : "written",
                mpack_type_to_string(element->type));
        return mpack_error_bug;
    }

    if (!element->builder && element->left == 0 && !element->key_needs_value) {
        mpack_break("too many elements %s for %s", read ? "read" : "written",
                mpack_type_to_string(element->type));
        return mpack_error_bug;
    }

    return mpack_ok;
}

mpack_error_t mpack_track_element(mpack_track_t* track, bool read) {
    mpack_error_t error = mpack_track_peek_element(track, read);
    if (track->count == 0 || error != mpack_ok)
        return error;

    mpack_track_element_t* element = &track->elements[track->count - 1];

    if (element->type == mpack_type_map) {
        if (!element->key_needs_value) {
            element->key_needs_value = true;
            return mpack_ok; // don't decrement
        }
        element->key_needs_value = false;
    }

    if (!element->builder)
        --element->left;
    return mpack_ok;
}

mpack_error_t mpack_track_bytes(mpack_track_t* track, bool read, size_t count) {
    MPACK_UNUSED(read);
    mpack_assert(track->elements, "null track elements!");

    if (count > MPACK_UINT32_MAX) {
        mpack_break("%s more bytes than could possibly fit in a str/bin/ext!",
                read ? "reading" : "writing");
        return mpack_error_bug;
    }

    if (track->count == 0) {
        mpack_break("bytes cannot be %s with no open bin, str or ext", read ? "read" : "written");
        return mpack_error_bug;
    }

    mpack_track_element_t* element = &track->elements[track->count - 1];

    if (element->type == mpack_type_map || element->type == mpack_type_array) {
        mpack_break("bytes cannot be %s within an %s", read ? "read" : "written",
                mpack_type_to_string(element->type));
        return mpack_error_bug;
    }

    if (element->left < count) {
        mpack_break("too many bytes %s for %s", read ? "read" : "written",
                mpack_type_to_string(element->type));
        return mpack_error_bug;
    }

    element->left -= (uint32_t)count;
    return mpack_ok;
}

mpack_error_t mpack_track_str_bytes_all(mpack_track_t* track, bool read, size_t count) {
    mpack_error_t error = mpack_track_bytes(track, read, count);
    if (error != mpack_ok)
        return error;

    mpack_track_element_t* element = &track->elements[track->count - 1];

    if (element->type != mpack_type_str) {
        mpack_break("the open type must be a string, not a %s", mpack_type_to_string(element->type));
        return mpack_error_bug;
    }

    if (element->left != 0) {
        mpack_break("not all bytes were read; the wrong byte count was requested for a string read.");
        return mpack_error_bug;
    }

    return mpack_ok;
}

mpack_error_t mpack_track_check_empty(mpack_track_t* track) {
    if (track->count != 0) {
        mpack_break("unclosed %s", mpack_type_to_string(track->elements[0].type));
        return mpack_error_bug;
    }
    return mpack_ok;
}

mpack_error_t mpack_track_destroy(mpack_track_t* track, bool cancel) {
    mpack_error_t error = cancel ? mpack_ok : mpack_track_check_empty(track);
    if (track->elements) {
        MPACK_FREE(track->elements);
        track->elements = NULL;
    }
    return error;
}
#endif



static bool mpack_utf8_check_impl(const uint8_t* str, size_t count, bool allow_null) {
    while (count > 0) {
        uint8_t lead = str[0];

        // NUL
        if (!allow_null && lead == '\0') // we don't allow NUL bytes in MPack C-strings
            return false;

        // ASCII
        if (lead <= 0x7F) {
            ++str;
            --count;

        // 2-byte sequence
        } else if ((lead & 0xE0) == 0xC0) {
            if (count < 2) // truncated sequence
                return false;

            uint8_t cont = str[1];
            if ((cont & 0xC0) != 0x80) // not a continuation byte
                return false;

            str += 2;
            count -= 2;

            uint32_t z = ((uint32_t)(lead & ~0xE0) << 6) |
                          (uint32_t)(cont & ~0xC0);

            if (z < 0x80) // overlong sequence
                return false;

        // 3-byte sequence
        } else if ((lead & 0xF0) == 0xE0) {
            if (count < 3) // truncated sequence
                return false;

            uint8_t cont1 = str[1];
            if ((cont1 & 0xC0) != 0x80) // not a continuation byte
                return false;
            uint8_t cont2 = str[2];
            if ((cont2 & 0xC0) != 0x80) // not a continuation byte
                return false;

            str += 3;
            count -= 3;

            uint32_t z = ((uint32_t)(lead  & ~0xF0) << 12) |
                         ((uint32_t)(cont1 & ~0xC0) <<  6) |
                          (uint32_t)(cont2 & ~0xC0);

            if (z < 0x800) // overlong sequence
                return false;
            if (z >= 0xD800 && z <= 0xDFFF) // surrogate
                return false;

        // 4-byte sequence
        } else if ((lead & 0xF8) == 0xF0) {
            if (count < 4) // truncated sequence
                return false;

            uint8_t cont1 = str[1];
            if ((cont1 & 0xC0) != 0x80) // not a continuation byte
                return false;
            uint8_t cont2 = str[2];
            if ((cont2 & 0xC0) != 0x80) // not a continuation byte
                return false;
            uint8_t cont3 = str[3];
            if ((cont3 & 0xC0) != 0x80) // not a continuation byte
                return false;

            str += 4;
            count -= 4;

            uint32_t z = ((uint32_t)(lead  & ~0xF8) << 18) |
                         ((uint32_t)(cont1 & ~0xC0) << 12) |
                         ((uint32_t)(cont2 & ~0xC0) <<  6) |
                          (uint32_t)(cont3 & ~0xC0);

            if (z < 0x10000) // overlong sequence
                return false;
            if (z > 0x10FFFF) // codepoint limit
                return false;

        } else {
            return false; // continuation byte without a lead, or lead for a 5-byte sequence or longer
        }
    }
    return true;
}

bool mpack_utf8_check(const char* str, size_t bytes) {
    return mpack_utf8_check_impl((const uint8_t*)str, bytes, true);
}

bool mpack_utf8_check_no_null(const char* str, size_t bytes) {
    return mpack_utf8_check_impl((const uint8_t*)str, bytes, false);
}

bool mpack_str_check_no_null(const char* str, size_t bytes) {
    size_t i;
    for (i = 0; i < bytes; ++i)
        if (str[i] == '\0')
            return false;
    return true;
}

#if MPACK_DEBUG && MPACK_STDIO
void mpack_print_append(mpack_print_t* print, const char* data, size_t count) {

    // copy whatever fits into the buffer
    size_t copy = print->size - print->count;
    if (copy > count)
        copy = count;
    mpack_memcpy(print->buffer + print->count, data, copy);
    print->count += copy;
    data += copy;
    count -= copy;

    // if we don't need to flush or can't flush there's nothing else to do
    if (count == 0 || print->callback == NULL)
        return;

    // flush the buffer
    print->callback(print->context, print->buffer, print->count);

    if (count > print->size / 2) {
        // flush the rest of the data
        print->count = 0;
        print->callback(print->context, data, count);
    } else {
        // copy the rest of the data into the buffer
        mpack_memcpy(print->buffer, data, count);
        print->count = count;
    }

}

void mpack_print_flush(mpack_print_t* print) {
    if (print->count > 0 && print->callback != NULL) {
        print->callback(print->context, print->buffer, print->count);
        print->count = 0;
    }
}

void mpack_print_file_callback(void* context, const char* data, size_t count) {
    FILE* file = (FILE*)context;
    fwrite(data, 1, count, file);
}
#endif

MPACK_SILENCE_WARNINGS_END

/* mpack/mpack-writer.c.c */

#define MPACK_INTERNAL 1

/* #include "mpack-writer.h" */

MPACK_SILENCE_WARNINGS_BEGIN

#if MPACK_WRITER

#if MPACK_BUILDER
static void mpack_builder_flush(mpack_writer_t* writer);
#endif

#if MPACK_WRITE_TRACKING
static void mpack_writer_flag_if_error(mpack_writer_t* writer, mpack_error_t error) {
    if (error != mpack_ok)
        mpack_writer_flag_error(writer, error);
}

void mpack_writer_track_push(mpack_writer_t* writer, mpack_type_t type, uint32_t count) {
    if (writer->error == mpack_ok)
        mpack_writer_flag_if_error(writer, mpack_track_push(&writer->track, type, count));
}

void mpack_writer_track_push_builder(mpack_writer_t* writer, mpack_type_t type) {
    if (writer->error == mpack_ok)
        mpack_writer_flag_if_error(writer, mpack_track_push_builder(&writer->track, type));
}

void mpack_writer_track_pop(mpack_writer_t* writer, mpack_type_t type) {
    if (writer->error == mpack_ok)
        mpack_writer_flag_if_error(writer, mpack_track_pop(&writer->track, type));
}

void mpack_writer_track_pop_builder(mpack_writer_t* writer, mpack_type_t type) {
    if (writer->error == mpack_ok)
        mpack_writer_flag_if_error(writer, mpack_track_pop_builder(&writer->track, type));
}

void mpack_writer_track_bytes(mpack_writer_t* writer, size_t count) {
    if (writer->error == mpack_ok)
        mpack_writer_flag_if_error(writer, mpack_track_bytes(&writer->track, false, count));
}
#endif

// This should probably be renamed. It's not solely used for tracking.
static inline void mpack_writer_track_element(mpack_writer_t* writer) {
    (void)writer;

    #if MPACK_WRITE_TRACKING
    if (writer->error == mpack_ok)
        mpack_writer_flag_if_error(writer, mpack_track_element(&writer->track, false));
    #endif

    #if MPACK_BUILDER
    if (writer->builder.current_build != NULL) {
        mpack_build_t* build = writer->builder.current_build;
        // We only track this write if it's not nested within another non-build
        // map or array.
        if (build->nested_compound_elements == 0) {
            if (build->type != mpack_type_map) {
                ++build->count;
                mpack_log("adding element to build %p, now %u elements\n", (void*)build, build->count);
            } else if (build->key_needs_value) {
                build->key_needs_value = false;
                ++build->count;
            } else {
                build->key_needs_value = true;
            }
        }
    }
    #endif
}

static void mpack_writer_clear(mpack_writer_t* writer) {
    #if MPACK_COMPATIBILITY
    writer->version = mpack_version_current;
    #endif
    writer->flush = NULL;
    writer->error_fn = NULL;
    writer->teardown = NULL;
    writer->context = NULL;

    writer->buffer = NULL;
    writer->position = NULL;
    writer->end = NULL;
    writer->error = mpack_ok;

    #if MPACK_WRITE_TRACKING
    mpack_memset(&writer->track, 0, sizeof(writer->track));
    #endif

    #if MPACK_BUILDER
    writer->builder.current_build = NULL;
    writer->builder.latest_build = NULL;
    writer->builder.current_page = NULL;
    writer->builder.pages = NULL;
    writer->builder.stash_buffer = NULL;
    writer->builder.stash_position = NULL;
    writer->builder.stash_end = NULL;
    #endif
}

void mpack_writer_init(mpack_writer_t* writer, char* buffer, size_t size) {
    mpack_assert(buffer != NULL, "cannot initialize writer with empty buffer");
    mpack_writer_clear(writer);
    writer->buffer = buffer;
    writer->position = buffer;
    writer->end = writer->buffer + size;

    #if MPACK_WRITE_TRACKING
    mpack_writer_flag_if_error(writer, mpack_track_init(&writer->track));
    #endif

    mpack_log("===========================\n");
    mpack_log("initializing writer with buffer size %i\n", (int)size);
}

void mpack_writer_init_error(mpack_writer_t* writer, mpack_error_t error) {
    mpack_writer_clear(writer);
    writer->error = error;

    mpack_log("===========================\n");
    mpack_log("initializing writer in error state %i\n", (int)error);
}

void mpack_writer_set_flush(mpack_writer_t* writer, mpack_writer_flush_t flush) {
    MPACK_STATIC_ASSERT(MPACK_WRITER_MINIMUM_BUFFER_SIZE >= MPACK_MAXIMUM_TAG_SIZE,
            "minimum buffer size must fit any tag!");
    MPACK_STATIC_ASSERT(31 + MPACK_TAG_SIZE_FIXSTR >= MPACK_WRITER_MINIMUM_BUFFER_SIZE,
            "minimum buffer size must fit the largest possible fixstr!");

    if (mpack_writer_buffer_size(writer) < MPACK_WRITER_MINIMUM_BUFFER_SIZE) {
        mpack_break("buffer size is %i, but minimum buffer size for flush is %i",
                (int)mpack_writer_buffer_size(writer), MPACK_WRITER_MINIMUM_BUFFER_SIZE);
        mpack_writer_flag_error(writer, mpack_error_bug);
        return;
    }

    writer->flush = flush;
}

#ifdef MPACK_MALLOC
typedef struct mpack_growable_writer_t {
    char** target_data;
    size_t* target_size;
} mpack_growable_writer_t;

static char* mpack_writer_get_reserved(mpack_writer_t* writer) {
    // This is in a separate function in order to avoid false strict aliasing
    // warnings. We aren't actually violating strict aliasing (the reserved
    // space is only ever dereferenced as an mpack_growable_writer_t.)
    return (char*)writer->reserved;
}

static void mpack_growable_writer_flush(mpack_writer_t* writer, const char* data, size_t count) {

    // This is an intrusive flush function which modifies the writer's buffer
    // in response to a flush instead of emptying it in order to add more
    // capacity for data. This removes the need to copy data from a fixed buffer
    // into a growable one, improving performance.
    //
    // There are three ways flush can be called:
    //   - flushing the buffer during writing (used is zero, count is all data, data is buffer)
    //   - flushing extra data during writing (used is all flushed data, count is extra data, data is not buffer)
    //   - flushing during teardown (used and count are both all flushed data, data is buffer)
    //
    // In the first two cases, we grow the buffer by at least double, enough
    // to ensure that new data will fit. We ignore the teardown flush.

    if (data == writer->buffer) {

        // teardown, do nothing
        if (mpack_writer_buffer_used(writer) == count)
            return;

        // otherwise leave the data in the buffer and just grow
        writer->position = writer->buffer + count;
        count = 0;
    }

    size_t used = mpack_writer_buffer_used(writer);
    size_t size = mpack_writer_buffer_size(writer);

    mpack_log("flush size %i used %i data %p buffer %p\n",
            (int)count, (int)used, data, writer->buffer);

    mpack_assert(data == writer->buffer || used + count > size,
            "extra flush for %i but there is %i space left in the buffer! (%i/%i)",
            (int)count, (int)mpack_writer_buffer_left(writer), (int)used, (int)size);

    // grow to fit the data
    // TODO: this really needs to correctly test for overflow
    size_t new_size = size * 2;
    while (new_size < used + count)
        new_size *= 2;

    mpack_log("flush growing buffer size from %i to %i\n", (int)size, (int)new_size);

    // grow the buffer
    char* new_buffer = (char*)mpack_realloc(writer->buffer, used, new_size);
    if (new_buffer == NULL) {
        mpack_writer_flag_error(writer, mpack_error_memory);
        return;
    }
    writer->position = new_buffer + used;
    writer->buffer = new_buffer;
    writer->end = writer->buffer + new_size;

    // append the extra data
    if (count > 0) {
        mpack_memcpy(writer->position, data, count);
        writer->position += count;
    }

    mpack_log("new buffer %p, used %i\n", new_buffer, (int)mpack_writer_buffer_used(writer));
}

static void mpack_growable_writer_teardown(mpack_writer_t* writer) {
    mpack_growable_writer_t* growable_writer = (mpack_growable_writer_t*)mpack_writer_get_reserved(writer);

    if (mpack_writer_error(writer) == mpack_ok) {

        // shrink the buffer to an appropriate size if the data is
        // much smaller than the buffer
        if (mpack_writer_buffer_used(writer) < mpack_writer_buffer_size(writer) / 2) {
            size_t used = mpack_writer_buffer_used(writer);

            // We always return a non-null pointer that must be freed, even if
            // nothing was written. malloc() and realloc() do not necessarily
            // do this so we enforce it ourselves.
            size_t size = (used != 0) ? used : 1;

            char* buffer = (char*)mpack_realloc(writer->buffer, used, size);
            if (!buffer) {
                MPACK_FREE(writer->buffer);
                mpack_writer_flag_error(writer, mpack_error_memory);
                return;
            }
            writer->buffer = buffer;
            writer->end = (writer->position = writer->buffer + used);
        }

        *growable_writer->target_data = writer->buffer;
        *growable_writer->target_size = mpack_writer_buffer_used(writer);
        writer->buffer = NULL;

    } else if (writer->buffer) {
        MPACK_FREE(writer->buffer);
        writer->buffer = NULL;
    }

    writer->context = NULL;
}

void mpack_writer_init_growable(mpack_writer_t* writer, char** target_data, size_t* target_size) {
    mpack_assert(target_data != NULL, "cannot initialize writer without a destination for the data");
    mpack_assert(target_size != NULL, "cannot initialize writer without a destination for the size");

    *target_data = NULL;
    *target_size = 0;

    MPACK_STATIC_ASSERT(sizeof(mpack_growable_writer_t) <= sizeof(writer->reserved),
            "not enough reserved space for growable writer!");
    mpack_growable_writer_t* growable_writer = (mpack_growable_writer_t*)mpack_writer_get_reserved(writer);

    growable_writer->target_data = target_data;
    growable_writer->target_size = target_size;

    size_t capacity = MPACK_BUFFER_SIZE;
    char* buffer = (char*)MPACK_MALLOC(capacity);
    if (buffer == NULL) {
        mpack_writer_init_error(writer, mpack_error_memory);
        return;
    }

    mpack_writer_init(writer, buffer, capacity);
    mpack_writer_set_flush(writer, mpack_growable_writer_flush);
    mpack_writer_set_teardown(writer, mpack_growable_writer_teardown);
}
#endif

#if MPACK_STDIO
static void mpack_file_writer_flush(mpack_writer_t* writer, const char* buffer, size_t count) {
    FILE* file = (FILE*)writer->context;
    size_t written = fwrite((const void*)buffer, 1, count, file);
    if (written != count)
        mpack_writer_flag_error(writer, mpack_error_io);
}

static void mpack_file_writer_teardown(mpack_writer_t* writer) {
    MPACK_FREE(writer->buffer);
    writer->buffer = NULL;
    writer->context = NULL;
}

static void mpack_file_writer_teardown_close(mpack_writer_t* writer) {
    FILE* file = (FILE*)writer->context;

    if (file) {
        int ret = fclose(file);
        if (ret != 0)
            mpack_writer_flag_error(writer, mpack_error_io);
    }

    mpack_file_writer_teardown(writer);
}

void mpack_writer_init_stdfile(mpack_writer_t* writer, FILE* file, bool close_when_done) {
    mpack_assert(file != NULL, "file is NULL");

    size_t capacity = MPACK_BUFFER_SIZE;
    char* buffer = (char*)MPACK_MALLOC(capacity);
    if (buffer == NULL) {
        mpack_writer_init_error(writer, mpack_error_memory);
        if (close_when_done) {
            fclose(file);
        }
        return;
    }

    mpack_writer_init(writer, buffer, capacity);
    mpack_writer_set_context(writer, file);
    mpack_writer_set_flush(writer, mpack_file_writer_flush);
    mpack_writer_set_teardown(writer, close_when_done ?
            mpack_file_writer_teardown_close :
            mpack_file_writer_teardown);
}

void mpack_writer_init_filename(mpack_writer_t* writer, const char* filename) {
    mpack_assert(filename != NULL, "filename is NULL");

    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        mpack_writer_init_error(writer, mpack_error_io);
        return;
    }

    mpack_writer_init_stdfile(writer, file, true);
}
#endif

void mpack_writer_flag_error(mpack_writer_t* writer, mpack_error_t error) {
    mpack_log("writer %p setting error %i: %s\n", (void*)writer, (int)error, mpack_error_to_string(error));

    if (writer->error == mpack_ok) {
        writer->error = error;
        if (writer->error_fn)
            writer->error_fn(writer, writer->error);
    }
}

MPACK_STATIC_INLINE void mpack_writer_flush_unchecked(mpack_writer_t* writer) {
    // This is a bit ugly; we reset used before calling flush so that
    // a flush function can distinguish between flushing the buffer
    // versus flushing external data. see mpack_growable_writer_flush()
    size_t used = mpack_writer_buffer_used(writer);
    writer->position = writer->buffer;
    writer->flush(writer, writer->buffer, used);
}

void mpack_writer_flush_message(mpack_writer_t* writer) {
    if (writer->error != mpack_ok)
        return;

    #if MPACK_WRITE_TRACKING
    // You cannot flush while there are elements open.
    mpack_writer_flag_if_error(writer, mpack_track_check_empty(&writer->track));
    if (writer->error != mpack_ok)
        return;
    #endif

    #if MPACK_BUILDER
    if (writer->builder.current_build != NULL) {
        mpack_break("cannot call mpack_writer_flush_message() while there are elements open!");
        mpack_writer_flag_error(writer, mpack_error_bug);
        return;
    }
    #endif

    if (writer->flush == NULL) {
        mpack_break("cannot call mpack_writer_flush_message() without a flush function!");
        mpack_writer_flag_error(writer, mpack_error_bug);
        return;
    }

    if (mpack_writer_buffer_used(writer) > 0)
        mpack_writer_flush_unchecked(writer);
}

// Ensures there are at least count bytes free in the buffer. This
// will flag an error if the flush function fails to make enough
// room in the buffer.
MPACK_NOINLINE static bool mpack_writer_ensure(mpack_writer_t* writer, size_t count) {
    mpack_assert(count != 0, "cannot ensure zero bytes!");
    mpack_assert(count <= MPACK_WRITER_MINIMUM_BUFFER_SIZE,
            "cannot ensure %i bytes, this is more than the minimum buffer size %i!",
            (int)count, (int)MPACK_WRITER_MINIMUM_BUFFER_SIZE);
    mpack_assert(count > mpack_writer_buffer_left(writer),
            "request to ensure %i bytes but there are already %i left in the buffer!",
            (int)count, (int)mpack_writer_buffer_left(writer));

    mpack_log("ensuring %i bytes, %i left\n", (int)count, (int)mpack_writer_buffer_left(writer));

    if (mpack_writer_error(writer) != mpack_ok)
        return false;

    #if MPACK_BUILDER
    // if we have a build in progress, we just ask the builder for a page.
    // either it will have space for a tag, or it will flag a memory error.
    if (writer->builder.current_build != NULL) {
        mpack_builder_flush(writer);
        return mpack_writer_error(writer) == mpack_ok;
    }
    #endif

    if (writer->flush == NULL) {
        mpack_writer_flag_error(writer, mpack_error_too_big);
        return false;
    }

    mpack_writer_flush_unchecked(writer);
    if (mpack_writer_error(writer) != mpack_ok)
        return false;

    if (mpack_writer_buffer_left(writer) >= count)
        return true;

    mpack_writer_flag_error(writer, mpack_error_io);
    return false;
}

// Writes encoded bytes to the buffer when we already know the data
// does not fit in the buffer (i.e. it straddles the edge of the
// buffer.) If there is a flush function, it is guaranteed to be
// called; otherwise mpack_error_too_big is raised.
MPACK_NOINLINE static void mpack_write_native_straddle(mpack_writer_t* writer, const char* p, size_t count) {
    mpack_assert(count == 0 || p != NULL, "data pointer for %i bytes is NULL", (int)count);

    if (mpack_writer_error(writer) != mpack_ok)
        return;
    mpack_log("big write for %i bytes from %p, %i space left in buffer\n",
            (int)count, p, (int)mpack_writer_buffer_left(writer));
    mpack_assert(count > mpack_writer_buffer_left(writer),
            "big write requested for %i bytes, but there is %i available "
            "space in buffer. should have called mpack_write_native() instead",
            (int)count, (int)(mpack_writer_buffer_left(writer)));

    #if MPACK_BUILDER
    // if we have a build in progress, we can't flush. we need to copy all
    // bytes into as many build buffer pages as it takes.
    if (writer->builder.current_build != NULL) {
        while (true) {
            size_t step = (size_t)(writer->end - writer->position);
            if (step > count)
                step = count;
            mpack_memcpy(writer->position, p, step);
            writer->position += step;
            p += step;
            count -= step;

            if (count == 0)
                return;

            mpack_builder_flush(writer);
            if (mpack_writer_error(writer) != mpack_ok)
                return;
            mpack_assert(writer->position != writer->end);
        }
    }
    #endif

    // we'll need a flush function
    if (!writer->flush) {
        mpack_writer_flag_error(writer, mpack_error_too_big);
        return;
    }

    // flush the buffer
    mpack_writer_flush_unchecked(writer);
    if (mpack_writer_error(writer) != mpack_ok)
        return;

    // note that an intrusive flush function (such as mpack_growable_writer_flush())
    // may have changed size and/or reset used to a non-zero value. we treat both as
    // though they may have changed, and there may still be data in the buffer.

    // flush the extra data directly if it doesn't fit in the buffer
    if (count > mpack_writer_buffer_left(writer)) {
        writer->flush(writer, p, count);
        if (mpack_writer_error(writer) != mpack_ok)
            return;
    } else {
        mpack_memcpy(writer->position, p, count);
        writer->position += count;
    }
}

// Writes encoded bytes to the buffer, flushing if necessary.
MPACK_STATIC_INLINE void mpack_write_native(mpack_writer_t* writer, const char* p, size_t count) {
    mpack_assert(count == 0 || p != NULL, "data pointer for %i bytes is NULL", (int)count);

    if (mpack_writer_buffer_left(writer) < count) {
        mpack_write_native_straddle(writer, p, count);
    } else {
        mpack_memcpy(writer->position, p, count);
        writer->position += count;
    }
}

mpack_error_t mpack_writer_destroy(mpack_writer_t* writer) {

    // clean up tracking, asserting if we're not already in an error state
    #if MPACK_WRITE_TRACKING
    mpack_track_destroy(&writer->track, writer->error != mpack_ok);
    #endif

    // flush any outstanding data
    if (mpack_writer_error(writer) == mpack_ok && mpack_writer_buffer_used(writer) != 0 && writer->flush != NULL) {
        writer->flush(writer, writer->buffer, mpack_writer_buffer_used(writer));
        writer->flush = NULL;
    }

    if (writer->teardown) {
        writer->teardown(writer);
        writer->teardown = NULL;
    }

    return writer->error;
}

void mpack_write_tag(mpack_writer_t* writer, mpack_tag_t value) {
    switch (value.type) {
        case mpack_type_missing:
            mpack_break("cannot write a missing value!");
            mpack_writer_flag_error(writer, mpack_error_bug);
            return;

        case mpack_type_nil:    mpack_write_nil   (writer);            return;
        case mpack_type_bool:   mpack_write_bool  (writer, value.v.b); return;
        case mpack_type_int:    mpack_write_int   (writer, value.v.i); return;
        case mpack_type_uint:   mpack_write_uint  (writer, value.v.u); return;

        case mpack_type_float:
            #if MPACK_FLOAT
            mpack_write_float
            #else
            mpack_write_raw_float
            #endif
                (writer, value.v.f);
            return;
        case mpack_type_double:
            #if MPACK_DOUBLE
            mpack_write_double
            #else
            mpack_write_raw_double
            #endif
                (writer, value.v.d);
            return;

        case mpack_type_str: mpack_start_str(writer, value.v.l); return;
        case mpack_type_bin: mpack_start_bin(writer, value.v.l); return;

        #if MPACK_EXTENSIONS
        case mpack_type_ext:
            mpack_start_ext(writer, mpack_tag_ext_exttype(&value), mpack_tag_ext_length(&value));
            return;
        #endif

        case mpack_type_array: mpack_start_array(writer, value.v.n); return;
        case mpack_type_map:   mpack_start_map(writer, value.v.n);   return;
    }

    mpack_break("unrecognized type %i", (int)value.type);
    mpack_writer_flag_error(writer, mpack_error_bug);
}

MPACK_STATIC_INLINE void mpack_write_byte_element(mpack_writer_t* writer, char value) {
    mpack_writer_track_element(writer);
    if (MPACK_LIKELY(mpack_writer_buffer_left(writer) >= 1) || mpack_writer_ensure(writer, 1))
        *(writer->position++) = value;
}

void mpack_write_nil(mpack_writer_t* writer) {
    mpack_write_byte_element(writer, (char)0xc0);
}

void mpack_write_bool(mpack_writer_t* writer, bool value) {
    mpack_write_byte_element(writer, (char)(0xc2 | (value ? 1 : 0)));
}

void mpack_write_true(mpack_writer_t* writer) {
    mpack_write_byte_element(writer, (char)0xc3);
}

void mpack_write_false(mpack_writer_t* writer) {
    mpack_write_byte_element(writer, (char)0xc2);
}

void mpack_write_object_bytes(mpack_writer_t* writer, const char* data, size_t bytes) {
    mpack_writer_track_element(writer);
    mpack_write_native(writer, data, bytes);
}

/*
 * Encode functions
 */

MPACK_STATIC_INLINE void mpack_encode_fixuint(char* p, uint8_t value) {
    mpack_assert(value <= 127);
    mpack_store_u8(p, value);
}

MPACK_STATIC_INLINE void mpack_encode_u8(char* p, uint8_t value) {
    mpack_assert(value > 127);
    mpack_store_u8(p, 0xcc);
    mpack_store_u8(p + 1, value);
}

MPACK_STATIC_INLINE void mpack_encode_u16(char* p, uint16_t value) {
    mpack_assert(value > MPACK_UINT8_MAX);
    mpack_store_u8(p, 0xcd);
    mpack_store_u16(p + 1, value);
}

MPACK_STATIC_INLINE void mpack_encode_u32(char* p, uint32_t value) {
    mpack_assert(value > MPACK_UINT16_MAX);
    mpack_store_u8(p, 0xce);
    mpack_store_u32(p + 1, value);
}

MPACK_STATIC_INLINE void mpack_encode_u64(char* p, uint64_t value) {
    mpack_assert(value > MPACK_UINT32_MAX);
    mpack_store_u8(p, 0xcf);
    mpack_store_u64(p + 1, value);
}

MPACK_STATIC_INLINE void mpack_encode_fixint(char* p, int8_t value) {
    // this can encode positive or negative fixints
    mpack_assert(value >= -32);
    mpack_store_i8(p, value);
}

MPACK_STATIC_INLINE void mpack_encode_i8(char* p, int8_t value) {
    mpack_assert(value < -32);
    mpack_store_u8(p, 0xd0);
    mpack_store_i8(p + 1, value);
}

MPACK_STATIC_INLINE void mpack_encode_i16(char* p, int16_t value) {
    mpack_assert(value < MPACK_INT8_MIN);
    mpack_store_u8(p, 0xd1);
    mpack_store_i16(p + 1, value);
}

MPACK_STATIC_INLINE void mpack_encode_i32(char* p, int32_t value) {
    mpack_assert(value < MPACK_INT16_MIN);
    mpack_store_u8(p, 0xd2);
    mpack_store_i32(p + 1, value);
}

MPACK_STATIC_INLINE void mpack_encode_i64(char* p, int64_t value) {
    mpack_assert(value < MPACK_INT32_MIN);
    mpack_store_u8(p, 0xd3);
    mpack_store_i64(p + 1, value);
}

#if MPACK_FLOAT
MPACK_STATIC_INLINE void mpack_encode_float(char* p, float value) {
    mpack_store_u8(p, 0xca);
    mpack_store_float(p + 1, value);
}
#else
MPACK_STATIC_INLINE void mpack_encode_raw_float(char* p, uint32_t value) {
    mpack_store_u8(p, 0xca);
    mpack_store_u32(p + 1, value);
}
#endif

#if MPACK_DOUBLE
MPACK_STATIC_INLINE void mpack_encode_double(char* p, double value) {
    mpack_store_u8(p, 0xcb);
    mpack_store_double(p + 1, value);
}
#else
MPACK_STATIC_INLINE void mpack_encode_raw_double(char* p, uint64_t value) {
    mpack_store_u8(p, 0xcb);
    mpack_store_u64(p + 1, value);
}
#endif

MPACK_STATIC_INLINE void mpack_encode_fixarray(char* p, uint8_t count) {
    mpack_assert(count <= 15);
    mpack_store_u8(p, (uint8_t)(0x90 | count));
}

MPACK_STATIC_INLINE void mpack_encode_array16(char* p, uint16_t count) {
    mpack_assert(count > 15);
    mpack_store_u8(p, 0xdc);
    mpack_store_u16(p + 1, count);
}

MPACK_STATIC_INLINE void mpack_encode_array32(char* p, uint32_t count) {
    mpack_assert(count > MPACK_UINT16_MAX);
    mpack_store_u8(p, 0xdd);
    mpack_store_u32(p + 1, count);
}

MPACK_STATIC_INLINE void mpack_encode_fixmap(char* p, uint8_t count) {
    mpack_assert(count <= 15);
    mpack_store_u8(p, (uint8_t)(0x80 | count));
}

MPACK_STATIC_INLINE void mpack_encode_map16(char* p, uint16_t count) {
    mpack_assert(count > 15);
    mpack_store_u8(p, 0xde);
    mpack_store_u16(p + 1, count);
}

MPACK_STATIC_INLINE void mpack_encode_map32(char* p, uint32_t count) {
    mpack_assert(count > MPACK_UINT16_MAX);
    mpack_store_u8(p, 0xdf);
    mpack_store_u32(p + 1, count);
}

MPACK_STATIC_INLINE void mpack_encode_fixstr(char* p, uint8_t count) {
    mpack_assert(count <= 31);
    mpack_store_u8(p, (uint8_t)(0xa0 | count));
}

MPACK_STATIC_INLINE void mpack_encode_str8(char* p, uint8_t count) {
    mpack_assert(count > 31);
    mpack_store_u8(p, 0xd9);
    mpack_store_u8(p + 1, count);
}

MPACK_STATIC_INLINE void mpack_encode_str16(char* p, uint16_t count) {
    // we might be encoding a raw in compatibility mode, so we
    // allow count to be in the range [32, MPACK_UINT8_MAX].
    mpack_assert(count > 31);
    mpack_store_u8(p, 0xda);
    mpack_store_u16(p + 1, count);
}

MPACK_STATIC_INLINE void mpack_encode_str32(char* p, uint32_t count) {
    mpack_assert(count > MPACK_UINT16_MAX);
    mpack_store_u8(p, 0xdb);
    mpack_store_u32(p + 1, count);
}

MPACK_STATIC_INLINE void mpack_encode_bin8(char* p, uint8_t count) {
    mpack_store_u8(p, 0xc4);
    mpack_store_u8(p + 1, count);
}

MPACK_STATIC_INLINE void mpack_encode_bin16(char* p, uint16_t count) {
    mpack_assert(count > MPACK_UINT8_MAX);
    mpack_store_u8(p, 0xc5);
    mpack_store_u16(p + 1, count);
}

MPACK_STATIC_INLINE void mpack_encode_bin32(char* p, uint32_t count) {
    mpack_assert(count > MPACK_UINT16_MAX);
    mpack_store_u8(p, 0xc6);
    mpack_store_u32(p + 1, count);
}

#if MPACK_EXTENSIONS
MPACK_STATIC_INLINE void mpack_encode_fixext1(char* p, int8_t exttype) {
    mpack_store_u8(p, 0xd4);
    mpack_store_i8(p + 1, exttype);
}

MPACK_STATIC_INLINE void mpack_encode_fixext2(char* p, int8_t exttype) {
    mpack_store_u8(p, 0xd5);
    mpack_store_i8(p + 1, exttype);
}

MPACK_STATIC_INLINE void mpack_encode_fixext4(char* p, int8_t exttype) {
    mpack_store_u8(p, 0xd6);
    mpack_store_i8(p + 1, exttype);
}

MPACK_STATIC_INLINE void mpack_encode_fixext8(char* p, int8_t exttype) {
    mpack_store_u8(p, 0xd7);
    mpack_store_i8(p + 1, exttype);
}

MPACK_STATIC_INLINE void mpack_encode_fixext16(char* p, int8_t exttype) {
    mpack_store_u8(p, 0xd8);
    mpack_store_i8(p + 1, exttype);
}

MPACK_STATIC_INLINE void mpack_encode_ext8(char* p, int8_t exttype, uint8_t count) {
    mpack_assert(count != 1 && count != 2 && count != 4 && count != 8 && count != 16);
    mpack_store_u8(p, 0xc7);
    mpack_store_u8(p + 1, count);
    mpack_store_i8(p + 2, exttype);
}

MPACK_STATIC_INLINE void mpack_encode_ext16(char* p, int8_t exttype, uint16_t count) {
    mpack_assert(count > MPACK_UINT8_MAX);
    mpack_store_u8(p, 0xc8);
    mpack_store_u16(p + 1, count);
    mpack_store_i8(p + 3, exttype);
}

MPACK_STATIC_INLINE void mpack_encode_ext32(char* p, int8_t exttype, uint32_t count) {
    mpack_assert(count > MPACK_UINT16_MAX);
    mpack_store_u8(p, 0xc9);
    mpack_store_u32(p + 1, count);
    mpack_store_i8(p + 5, exttype);
}

MPACK_STATIC_INLINE void mpack_encode_timestamp_4(char* p, uint32_t seconds) {
    mpack_encode_fixext4(p, MPACK_EXTTYPE_TIMESTAMP);
    mpack_store_u32(p + MPACK_TAG_SIZE_FIXEXT4, seconds);
}

MPACK_STATIC_INLINE void mpack_encode_timestamp_8(char* p, int64_t seconds, uint32_t nanoseconds) {
    mpack_assert(nanoseconds <= MPACK_TIMESTAMP_NANOSECONDS_MAX);
    mpack_encode_fixext8(p, MPACK_EXTTYPE_TIMESTAMP);
    uint64_t encoded = ((uint64_t)nanoseconds << 34) | (uint64_t)seconds;
    mpack_store_u64(p + MPACK_TAG_SIZE_FIXEXT8, encoded);
}

MPACK_STATIC_INLINE void mpack_encode_timestamp_12(char* p, int64_t seconds, uint32_t nanoseconds) {
    mpack_assert(nanoseconds <= MPACK_TIMESTAMP_NANOSECONDS_MAX);
    mpack_encode_ext8(p, MPACK_EXTTYPE_TIMESTAMP, 12);
    mpack_store_u32(p + MPACK_TAG_SIZE_EXT8, nanoseconds);
    mpack_store_i64(p + MPACK_TAG_SIZE_EXT8 + 4, seconds);
}
#endif



/*
 * Write functions
 */

// This is a macro wrapper to the encode functions to encode
// directly into the buffer. If mpack_writer_ensure() fails
// it will flag an error so we don't have to do anything.
#define MPACK_WRITE_ENCODED(encode_fn, size, ...) do {                                                 \
    if (MPACK_LIKELY(mpack_writer_buffer_left(writer) >= size) || mpack_writer_ensure(writer, size)) { \
        MPACK_EXPAND(encode_fn(writer->position, __VA_ARGS__));                                        \
        writer->position += size;                                                                      \
    }                                                                                                  \
} while (0)

void mpack_write_u8(mpack_writer_t* writer, uint8_t value) {
    #if MPACK_OPTIMIZE_FOR_SIZE
    mpack_write_u64(writer, value);
    #else
    mpack_writer_track_element(writer);
    if (value <= 127) {
        MPACK_WRITE_ENCODED(mpack_encode_fixuint, MPACK_TAG_SIZE_FIXUINT, value);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_u8, MPACK_TAG_SIZE_U8, value);
    }
    #endif
}

void mpack_write_u16(mpack_writer_t* writer, uint16_t value) {
    #if MPACK_OPTIMIZE_FOR_SIZE
    mpack_write_u64(writer, value);
    #else
    mpack_writer_track_element(writer);
    if (value <= 127) {
        MPACK_WRITE_ENCODED(mpack_encode_fixuint, MPACK_TAG_SIZE_FIXUINT, (uint8_t)value);
    } else if (value <= MPACK_UINT8_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_u8, MPACK_TAG_SIZE_U8, (uint8_t)value);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_u16, MPACK_TAG_SIZE_U16, value);
    }
    #endif
}

void mpack_write_u32(mpack_writer_t* writer, uint32_t value) {
    #if MPACK_OPTIMIZE_FOR_SIZE
    mpack_write_u64(writer, value);
    #else
    mpack_writer_track_element(writer);
    if (value <= 127) {
        MPACK_WRITE_ENCODED(mpack_encode_fixuint, MPACK_TAG_SIZE_FIXUINT, (uint8_t)value);
    } else if (value <= MPACK_UINT8_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_u8, MPACK_TAG_SIZE_U8, (uint8_t)value);
    } else if (value <= MPACK_UINT16_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_u16, MPACK_TAG_SIZE_U16, (uint16_t)value);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_u32, MPACK_TAG_SIZE_U32, value);
    }
    #endif
}

void mpack_write_u64(mpack_writer_t* writer, uint64_t value) {
    mpack_writer_track_element(writer);

    if (value <= 127) {
        MPACK_WRITE_ENCODED(mpack_encode_fixuint, MPACK_TAG_SIZE_FIXUINT, (uint8_t)value);
    } else if (value <= MPACK_UINT8_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_u8, MPACK_TAG_SIZE_U8, (uint8_t)value);
    } else if (value <= MPACK_UINT16_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_u16, MPACK_TAG_SIZE_U16, (uint16_t)value);
    } else if (value <= MPACK_UINT32_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_u32, MPACK_TAG_SIZE_U32, (uint32_t)value);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_u64, MPACK_TAG_SIZE_U64, value);
    }
}

void mpack_write_i8(mpack_writer_t* writer, int8_t value) {
    #if MPACK_OPTIMIZE_FOR_SIZE
    mpack_write_i64(writer, value);
    #else
    mpack_writer_track_element(writer);
    if (value >= -32) {
        // we encode positive and negative fixints together
        MPACK_WRITE_ENCODED(mpack_encode_fixint, MPACK_TAG_SIZE_FIXINT, (int8_t)value);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_i8, MPACK_TAG_SIZE_I8, (int8_t)value);
    }
    #endif
}

void mpack_write_i16(mpack_writer_t* writer, int16_t value) {
    #if MPACK_OPTIMIZE_FOR_SIZE
    mpack_write_i64(writer, value);
    #else
    mpack_writer_track_element(writer);
    if (value >= -32) {
        if (value <= 127) {
            // we encode positive and negative fixints together
            MPACK_WRITE_ENCODED(mpack_encode_fixint, MPACK_TAG_SIZE_FIXINT, (int8_t)value);
        } else if (value <= MPACK_UINT8_MAX) {
            MPACK_WRITE_ENCODED(mpack_encode_u8, MPACK_TAG_SIZE_U8, (uint8_t)value);
        } else {
            MPACK_WRITE_ENCODED(mpack_encode_u16, MPACK_TAG_SIZE_U16, (uint16_t)value);
        }
    } else if (value >= MPACK_INT8_MIN) {
        MPACK_WRITE_ENCODED(mpack_encode_i8, MPACK_TAG_SIZE_I8, (int8_t)value);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_i16, MPACK_TAG_SIZE_I16, (int16_t)value);
    }
    #endif
}

void mpack_write_i32(mpack_writer_t* writer, int32_t value) {
    #if MPACK_OPTIMIZE_FOR_SIZE
    mpack_write_i64(writer, value);
    #else
    mpack_writer_track_element(writer);
    if (value >= -32) {
        if (value <= 127) {
            // we encode positive and negative fixints together
            MPACK_WRITE_ENCODED(mpack_encode_fixint, MPACK_TAG_SIZE_FIXINT, (int8_t)value);
        } else if (value <= MPACK_UINT8_MAX) {
            MPACK_WRITE_ENCODED(mpack_encode_u8, MPACK_TAG_SIZE_U8, (uint8_t)value);
        } else if (value <= MPACK_UINT16_MAX) {
            MPACK_WRITE_ENCODED(mpack_encode_u16, MPACK_TAG_SIZE_U16, (uint16_t)value);
        } else {
            MPACK_WRITE_ENCODED(mpack_encode_u32, MPACK_TAG_SIZE_U32, (uint32_t)value);
        }
    } else if (value >= MPACK_INT8_MIN) {
        MPACK_WRITE_ENCODED(mpack_encode_i8, MPACK_TAG_SIZE_I8, (int8_t)value);
    } else if (value >= MPACK_INT16_MIN) {
        MPACK_WRITE_ENCODED(mpack_encode_i16, MPACK_TAG_SIZE_I16, (int16_t)value);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_i32, MPACK_TAG_SIZE_I32, value);
    }
    #endif
}

void mpack_write_i64(mpack_writer_t* writer, int64_t value) {
    #if MPACK_OPTIMIZE_FOR_SIZE
    if (value > 127) {
        // for non-fix positive ints we call the u64 writer to save space
        mpack_write_u64(writer, (uint64_t)value);
        return;
    }
    #endif

    mpack_writer_track_element(writer);
    if (value >= -32) {
        #if MPACK_OPTIMIZE_FOR_SIZE
        MPACK_WRITE_ENCODED(mpack_encode_fixint, MPACK_TAG_SIZE_FIXINT, (int8_t)value);
        #else
        if (value <= 127) {
            MPACK_WRITE_ENCODED(mpack_encode_fixint, MPACK_TAG_SIZE_FIXINT, (int8_t)value);
        } else if (value <= MPACK_UINT8_MAX) {
            MPACK_WRITE_ENCODED(mpack_encode_u8, MPACK_TAG_SIZE_U8, (uint8_t)value);
        } else if (value <= MPACK_UINT16_MAX) {
            MPACK_WRITE_ENCODED(mpack_encode_u16, MPACK_TAG_SIZE_U16, (uint16_t)value);
        } else if (value <= MPACK_UINT32_MAX) {
            MPACK_WRITE_ENCODED(mpack_encode_u32, MPACK_TAG_SIZE_U32, (uint32_t)value);
        } else {
            MPACK_WRITE_ENCODED(mpack_encode_u64, MPACK_TAG_SIZE_U64, (uint64_t)value);
        }
        #endif
    } else if (value >= MPACK_INT8_MIN) {
        MPACK_WRITE_ENCODED(mpack_encode_i8, MPACK_TAG_SIZE_I8, (int8_t)value);
    } else if (value >= MPACK_INT16_MIN) {
        MPACK_WRITE_ENCODED(mpack_encode_i16, MPACK_TAG_SIZE_I16, (int16_t)value);
    } else if (value >= MPACK_INT32_MIN) {
        MPACK_WRITE_ENCODED(mpack_encode_i32, MPACK_TAG_SIZE_I32, (int32_t)value);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_i64, MPACK_TAG_SIZE_I64, value);
    }
}

#if MPACK_FLOAT
void mpack_write_float(mpack_writer_t* writer, float value) {
    mpack_writer_track_element(writer);
    MPACK_WRITE_ENCODED(mpack_encode_float, MPACK_TAG_SIZE_FLOAT, value);
}
#else
void mpack_write_raw_float(mpack_writer_t* writer, uint32_t value) {
    mpack_writer_track_element(writer);
    MPACK_WRITE_ENCODED(mpack_encode_raw_float, MPACK_TAG_SIZE_FLOAT, value);
}
#endif

#if MPACK_DOUBLE
void mpack_write_double(mpack_writer_t* writer, double value) {
    mpack_writer_track_element(writer);
    MPACK_WRITE_ENCODED(mpack_encode_double, MPACK_TAG_SIZE_DOUBLE, value);
}
#else
void mpack_write_raw_double(mpack_writer_t* writer, uint64_t value) {
    mpack_writer_track_element(writer);
    MPACK_WRITE_ENCODED(mpack_encode_raw_double, MPACK_TAG_SIZE_DOUBLE, value);
}
#endif

#if MPACK_EXTENSIONS
void mpack_write_timestamp(mpack_writer_t* writer, int64_t seconds, uint32_t nanoseconds) {
    #if MPACK_COMPATIBILITY
    if (writer->version <= mpack_version_v4) {
        mpack_break("Timestamps require spec version v5 or later. This writer is in v%i mode.", (int)writer->version);
        mpack_writer_flag_error(writer, mpack_error_bug);
        return;
    }
    #endif

    if (nanoseconds > MPACK_TIMESTAMP_NANOSECONDS_MAX) {
        mpack_break("timestamp nanoseconds out of bounds: %u", nanoseconds);
        mpack_writer_flag_error(writer, mpack_error_bug);
        return;
    }

    mpack_writer_track_element(writer);

    if (seconds < 0 || seconds >= (MPACK_INT64_C(1) << 34)) {
        MPACK_WRITE_ENCODED(mpack_encode_timestamp_12, MPACK_EXT_SIZE_TIMESTAMP12, seconds, nanoseconds);
    } else if (seconds > MPACK_UINT32_MAX || nanoseconds > 0) {
        MPACK_WRITE_ENCODED(mpack_encode_timestamp_8, MPACK_EXT_SIZE_TIMESTAMP8, seconds, nanoseconds);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_timestamp_4, MPACK_EXT_SIZE_TIMESTAMP4, (uint32_t)seconds);
    }
}
#endif

static void mpack_write_array_notrack(mpack_writer_t* writer, uint32_t count) {
    if (count <= 15) {
        MPACK_WRITE_ENCODED(mpack_encode_fixarray, MPACK_TAG_SIZE_FIXARRAY, (uint8_t)count);
    } else if (count <= MPACK_UINT16_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_array16, MPACK_TAG_SIZE_ARRAY16, (uint16_t)count);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_array32, MPACK_TAG_SIZE_ARRAY32, (uint32_t)count);
    }
}

static void mpack_write_map_notrack(mpack_writer_t* writer, uint32_t count) {
    if (count <= 15) {
        MPACK_WRITE_ENCODED(mpack_encode_fixmap, MPACK_TAG_SIZE_FIXMAP, (uint8_t)count);
    } else if (count <= MPACK_UINT16_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_map16, MPACK_TAG_SIZE_MAP16, (uint16_t)count);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_map32, MPACK_TAG_SIZE_MAP32, (uint32_t)count);
    }
}

void mpack_start_array(mpack_writer_t* writer, uint32_t count) {
    mpack_writer_track_element(writer);
    mpack_write_array_notrack(writer, count);
    mpack_writer_track_push(writer, mpack_type_array, count);
    mpack_builder_compound_push(writer);
}

void mpack_start_map(mpack_writer_t* writer, uint32_t count) {
    mpack_writer_track_element(writer);
    mpack_write_map_notrack(writer, count);
    mpack_writer_track_push(writer, mpack_type_map, count);
    mpack_builder_compound_push(writer);
}

static void mpack_start_str_notrack(mpack_writer_t* writer, uint32_t count) {
    if (count <= 31) {
        MPACK_WRITE_ENCODED(mpack_encode_fixstr, MPACK_TAG_SIZE_FIXSTR, (uint8_t)count);

    // str8 is only supported in v5 or later.
    } else if (count <= MPACK_UINT8_MAX
            #if MPACK_COMPATIBILITY
            && writer->version >= mpack_version_v5
            #endif
            ) {
        MPACK_WRITE_ENCODED(mpack_encode_str8, MPACK_TAG_SIZE_STR8, (uint8_t)count);

    } else if (count <= MPACK_UINT16_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_str16, MPACK_TAG_SIZE_STR16, (uint16_t)count);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_str32, MPACK_TAG_SIZE_STR32, (uint32_t)count);
    }
}

static void mpack_start_bin_notrack(mpack_writer_t* writer, uint32_t count) {
    #if MPACK_COMPATIBILITY
    // In the v4 spec, there was only the raw type for any kind of
    // variable-length data. In v4 mode, we support the bin functions,
    // but we produce an old-style raw.
    if (writer->version <= mpack_version_v4) {
        mpack_start_str_notrack(writer, count);
        return;
    }
    #endif

    if (count <= MPACK_UINT8_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_bin8, MPACK_TAG_SIZE_BIN8, (uint8_t)count);
    } else if (count <= MPACK_UINT16_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_bin16, MPACK_TAG_SIZE_BIN16, (uint16_t)count);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_bin32, MPACK_TAG_SIZE_BIN32, (uint32_t)count);
    }
}

void mpack_start_str(mpack_writer_t* writer, uint32_t count) {
    mpack_writer_track_element(writer);
    mpack_start_str_notrack(writer, count);
    mpack_writer_track_push(writer, mpack_type_str, count);
}

void mpack_start_bin(mpack_writer_t* writer, uint32_t count) {
    mpack_writer_track_element(writer);
    mpack_start_bin_notrack(writer, count);
    mpack_writer_track_push(writer, mpack_type_bin, count);
}

#if MPACK_EXTENSIONS
void mpack_start_ext(mpack_writer_t* writer, int8_t exttype, uint32_t count) {
    #if MPACK_COMPATIBILITY
    if (writer->version <= mpack_version_v4) {
        mpack_break("Ext types require spec version v5 or later. This writer is in v%i mode.", (int)writer->version);
        mpack_writer_flag_error(writer, mpack_error_bug);
        return;
    }
    #endif

    mpack_writer_track_element(writer);

    if (count == 1) {
        MPACK_WRITE_ENCODED(mpack_encode_fixext1, MPACK_TAG_SIZE_FIXEXT1, exttype);
    } else if (count == 2) {
        MPACK_WRITE_ENCODED(mpack_encode_fixext2, MPACK_TAG_SIZE_FIXEXT2, exttype);
    } else if (count == 4) {
        MPACK_WRITE_ENCODED(mpack_encode_fixext4, MPACK_TAG_SIZE_FIXEXT4, exttype);
    } else if (count == 8) {
        MPACK_WRITE_ENCODED(mpack_encode_fixext8, MPACK_TAG_SIZE_FIXEXT8, exttype);
    } else if (count == 16) {
        MPACK_WRITE_ENCODED(mpack_encode_fixext16, MPACK_TAG_SIZE_FIXEXT16, exttype);
    } else if (count <= MPACK_UINT8_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_ext8, MPACK_TAG_SIZE_EXT8, exttype, (uint8_t)count);
    } else if (count <= MPACK_UINT16_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_ext16, MPACK_TAG_SIZE_EXT16, exttype, (uint16_t)count);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_ext32, MPACK_TAG_SIZE_EXT32, exttype, (uint32_t)count);
    }

    mpack_writer_track_push(writer, mpack_type_ext, count);
}
#endif



/*
 * Compound helpers and other functions
 */

void mpack_write_str(mpack_writer_t* writer, const char* data, uint32_t count) {
    mpack_assert(data != NULL, "data for string of length %i is NULL", (int)count);

    #if MPACK_OPTIMIZE_FOR_SIZE
    mpack_writer_track_element(writer);
    mpack_start_str_notrack(writer, count);
    mpack_write_native(writer, data, count);
    #else

    mpack_writer_track_element(writer);

    if (count <= 31) {
        // The minimum buffer size when using a flush function is guaranteed to
        // fit the largest possible fixstr.
        size_t size = count + MPACK_TAG_SIZE_FIXSTR;
        if (MPACK_LIKELY(mpack_writer_buffer_left(writer) >= size) || mpack_writer_ensure(writer, size)) {
            char* MPACK_RESTRICT p = writer->position;
            mpack_encode_fixstr(p, (uint8_t)count);
            mpack_memcpy(p + MPACK_TAG_SIZE_FIXSTR, data, count);
            writer->position += count + MPACK_TAG_SIZE_FIXSTR;
        }
        return;
    }

    if (count <= MPACK_UINT8_MAX
            #if MPACK_COMPATIBILITY
            && writer->version >= mpack_version_v5
            #endif
            ) {
        if (count + MPACK_TAG_SIZE_STR8 <= mpack_writer_buffer_left(writer)) {
            char* MPACK_RESTRICT p = writer->position;
            mpack_encode_str8(p, (uint8_t)count);
            mpack_memcpy(p + MPACK_TAG_SIZE_STR8, data, count);
            writer->position += count + MPACK_TAG_SIZE_STR8;
        } else {
            MPACK_WRITE_ENCODED(mpack_encode_str8, MPACK_TAG_SIZE_STR8, (uint8_t)count);
            mpack_write_native(writer, data, count);
        }
        return;
    }

    // str16 and str32 are likely to be a significant fraction of the buffer
    // size, so we don't bother with a combined space check in order to
    // minimize code size.
    if (count <= MPACK_UINT16_MAX) {
        MPACK_WRITE_ENCODED(mpack_encode_str16, MPACK_TAG_SIZE_STR16, (uint16_t)count);
        mpack_write_native(writer, data, count);
    } else {
        MPACK_WRITE_ENCODED(mpack_encode_str32, MPACK_TAG_SIZE_STR32, (uint32_t)count);
        mpack_write_native(writer, data, count);
    }

    #endif
}

void mpack_write_bin(mpack_writer_t* writer, const char* data, uint32_t count) {
    mpack_assert(data != NULL, "data pointer for bin of %i bytes is NULL", (int)count);
    mpack_start_bin(writer, count);
    mpack_write_bytes(writer, data, count);
    mpack_finish_bin(writer);
}

#if MPACK_EXTENSIONS
void mpack_write_ext(mpack_writer_t* writer, int8_t exttype, const char* data, uint32_t count) {
    mpack_assert(data != NULL, "data pointer for ext of type %i and %i bytes is NULL", exttype, (int)count);
    mpack_start_ext(writer, exttype, count);
    mpack_write_bytes(writer, data, count);
    mpack_finish_ext(writer);
}
#endif

void mpack_write_bytes(mpack_writer_t* writer, const char* data, size_t count) {
    mpack_assert(data != NULL, "data pointer for %i bytes is NULL", (int)count);
    mpack_writer_track_bytes(writer, count);
    mpack_write_native(writer, data, count);
}

void mpack_write_cstr(mpack_writer_t* writer, const char* cstr) {
    mpack_assert(cstr != NULL, "cstr pointer is NULL");
    size_t length = mpack_strlen(cstr);
    if (length > MPACK_UINT32_MAX)
        mpack_writer_flag_error(writer, mpack_error_invalid);
    mpack_write_str(writer, cstr, (uint32_t)length);
}

void mpack_write_cstr_or_nil(mpack_writer_t* writer, const char* cstr) {
    if (cstr)
        mpack_write_cstr(writer, cstr);
    else
        mpack_write_nil(writer);
}

void mpack_write_utf8(mpack_writer_t* writer, const char* str, uint32_t length) {
    mpack_assert(str != NULL, "data for string of length %i is NULL", (int)length);
    if (!mpack_utf8_check(str, length)) {
        mpack_writer_flag_error(writer, mpack_error_invalid);
        return;
    }
    mpack_write_str(writer, str, length);
}

void mpack_write_utf8_cstr(mpack_writer_t* writer, const char* cstr) {
    mpack_assert(cstr != NULL, "cstr pointer is NULL");
    size_t length = mpack_strlen(cstr);
    if (length > MPACK_UINT32_MAX) {
        mpack_writer_flag_error(writer, mpack_error_invalid);
        return;
    }
    mpack_write_utf8(writer, cstr, (uint32_t)length);
}

void mpack_write_utf8_cstr_or_nil(mpack_writer_t* writer, const char* cstr) {
    if (cstr)
        mpack_write_utf8_cstr(writer, cstr);
    else
        mpack_write_nil(writer);
}

/*
 * Builder implementation
 *
 * When a writer is in build mode, it diverts writes to an internal growable
 * buffer. All elements other than builder start tags are encoded as normal
 * into the builder buffer (even nested maps and arrays of known size, e.g.
 * `mpack_start_array()`.) But for compound elements of unknown size, an
 * mpack_build_t is written to the buffer instead.
 *
 * The mpack_build_t tracks everything needed to re-constitute the final
 * message once all sizes are known. When the last build element is completed,
 * the builder resolves the build by walking through the builds, outputting the
 * final encoded tag, and copying everything in between to the writer's true
 * buffer.
 *
 * To make things extra complicated, the builder buffer is not contiguous. It's
 * allocated in pages, where the first page may be an internal page in the
 * writer. But, each mpack_build_t must itself be contiguous and aligned
 * properly within the buffer. This means bytes can be skipped (and wasted)
 * before the builds or at the end of pages.
 *
 * To keep track of this, builds store both their element count and the number
 * of encoded bytes that follow, and pages store the number of bytes used. As
 * elements are written, each element adds to the count in the current open
 * build, and the number of bytes written adds to the current page and the byte
 * count in the last started build (whether or not it is completed.)
 */

#if MPACK_BUILDER

#ifdef MPACK_ALIGNOF
    #define MPACK_BUILD_ALIGNMENT MPACK_ALIGNOF(mpack_build_t)
#else
    // without alignof, we just align to the greater of size_t, void* and uint64_t.
    // (we do this even though we don't have uint64_t in it in case we add it later.)
    #define MPACK_BUILD_ALIGNMENT_MAX(x, y) ((x) > (y) ? (x) : (y))
    #define MPACK_BUILD_ALIGNMENT (MPACK_BUILD_ALIGNMENT_MAX(sizeof(void*), \
                MPACK_BUILD_ALIGNMENT_MAX(sizeof(size_t), sizeof(uint64_t))))
#endif

static inline void mpack_builder_check_sizes(mpack_writer_t* writer) {

    // We check internal and page sizes here so that we don't have to check
    // them again. A new page with a build in it will have a page header,
    // build, and minimum space for a tag. This will perform horribly and waste
    // tons of memory if the page size is small, so you're best off just
    // sticking with the defaults.
    //
    // These are all known at compile time, so if they are large
    // enough this function should trivially optimize to a no-op.

    #if MPACK_BUILDER_INTERNAL_STORAGE
    // make sure the internal storage is big enough to be useful
    MPACK_STATIC_ASSERT(MPACK_BUILDER_INTERNAL_STORAGE_SIZE >= (sizeof(mpack_builder_page_t) +
            sizeof(mpack_build_t) + MPACK_WRITER_MINIMUM_BUFFER_SIZE),
            "MPACK_BUILDER_INTERNAL_STORAGE_SIZE is too small to be useful!");
    if (MPACK_BUILDER_INTERNAL_STORAGE_SIZE < (sizeof(mpack_builder_page_t) +
            sizeof(mpack_build_t) + MPACK_WRITER_MINIMUM_BUFFER_SIZE))
    {
        mpack_break("MPACK_BUILDER_INTERNAL_STORAGE_SIZE is too small to be useful!");
        mpack_writer_flag_error(writer, mpack_error_bug);
    }
    #endif

    // make sure the builder page size is big enough to be useful
    MPACK_STATIC_ASSERT(MPACK_BUILDER_PAGE_SIZE >= (sizeof(mpack_builder_page_t) +
            sizeof(mpack_build_t) + MPACK_WRITER_MINIMUM_BUFFER_SIZE),
            "MPACK_BUILDER_PAGE_SIZE is too small to be useful!");
    if (MPACK_BUILDER_PAGE_SIZE < (sizeof(mpack_builder_page_t) +
            sizeof(mpack_build_t) + MPACK_WRITER_MINIMUM_BUFFER_SIZE))
    {
        mpack_break("MPACK_BUILDER_PAGE_SIZE is too small to be useful!");
        mpack_writer_flag_error(writer, mpack_error_bug);
    }
}

static inline size_t mpack_builder_page_size(mpack_writer_t* writer, mpack_builder_page_t* page) {
    #if MPACK_BUILDER_INTERNAL_STORAGE
    if ((char*)page == writer->builder.internal)
        return sizeof(writer->builder.internal);
    #else
    (void)writer;
    (void)page;
    #endif
    return MPACK_BUILDER_PAGE_SIZE;
}

static inline size_t mpack_builder_align_build(size_t bytes_used) {
    size_t offset = bytes_used;
    offset += MPACK_BUILD_ALIGNMENT - 1;
    offset -= offset % MPACK_BUILD_ALIGNMENT;
    mpack_log("aligned %zi to %zi\n", bytes_used, offset);
    return offset;
}

static inline void mpack_builder_free_page(mpack_writer_t* writer, mpack_builder_page_t* page) {
    mpack_log("freeing page %p\n", (void*)page);
    #if MPACK_BUILDER_INTERNAL_STORAGE
    if ((char*)page == writer->builder.internal)
        return;
    #else
    (void)writer;
    #endif
    MPACK_FREE(page);
}

static inline size_t mpack_builder_page_remaining(mpack_writer_t* writer, mpack_builder_page_t* page) {
    return mpack_builder_page_size(writer, page) - page->bytes_used;
}

static void mpack_builder_configure_buffer(mpack_writer_t* writer) {
    if (mpack_writer_error(writer) != mpack_ok)
        return;
    mpack_builder_t* builder = &writer->builder;

    mpack_builder_page_t* page = builder->current_page;
    mpack_assert(page != NULL, "page is null??");

    // This diverts the writer into the remainder of the current page of our
    // build buffer.
    writer->buffer = (char*)page + page->bytes_used;
    writer->position = (char*)page + page->bytes_used;
    writer->end = (char*)page + mpack_builder_page_size(writer, page);
    mpack_log("configuring buffer from %p to %p\n", (void*)writer->position, (void*)writer->end);
}

static void mpack_builder_add_page(mpack_writer_t* writer) {
    mpack_builder_t* builder = &writer->builder;
    mpack_assert(writer->error == mpack_ok);

    mpack_log("adding a page.\n");
    mpack_builder_page_t* page = (mpack_builder_page_t*)MPACK_MALLOC(MPACK_BUILDER_PAGE_SIZE);
    if (page == NULL) {
        mpack_writer_flag_error(writer, mpack_error_memory);
        return;
    }

    page->next = NULL;
    page->bytes_used = sizeof(mpack_builder_page_t);
    builder->current_page->next = page;
    builder->current_page = page;
}

// Checks how many bytes the writer wrote to the page, adding it to the page's
// bytes_used. This must be followed up with mpack_builder_configure_buffer()
// (after adding a new page, build, etc) to reset the writer's buffer pointers.
static void mpack_builder_apply_writes(mpack_writer_t* writer) {
    mpack_assert(writer->error == mpack_ok);
    mpack_builder_t* builder = &writer->builder;
    mpack_log("latest build is %p\n", (void*)builder->latest_build);

    // The difference between buffer and current is the number of bytes that
    // were written to the page.
    size_t bytes_written = (size_t)(writer->position - writer->buffer);
    mpack_log("applying write of %zi bytes to build %p\n", bytes_written, (void*)builder->latest_build);

    mpack_assert(builder->current_page != NULL);
    mpack_assert(builder->latest_build != NULL);
    builder->current_page->bytes_used += bytes_written;
    builder->latest_build->bytes += bytes_written;
    mpack_log("latest build %p now has %zi bytes\n", (void*)builder->latest_build, builder->latest_build->bytes);
}

static void mpack_builder_flush(mpack_writer_t* writer) {
    mpack_assert(writer->error == mpack_ok);
    mpack_builder_apply_writes(writer);
    mpack_builder_add_page(writer);
    mpack_builder_configure_buffer(writer);
}

MPACK_NOINLINE static void mpack_builder_begin(mpack_writer_t* writer) {
    mpack_builder_t* builder = &writer->builder;
    mpack_assert(writer->error == mpack_ok);
    mpack_assert(builder->current_build == NULL);
    mpack_assert(builder->latest_build == NULL);
    mpack_assert(builder->pages == NULL);

    // If this is the first build, we need to stash the real buffer backing our
    // writer. We'll be diverting the writer to our build buffer.
    builder->stash_buffer = writer->buffer;
    builder->stash_position = writer->position;
    builder->stash_end = writer->end;

    mpack_builder_page_t* page;

    // we've checked that both these sizes are large enough above.
    #if MPACK_BUILDER_INTERNAL_STORAGE
    page = (mpack_builder_page_t*)builder->internal;
    mpack_log("beginning builder with internal storage %p\n", (void*)page);
    #else
    page = (mpack_builder_page_t*)MPACK_MALLOC(MPACK_BUILDER_PAGE_SIZE);
    if (page == NULL) {
        mpack_writer_flag_error(writer, mpack_error_memory);
        return;
    }
    mpack_log("beginning builder with allocated page %p\n", (void*)page);
    #endif

    page->next = NULL;
    page->bytes_used = sizeof(mpack_builder_page_t);
    builder->pages = page;
    builder->current_page = page;
}

static void mpack_builder_build(mpack_writer_t* writer, mpack_type_t type) {
    mpack_builder_check_sizes(writer);
    if (mpack_writer_error(writer) != mpack_ok)
        return;

    mpack_writer_track_element(writer);
    mpack_writer_track_push_builder(writer, type);

    mpack_builder_t* builder = &writer->builder;

    if (builder->current_build == NULL) {
        mpack_builder_begin(writer);
    } else {
        mpack_builder_apply_writes(writer);
    }
    if (mpack_writer_error(writer) != mpack_ok)
        return;

    // find aligned space for a new build. if there isn't enough space in the
    // current page, we discard the remaining space in it and allocate a new
    // page.
    size_t offset = mpack_builder_align_build(builder->current_page->bytes_used);
    if (offset + sizeof(mpack_build_t) > mpack_builder_page_size(writer, builder->current_page)) {
        mpack_log("not enough space for a build. %zi bytes used of %zi in this page\n",
                builder->current_page->bytes_used, mpack_builder_page_size(writer, builder->current_page));
        mpack_builder_add_page(writer);
        // there is always enough space in a fresh page.
        offset = mpack_builder_align_build(builder->current_page->bytes_used);
    }

    // allocate the build within the page. note that we don't keep track of the
    // space wasted due to the offset. instead the previous build has stored
    // how many bytes follow it, and we'll redo this offset calculation to find
    // this build after it.
    mpack_builder_page_t* page = builder->current_page;
    page->bytes_used = offset + sizeof(mpack_build_t);
    mpack_assert(page->bytes_used <= mpack_builder_page_size(writer, page));
    mpack_build_t* build = (mpack_build_t*)((char*)page + offset);
    mpack_log("created new build %p within page %p, which now has %zi bytes used\n",
            (void*)build, (void*)page, page->bytes_used);

    // configure the new build
    build->parent = builder->current_build;
    build->bytes = 0;
    build->count = 0;
    build->type = type;
    build->key_needs_value = false;
    build->nested_compound_elements = 0;

    mpack_log("setting current and latest build to new build %p\n", (void*)build);
    builder->current_build = build;
    builder->latest_build = build;

    // we always need to provide a buffer that meets the minimum buffer size.
    // if there isn't enough space, we discard the remaining space in the
    // current page and allocate a new one.
    if (mpack_builder_page_remaining(writer, page) < MPACK_WRITER_MINIMUM_BUFFER_SIZE) {
        mpack_log("less than minimum buffer size in current page. %zi bytes used of %zi in this page\n",
                builder->current_page->bytes_used, mpack_builder_page_size(writer, builder->current_page));
        mpack_builder_add_page(writer);
        if (mpack_writer_error(writer) != mpack_ok)
            return;
    }
    mpack_assert(mpack_builder_page_remaining(writer, builder->current_page) >= MPACK_WRITER_MINIMUM_BUFFER_SIZE);
    mpack_builder_configure_buffer(writer);
}

MPACK_NOINLINE
static void mpack_builder_resolve(mpack_writer_t* writer) {
    mpack_builder_t* builder = &writer->builder;

    // The starting page is the internal storage (if we have it), otherwise
    // it's the first page in the array
    mpack_builder_page_t* page =
        #if MPACK_BUILDER_INTERNAL_STORAGE
        (mpack_builder_page_t*)builder->internal
        #else
        builder->pages
        #endif
        ;

    // We start by restoring the writer's original buffer so we can write the
    // data for real.
    writer->buffer = builder->stash_buffer;
    writer->position = builder->stash_position;
    writer->end = builder->stash_end;

    // We can also close out the build now.
    builder->current_build = NULL;
    builder->latest_build = NULL;
    builder->current_page = NULL;
    builder->pages = NULL;

    // the starting page always starts with the first build
    size_t offset = mpack_builder_align_build(sizeof(mpack_builder_page_t));
    mpack_build_t* build = (mpack_build_t*)((char*)page + offset);
    mpack_log("starting resolve with build %p in page %p\n", (void*)build, (void*)page);

    // encoded data immediately follows the build
    offset += sizeof(mpack_build_t);

    // Walk the list of builds, writing everything out in the buffer. Note that
    // we don't check for errors anywhere. The lower-level write functions will
    // all check for errors. We need to walk all pages anyway to free them, so
    // there's not much point in optimizing an error path at the expense of the
    // normal path.
    while (true) {

        // write out the container tag
        mpack_log("writing out an %s with count %u followed by %zi bytes\n",
                mpack_type_to_string(build->type), build->count, build->bytes);
        switch (build->type) {
            case mpack_type_map:
                mpack_write_map_notrack(writer, build->count);
                break;
            case mpack_type_array:
                mpack_write_array_notrack(writer, build->count);
                break;
            default:
                mpack_break("invalid type in builder?");
                mpack_writer_flag_error(writer, mpack_error_bug);
                return;
        }

        // figure out how many bytes follow this container. we're going to be
        // freeing pages as we write, so we need to be done with this build.
        size_t left = build->bytes;
        build = NULL;

        // write out all bytes following this container
        while (left > 0) {
            size_t bytes_used = page->bytes_used;
            if (offset < bytes_used) {
                size_t step = bytes_used - offset;
                if (step > left)
                    step = left;
                mpack_log("writing out %zi bytes starting at %p in page %p\n",
                        step, (void*)((char*)page + offset), (void*)page);
                mpack_write_native(writer, (char*)page + offset, step);
                offset += step;
                left -= step;
            }

            if (left == 0) {
                mpack_log("done writing bytes for this build\n");
                break;
            }

            // still need to write more bytes. free this page and jump to the
            // next one.
            mpack_builder_page_t* next_page = page->next;
            mpack_builder_free_page(writer, page);
            page = next_page;
            // bytes on the next page immediately follow the header.
            offset = sizeof(mpack_builder_page_t);
        }

        // now see if we can find another build.
        offset = mpack_builder_align_build(offset);
        if (offset + sizeof(mpack_build_t) >= mpack_builder_page_size(writer, page)) {
            mpack_log("not enough room in this page for another build\n");
            mpack_builder_page_t* next_page = page->next;
            mpack_builder_free_page(writer, page);
            page = next_page;
            if (page == NULL) {
                mpack_log("no more pages\n");
                // there are no more pages. we're done.
                break;
            }
            offset = mpack_builder_align_build(sizeof(mpack_builder_page_t));
        }
        if (offset + sizeof(mpack_build_t) > page->bytes_used) {
            // there is no more data. we're done.
            mpack_log("no more data\n");
            mpack_builder_free_page(writer, page);
            break;
        }

        // we've found another build. loop around!
        build = (mpack_build_t*)((char*)page + offset);
        offset += sizeof(mpack_build_t);
        mpack_log("found build %p\n", (void*)build);
    }

    mpack_log("done resolve.\n");
}

static void mpack_builder_complete(mpack_writer_t* writer, mpack_type_t type) {
    if (mpack_writer_error(writer) != mpack_ok)
        return;

    mpack_writer_track_pop_builder(writer, type);
    mpack_builder_t* builder = &writer->builder;
    mpack_assert(builder->current_build != NULL, "no build in progress!");
    mpack_assert(builder->latest_build != NULL, "missing latest build!");
    mpack_assert(builder->current_build->type == type, "completing wrong type!");
    mpack_log("completing build %p\n", (void*)builder->current_build);

    if (builder->current_build->key_needs_value) {
        mpack_break("an odd number of elements were written in a map!");
        mpack_writer_flag_error(writer, mpack_error_bug);
        return;
    }

    if (builder->current_build->nested_compound_elements != 0) {
        mpack_break("there is a nested unfinished non-build map or array in this build.");
        mpack_writer_flag_error(writer, mpack_error_bug);
        return;
    }

    // We need to apply whatever writes have been made to the current build
    // before popping it.
    mpack_builder_apply_writes(writer);

    // For a nested build, we just switch the current build back to its parent.
    if (builder->current_build->parent != NULL) {
        mpack_log("setting current build to parent build %p. latest is still %p.\n",
                (void*)builder->current_build->parent, (void*)builder->latest_build);
        builder->current_build = builder->current_build->parent;
        mpack_builder_configure_buffer(writer);
    } else {
        // We're completing the final build.
        mpack_builder_resolve(writer);
    }
}

void mpack_build_map(mpack_writer_t* writer) {
    mpack_builder_build(writer, mpack_type_map);
}

void mpack_build_array(mpack_writer_t* writer) {
    mpack_builder_build(writer, mpack_type_array);
}

void mpack_complete_map(mpack_writer_t* writer) {
    mpack_builder_complete(writer, mpack_type_map);
}

void mpack_complete_array(mpack_writer_t* writer) {
    mpack_builder_complete(writer, mpack_type_array);
}

#endif // MPACK_BUILDER
#endif // MPACK_WRITER

MPACK_SILENCE_WARNINGS_END

/* mpack/mpack-reader.c.c */

#define MPACK_INTERNAL 1

/* #include "mpack-reader.h" */

MPACK_SILENCE_WARNINGS_BEGIN

#if MPACK_READER

static void mpack_reader_skip_using_fill(mpack_reader_t* reader, size_t count);

void mpack_reader_init(mpack_reader_t* reader, char* buffer, size_t size, size_t count) {
    mpack_assert(buffer != NULL, "buffer is NULL");

    mpack_memset(reader, 0, sizeof(*reader));
    reader->buffer = buffer;
    reader->size = size;
    reader->data = buffer;
    reader->end = buffer + count;

    #if MPACK_READ_TRACKING
    mpack_reader_flag_if_error(reader, mpack_track_init(&reader->track));
    #endif

    mpack_log("===========================\n");
    mpack_log("initializing reader with buffer size %i\n", (int)size);
}

void mpack_reader_init_error(mpack_reader_t* reader, mpack_error_t error) {
    mpack_memset(reader, 0, sizeof(*reader));
    reader->error = error;

    mpack_log("===========================\n");
    mpack_log("initializing reader error state %i\n", (int)error);
}

void mpack_reader_init_data(mpack_reader_t* reader, const char* data, size_t count) {
    mpack_assert(data != NULL, "data is NULL");

    mpack_memset(reader, 0, sizeof(*reader));
    reader->data = data;
    reader->end = data + count;

    #if MPACK_READ_TRACKING
    mpack_reader_flag_if_error(reader, mpack_track_init(&reader->track));
    #endif

    mpack_log("===========================\n");
    mpack_log("initializing reader with data size %i\n", (int)count);
}

void mpack_reader_set_fill(mpack_reader_t* reader, mpack_reader_fill_t fill) {
    MPACK_STATIC_ASSERT(MPACK_READER_MINIMUM_BUFFER_SIZE >= MPACK_MAXIMUM_TAG_SIZE,
            "minimum buffer size must fit any tag!");

    if (reader->size == 0) {
        mpack_break("cannot use fill function without a writeable buffer!");
        mpack_reader_flag_error(reader, mpack_error_bug);
        return;
    }

    if (reader->size < MPACK_READER_MINIMUM_BUFFER_SIZE) {
        mpack_break("buffer size is %i, but minimum buffer size for fill is %i",
                (int)reader->size, MPACK_READER_MINIMUM_BUFFER_SIZE);
        mpack_reader_flag_error(reader, mpack_error_bug);
        return;
    }

    reader->fill = fill;
}

void mpack_reader_set_skip(mpack_reader_t* reader, mpack_reader_skip_t skip) {
    mpack_assert(reader->size != 0, "cannot use skip function without a writeable buffer!");
    reader->skip = skip;
}

#if MPACK_STDIO
static size_t mpack_file_reader_fill(mpack_reader_t* reader, char* buffer, size_t count) {
    if (feof((FILE *)reader->context)) {
       mpack_reader_flag_error(reader, mpack_error_eof);
       return 0;
    }
    return fread((void*)buffer, 1, count, (FILE*)reader->context);
}

static void mpack_file_reader_skip(mpack_reader_t* reader, size_t count) {
    if (mpack_reader_error(reader) != mpack_ok)
        return;
    FILE* file = (FILE*)reader->context;

    // We call ftell() to test whether the stream is seekable
    // without causing a file error.
    if (ftell(file) >= 0) {
        mpack_log("seeking forward %i bytes\n", (int)count);
        if (fseek(file, (long int)count, SEEK_CUR) == 0)
            return;
        mpack_log("fseek() didn't return zero!\n");
        if (ferror(file)) {
            mpack_reader_flag_error(reader, mpack_error_io);
            return;
        }
    }

    // If the stream is not seekable, fall back to the fill function.
    mpack_reader_skip_using_fill(reader, count);
}

static void mpack_file_reader_teardown(mpack_reader_t* reader) {
    MPACK_FREE(reader->buffer);
    reader->buffer = NULL;
    reader->context = NULL;
    reader->size = 0;
    reader->fill = NULL;
    reader->skip = NULL;
    reader->teardown = NULL;
}

static void mpack_file_reader_teardown_close(mpack_reader_t* reader) {
    FILE* file = (FILE*)reader->context;

    if (file) {
        int ret = fclose(file);
        if (ret != 0)
            mpack_reader_flag_error(reader, mpack_error_io);
    }

    mpack_file_reader_teardown(reader);
}

void mpack_reader_init_stdfile(mpack_reader_t* reader, FILE* file, bool close_when_done) {
    mpack_assert(file != NULL, "file is NULL");

    size_t capacity = MPACK_BUFFER_SIZE;
    char* buffer = (char*)MPACK_MALLOC(capacity);
    if (buffer == NULL) {
        mpack_reader_init_error(reader, mpack_error_memory);
        if (close_when_done) {
            fclose(file);
        }
        return;
    }

    mpack_reader_init(reader, buffer, capacity, 0);
    mpack_reader_set_context(reader, file);
    mpack_reader_set_fill(reader, mpack_file_reader_fill);
    mpack_reader_set_skip(reader, mpack_file_reader_skip);
    mpack_reader_set_teardown(reader, close_when_done ?
            mpack_file_reader_teardown_close :
            mpack_file_reader_teardown);
}

void mpack_reader_init_filename(mpack_reader_t* reader, const char* filename) {
    mpack_assert(filename != NULL, "filename is NULL");

    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        mpack_reader_init_error(reader, mpack_error_io);
        return;
    }

    mpack_reader_init_stdfile(reader, file, true);
}
#endif

mpack_error_t mpack_reader_destroy(mpack_reader_t* reader) {

    // clean up tracking, asserting if we're not already in an error state
    #if MPACK_READ_TRACKING
    mpack_reader_flag_if_error(reader, mpack_track_destroy(&reader->track, mpack_reader_error(reader) != mpack_ok));
    #endif

    if (reader->teardown)
        reader->teardown(reader);
    reader->teardown = NULL;

    return reader->error;
}

size_t mpack_reader_remaining(mpack_reader_t* reader, const char** data) {
    if (mpack_reader_error(reader) != mpack_ok)
        return 0;

    #if MPACK_READ_TRACKING
    if (mpack_reader_flag_if_error(reader, mpack_track_check_empty(&reader->track)) != mpack_ok)
        return 0;
    #endif

    if (data)
        *data = reader->data;
    return (size_t)(reader->end - reader->data);
}

void mpack_reader_flag_error(mpack_reader_t* reader, mpack_error_t error) {
    mpack_log("reader %p setting error %i: %s\n", (void*)reader, (int)error, mpack_error_to_string(error));

    if (reader->error == mpack_ok) {
        reader->error = error;
        reader->end = reader->data;
        if (reader->error_fn)
            reader->error_fn(reader, error);
    }
}

// Loops on the fill function, reading between the minimum and
// maximum number of bytes and flagging an error if it fails.
MPACK_NOINLINE static size_t mpack_fill_range(mpack_reader_t* reader, char* p, size_t min_bytes, size_t max_bytes) {
    mpack_assert(reader->fill != NULL, "mpack_fill_range() called with no fill function?");
    mpack_assert(min_bytes > 0, "cannot fill zero bytes!");
    mpack_assert(max_bytes >= min_bytes, "min_bytes %i cannot be larger than max_bytes %i!",
            (int)min_bytes, (int)max_bytes);

    size_t count = 0;
    while (count < min_bytes) {
        size_t read = reader->fill(reader, p + count, max_bytes - count);

        // Reader fill functions can flag an error or return 0 on failure. We
        // also guard against functions that return -1 just in case.
        if (mpack_reader_error(reader) != mpack_ok)
            return 0;
        if (read == 0 || read == ((size_t)(-1))) {
            mpack_reader_flag_error(reader, mpack_error_io);
            return 0;
        }

        count += read;
    }
    return count;
}

MPACK_NOINLINE bool mpack_reader_ensure_straddle(mpack_reader_t* reader, size_t count) {
    mpack_assert(count != 0, "cannot ensure zero bytes!");
    mpack_assert(reader->error == mpack_ok, "reader cannot be in an error state!");

    mpack_assert(count > (size_t)(reader->end - reader->data),
            "straddling ensure requested for %i bytes, but there are %i bytes "
            "left in buffer. call mpack_reader_ensure() instead",
            (int)count, (int)(reader->end - reader->data));

    // we'll need a fill function to get more data. if there's no
    // fill function, the buffer should contain an entire MessagePack
    // object, so we raise mpack_error_invalid instead of mpack_error_io
    // on truncated data.
    if (reader->fill == NULL) {
        mpack_reader_flag_error(reader, mpack_error_invalid);
        return false;
    }

    // we need enough space in the buffer. if the buffer is not
    // big enough, we return mpack_error_too_big (since this is
    // for an in-place read larger than the buffer size.)
    if (count > reader->size) {
        mpack_reader_flag_error(reader, mpack_error_too_big);
        return false;
    }

    // move the existing data to the start of the buffer
    size_t left = (size_t)(reader->end - reader->data);
    mpack_memmove(reader->buffer, reader->data, left);
    reader->end -= reader->data - reader->buffer;
    reader->data = reader->buffer;

    // read at least the necessary number of bytes, accepting up to the
    // buffer size
    size_t read = mpack_fill_range(reader, reader->buffer + left,
            count - left, reader->size - left);
    if (mpack_reader_error(reader) != mpack_ok)
        return false;
    reader->end += read;
    return true;
}

// Reads count bytes into p. Used when there are not enough bytes
// left in the buffer to satisfy a read.
MPACK_NOINLINE void mpack_read_native_straddle(mpack_reader_t* reader, char* p, size_t count) {
    mpack_assert(count == 0 || p != NULL, "data pointer for %i bytes is NULL", (int)count);

    if (mpack_reader_error(reader) != mpack_ok) {
        mpack_memset(p, 0, count);
        return;
    }

    size_t left = (size_t)(reader->end - reader->data);
    mpack_log("big read for %i bytes into %p, %i left in buffer, buffer size %i\n",
            (int)count, p, (int)left, (int)reader->size);

    if (count <= left) {
        mpack_assert(0,
                "big read requested for %i bytes, but there are %i bytes "
                "left in buffer. call mpack_read_native() instead",
                (int)count, (int)left);
        mpack_reader_flag_error(reader, mpack_error_bug);
        mpack_memset(p, 0, count);
        return;
    }

    // we'll need a fill function to get more data. if there's no
    // fill function, the buffer should contain an entire MessagePack
    // object, so we raise mpack_error_invalid instead of mpack_error_io
    // on truncated data.
    if (reader->fill == NULL) {
        mpack_reader_flag_error(reader, mpack_error_invalid);
        mpack_memset(p, 0, count);
        return;
    }

    if (reader->size == 0) {
        // somewhat debatable what error should be returned here. when
        // initializing a reader with an in-memory buffer it's not
        // necessarily a bug if the data is blank; it might just have
        // been truncated to zero. for this reason we return the same
        // error as if the data was truncated.
        mpack_reader_flag_error(reader, mpack_error_io);
        mpack_memset(p, 0, count);
        return;
    }

    // flush what's left of the buffer
    if (left > 0) {
        mpack_log("flushing %i bytes remaining in buffer\n", (int)left);
        mpack_memcpy(p, reader->data, left);
        count -= left;
        p += left;
        reader->data += left;
    }

    // if the remaining data needed is some small fraction of the
    // buffer size, we'll try to fill the buffer as much as possible
    // and copy the needed data out.
    if (count <= reader->size / MPACK_READER_SMALL_FRACTION_DENOMINATOR) {
        size_t read = mpack_fill_range(reader, reader->buffer, count, reader->size);
        if (mpack_reader_error(reader) != mpack_ok)
            return;
        mpack_memcpy(p, reader->buffer, count);
        reader->data = reader->buffer + count;
        reader->end = reader->buffer + read;

    // otherwise we read the remaining data directly into the target.
    } else {
        mpack_log("reading %i additional bytes\n", (int)count);
        mpack_fill_range(reader, p, count, count);
    }
}

MPACK_NOINLINE static void mpack_skip_bytes_straddle(mpack_reader_t* reader, size_t count) {

    // we'll need at least a fill function to skip more data. if there's
    // no fill function, the buffer should contain an entire MessagePack
    // object, so we raise mpack_error_invalid instead of mpack_error_io
    // on truncated data. (see mpack_read_native_straddle())
    if (reader->fill == NULL) {
        mpack_log("reader has no fill function!\n");
        mpack_reader_flag_error(reader, mpack_error_invalid);
        return;
    }

    // discard whatever's left in the buffer
    size_t left = (size_t)(reader->end - reader->data);
    mpack_log("discarding %i bytes still in buffer\n", (int)left);
    count -= left;
    reader->data = reader->end;

    // use the skip function if we've got one, and if we're trying
    // to skip a lot of data. if we only need to skip some tiny
    // fraction of the buffer size, it's probably better to just
    // fill the buffer and skip from it instead of trying to seek.
    if (reader->skip && count > reader->size / 16) {
        mpack_log("calling skip function for %i bytes\n", (int)count);
        reader->skip(reader, count);
        return;
    }

    mpack_reader_skip_using_fill(reader, count);
}

void mpack_skip_bytes(mpack_reader_t* reader, size_t count) {
    if (mpack_reader_error(reader) != mpack_ok)
        return;
    mpack_log("skip requested for %i bytes\n", (int)count);

    mpack_reader_track_bytes(reader, count);

    // check if we have enough in the buffer already
    size_t left = (size_t)(reader->end - reader->data);
    if (left >= count) {
        mpack_log("skipping %u bytes still in buffer\n", (uint32_t)count);
        reader->data += count;
        return;
    }

    mpack_skip_bytes_straddle(reader, count);
}

MPACK_NOINLINE static void mpack_reader_skip_using_fill(mpack_reader_t* reader, size_t count) {
    mpack_assert(reader->fill != NULL, "missing fill function!");
    mpack_assert(reader->data == reader->end, "there are bytes left in the buffer!");
    mpack_assert(reader->error == mpack_ok, "should not have called this in an error state (%i)", reader->error);
    mpack_log("skip using fill for %i bytes\n", (int)count);

    // fill and discard multiples of the buffer size
    while (count > reader->size) {
        mpack_log("filling and discarding buffer of %i bytes\n", (int)reader->size);
        if (mpack_fill_range(reader, reader->buffer, reader->size, reader->size) < reader->size) {
            mpack_reader_flag_error(reader, mpack_error_io);
            return;
        }
        count -= reader->size;
    }

    // fill the buffer as much as possible
    reader->data = reader->buffer;
    size_t read = mpack_fill_range(reader, reader->buffer, count, reader->size);
    if (read < count) {
        mpack_reader_flag_error(reader, mpack_error_io);
        return;
    }
    reader->end = reader->data + read;
    mpack_log("filled %i bytes into buffer; discarding %i bytes\n", (int)read, (int)count);
    reader->data += count;
}

void mpack_read_bytes(mpack_reader_t* reader, char* p, size_t count) {
    mpack_assert(p != NULL, "destination for read of %i bytes is NULL", (int)count);
    mpack_reader_track_bytes(reader, count);
    mpack_read_native(reader, p, count);
}

void mpack_read_utf8(mpack_reader_t* reader, char* p, size_t byte_count) {
    mpack_assert(p != NULL, "destination for read of %i bytes is NULL", (int)byte_count);
    mpack_reader_track_str_bytes_all(reader, byte_count);
    mpack_read_native(reader, p, byte_count);

    if (mpack_reader_error(reader) == mpack_ok && !mpack_utf8_check(p, byte_count))
        mpack_reader_flag_error(reader, mpack_error_type);
}

static void mpack_read_cstr_unchecked(mpack_reader_t* reader, char* buf, size_t buffer_size, size_t byte_count) {
    mpack_assert(buf != NULL, "destination for read of %i bytes is NULL", (int)byte_count);
    mpack_assert(buffer_size >= 1, "buffer size is zero; you must have room for at least a null-terminator");

    if (mpack_reader_error(reader)) {
        buf[0] = 0;
        return;
    }

    if (byte_count > buffer_size - 1) {
        mpack_reader_flag_error(reader, mpack_error_too_big);
        buf[0] = 0;
        return;
    }

    mpack_reader_track_str_bytes_all(reader, byte_count);
    mpack_read_native(reader, buf, byte_count);
    buf[byte_count] = 0;
}

void mpack_read_cstr(mpack_reader_t* reader, char* buf, size_t buffer_size, size_t byte_count) {
    mpack_read_cstr_unchecked(reader, buf, buffer_size, byte_count);

    // check for null bytes
    if (mpack_reader_error(reader) == mpack_ok && !mpack_str_check_no_null(buf, byte_count)) {
        buf[0] = 0;
        mpack_reader_flag_error(reader, mpack_error_type);
    }
}

void mpack_read_utf8_cstr(mpack_reader_t* reader, char* buf, size_t buffer_size, size_t byte_count) {
    mpack_read_cstr_unchecked(reader, buf, buffer_size, byte_count);

    // check encoding
    if (mpack_reader_error(reader) == mpack_ok && !mpack_utf8_check_no_null(buf, byte_count)) {
        buf[0] = 0;
        mpack_reader_flag_error(reader, mpack_error_type);
    }
}

#ifdef MPACK_MALLOC
// Reads native bytes with error callback disabled. This allows MPack reader functions
// to hold an allocated buffer and read native data into it without leaking it in
// case of a non-local jump (longjmp, throw) out of an error handler.
static void mpack_read_native_noerrorfn(mpack_reader_t* reader, char* p, size_t count) {
    mpack_assert(reader->error == mpack_ok, "cannot call if an error is already flagged!");
    mpack_reader_error_t error_fn = reader->error_fn;
    reader->error_fn = NULL;
    mpack_read_native(reader, p, count);
    reader->error_fn = error_fn;
}

char* mpack_read_bytes_alloc_impl(mpack_reader_t* reader, size_t count, bool null_terminated) {

    // track the bytes first in case it jumps
    mpack_reader_track_bytes(reader, count);
    if (mpack_reader_error(reader) != mpack_ok)
        return NULL;

    // cannot allocate zero bytes. this is not an error.
    if (count == 0 && null_terminated == false)
        return NULL;

    // allocate data
    char* data = (char*)MPACK_MALLOC(count + (null_terminated ? 1 : 0)); // TODO: can this overflow?
    if (data == NULL) {
        mpack_reader_flag_error(reader, mpack_error_memory);
        return NULL;
    }

    // read with error callback disabled so we don't leak our buffer
    mpack_read_native_noerrorfn(reader, data, count);

    // report flagged errors
    if (mpack_reader_error(reader) != mpack_ok) {
        MPACK_FREE(data);
        if (reader->error_fn)
            reader->error_fn(reader, mpack_reader_error(reader));
        return NULL;
    }

    if (null_terminated)
        data[count] = '\0';
    return data;
}
#endif

// read inplace without tracking (since there are different
// tracking modes for different inplace readers)
static const char* mpack_read_bytes_inplace_notrack(mpack_reader_t* reader, size_t count) {
    if (mpack_reader_error(reader) != mpack_ok)
        return NULL;

    // if we have enough bytes already in the buffer, we can return it directly.
    if ((size_t)(reader->end - reader->data) >= count) {
        const char* bytes = reader->data;
        reader->data += count;
        return bytes;
    }

    if (!mpack_reader_ensure(reader, count))
        return NULL;

    const char* bytes = reader->data;
    reader->data += count;
    return bytes;
}

const char* mpack_read_bytes_inplace(mpack_reader_t* reader, size_t count) {
    mpack_reader_track_bytes(reader, count);
    return mpack_read_bytes_inplace_notrack(reader, count);
}

const char* mpack_read_utf8_inplace(mpack_reader_t* reader, size_t count) {
    mpack_reader_track_str_bytes_all(reader, count);
    const char* str = mpack_read_bytes_inplace_notrack(reader, count);

    if (mpack_reader_error(reader) == mpack_ok && !mpack_utf8_check(str, count)) {
        mpack_reader_flag_error(reader, mpack_error_type);
        return NULL;
    }

    return str;
}

static size_t mpack_parse_tag(mpack_reader_t* reader, mpack_tag_t* tag) {
    mpack_assert(reader->error == mpack_ok, "reader cannot be in an error state!");

    if (!mpack_reader_ensure(reader, 1))
        return 0;
    uint8_t type = mpack_load_u8(reader->data);

    // unfortunately, by far the fastest way to parse a tag is to switch
    // on the first byte, and to explicitly list every possible byte. so for
    // infix types, the list of cases is quite large.
    //
    // in size-optimized builds, we switch on the top four bits first to
    // handle most infix types with a smaller jump table to save space.

    #if MPACK_OPTIMIZE_FOR_SIZE
    switch (type >> 4) {

        // positive fixnum
        case 0x0: case 0x1: case 0x2: case 0x3:
        case 0x4: case 0x5: case 0x6: case 0x7:
            *tag = mpack_tag_make_uint(type);
            return 1;

        // negative fixnum
        case 0xe: case 0xf:
            *tag = mpack_tag_make_int((int8_t)type);
            return 1;

        // fixmap
        case 0x8:
            *tag = mpack_tag_make_map(type & ~0xf0u);
            return 1;

        // fixarray
        case 0x9:
            *tag = mpack_tag_make_array(type & ~0xf0u);
            return 1;

        // fixstr
        case 0xa: case 0xb:
            *tag = mpack_tag_make_str(type & ~0xe0u);
            return 1;

        // not one of the common infix types
        default:
            break;

    }
    #endif

    // handle individual type tags
    switch (type) {

        #if !MPACK_OPTIMIZE_FOR_SIZE
        // positive fixnum
        case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05: case 0x06: case 0x07:
        case 0x08: case 0x09: case 0x0a: case 0x0b: case 0x0c: case 0x0d: case 0x0e: case 0x0f:
        case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15: case 0x16: case 0x17:
        case 0x18: case 0x19: case 0x1a: case 0x1b: case 0x1c: case 0x1d: case 0x1e: case 0x1f:
        case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25: case 0x26: case 0x27:
        case 0x28: case 0x29: case 0x2a: case 0x2b: case 0x2c: case 0x2d: case 0x2e: case 0x2f:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37:
        case 0x38: case 0x39: case 0x3a: case 0x3b: case 0x3c: case 0x3d: case 0x3e: case 0x3f:
        case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4a: case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f:
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f:
        case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: case 0x67:
        case 0x68: case 0x69: case 0x6a: case 0x6b: case 0x6c: case 0x6d: case 0x6e: case 0x6f:
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7a: case 0x7b: case 0x7c: case 0x7d: case 0x7e: case 0x7f:
            *tag = mpack_tag_make_uint(type);
            return 1;

        // negative fixnum
        case 0xe0: case 0xe1: case 0xe2: case 0xe3: case 0xe4: case 0xe5: case 0xe6: case 0xe7:
        case 0xe8: case 0xe9: case 0xea: case 0xeb: case 0xec: case 0xed: case 0xee: case 0xef:
        case 0xf0: case 0xf1: case 0xf2: case 0xf3: case 0xf4: case 0xf5: case 0xf6: case 0xf7:
        case 0xf8: case 0xf9: case 0xfa: case 0xfb: case 0xfc: case 0xfd: case 0xfe: case 0xff:
            *tag = mpack_tag_make_int((int8_t)type);
            return 1;

        // fixmap
        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8a: case 0x8b: case 0x8c: case 0x8d: case 0x8e: case 0x8f:
            *tag = mpack_tag_make_map(type & ~0xf0u);
            return 1;

        // fixarray
        case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9a: case 0x9b: case 0x9c: case 0x9d: case 0x9e: case 0x9f:
            *tag = mpack_tag_make_array(type & ~0xf0u);
            return 1;

        // fixstr
        case 0xa0: case 0xa1: case 0xa2: case 0xa3: case 0xa4: case 0xa5: case 0xa6: case 0xa7:
        case 0xa8: case 0xa9: case 0xaa: case 0xab: case 0xac: case 0xad: case 0xae: case 0xaf:
        case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4: case 0xb5: case 0xb6: case 0xb7:
        case 0xb8: case 0xb9: case 0xba: case 0xbb: case 0xbc: case 0xbd: case 0xbe: case 0xbf:
            *tag = mpack_tag_make_str(type & ~0xe0u);
            return 1;
        #endif

        // nil
        case 0xc0:
            *tag = mpack_tag_make_nil();
            return 1;

        // bool
        case 0xc2: case 0xc3:
            *tag = mpack_tag_make_bool((bool)(type & 1));
            return 1;

        // bin8
        case 0xc4:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_BIN8))
                return 0;
            *tag = mpack_tag_make_bin(mpack_load_u8(reader->data + 1));
            return MPACK_TAG_SIZE_BIN8;

        // bin16
        case 0xc5:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_BIN16))
                return 0;
            *tag = mpack_tag_make_bin(mpack_load_u16(reader->data + 1));
            return MPACK_TAG_SIZE_BIN16;

        // bin32
        case 0xc6:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_BIN32))
                return 0;
            *tag = mpack_tag_make_bin(mpack_load_u32(reader->data + 1));
            return MPACK_TAG_SIZE_BIN32;

        #if MPACK_EXTENSIONS
        // ext8
        case 0xc7:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_EXT8))
                return 0;
            *tag = mpack_tag_make_ext(mpack_load_i8(reader->data + 2), mpack_load_u8(reader->data + 1));
            return MPACK_TAG_SIZE_EXT8;

        // ext16
        case 0xc8:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_EXT16))
                return 0;
            *tag = mpack_tag_make_ext(mpack_load_i8(reader->data + 3), mpack_load_u16(reader->data + 1));
            return MPACK_TAG_SIZE_EXT16;

        // ext32
        case 0xc9:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_EXT32))
                return 0;
            *tag = mpack_tag_make_ext(mpack_load_i8(reader->data + 5), mpack_load_u32(reader->data + 1));
            return MPACK_TAG_SIZE_EXT32;
        #endif

        // float
        case 0xca:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_FLOAT))
                return 0;
            #if MPACK_FLOAT
            *tag = mpack_tag_make_float(mpack_load_float(reader->data + 1));
            #else
            *tag = mpack_tag_make_raw_float(mpack_load_u32(reader->data + 1));
            #endif
            return MPACK_TAG_SIZE_FLOAT;

        // double
        case 0xcb:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_DOUBLE))
                return 0;
            #if MPACK_DOUBLE
            *tag = mpack_tag_make_double(mpack_load_double(reader->data + 1));
            #else
            *tag = mpack_tag_make_raw_double(mpack_load_u64(reader->data + 1));
            #endif
            return MPACK_TAG_SIZE_DOUBLE;

        // uint8
        case 0xcc:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_U8))
                return 0;
            *tag = mpack_tag_make_uint(mpack_load_u8(reader->data + 1));
            return MPACK_TAG_SIZE_U8;

        // uint16
        case 0xcd:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_U16))
                return 0;
            *tag = mpack_tag_make_uint(mpack_load_u16(reader->data + 1));
            return MPACK_TAG_SIZE_U16;

        // uint32
        case 0xce:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_U32))
                return 0;
            *tag = mpack_tag_make_uint(mpack_load_u32(reader->data + 1));
            return MPACK_TAG_SIZE_U32;

        // uint64
        case 0xcf:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_U64))
                return 0;
            *tag = mpack_tag_make_uint(mpack_load_u64(reader->data + 1));
            return MPACK_TAG_SIZE_U64;

        // int8
        case 0xd0:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_I8))
                return 0;
            *tag = mpack_tag_make_int(mpack_load_i8(reader->data + 1));
            return MPACK_TAG_SIZE_I8;

        // int16
        case 0xd1:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_I16))
                return 0;
            *tag = mpack_tag_make_int(mpack_load_i16(reader->data + 1));
            return MPACK_TAG_SIZE_I16;

        // int32
        case 0xd2:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_I32))
                return 0;
            *tag = mpack_tag_make_int(mpack_load_i32(reader->data + 1));
            return MPACK_TAG_SIZE_I32;

        // int64
        case 0xd3:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_I64))
                return 0;
            *tag = mpack_tag_make_int(mpack_load_i64(reader->data + 1));
            return MPACK_TAG_SIZE_I64;

        #if MPACK_EXTENSIONS
        // fixext1
        case 0xd4:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_FIXEXT1))
                return 0;
            *tag = mpack_tag_make_ext(mpack_load_i8(reader->data + 1), 1);
            return MPACK_TAG_SIZE_FIXEXT1;

        // fixext2
        case 0xd5:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_FIXEXT2))
                return 0;
            *tag = mpack_tag_make_ext(mpack_load_i8(reader->data + 1), 2);
            return MPACK_TAG_SIZE_FIXEXT2;

        // fixext4
        case 0xd6:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_FIXEXT4))
                return 0;
            *tag = mpack_tag_make_ext(mpack_load_i8(reader->data + 1), 4);
            return 2;

        // fixext8
        case 0xd7:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_FIXEXT8))
                return 0;
            *tag = mpack_tag_make_ext(mpack_load_i8(reader->data + 1), 8);
            return MPACK_TAG_SIZE_FIXEXT8;

        // fixext16
        case 0xd8:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_FIXEXT16))
                return 0;
            *tag = mpack_tag_make_ext(mpack_load_i8(reader->data + 1), 16);
            return MPACK_TAG_SIZE_FIXEXT16;
        #endif

        // str8
        case 0xd9:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_STR8))
                return 0;
            *tag = mpack_tag_make_str(mpack_load_u8(reader->data + 1));
            return MPACK_TAG_SIZE_STR8;

        // str16
        case 0xda:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_STR16))
                return 0;
            *tag = mpack_tag_make_str(mpack_load_u16(reader->data + 1));
            return MPACK_TAG_SIZE_STR16;

        // str32
        case 0xdb:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_STR32))
                return 0;
            *tag = mpack_tag_make_str(mpack_load_u32(reader->data + 1));
            return MPACK_TAG_SIZE_STR32;

        // array16
        case 0xdc:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_ARRAY16))
                return 0;
            *tag = mpack_tag_make_array(mpack_load_u16(reader->data + 1));
            return MPACK_TAG_SIZE_ARRAY16;

        // array32
        case 0xdd:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_ARRAY32))
                return 0;
            *tag = mpack_tag_make_array(mpack_load_u32(reader->data + 1));
            return MPACK_TAG_SIZE_ARRAY32;

        // map16
        case 0xde:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_MAP16))
                return 0;
            *tag = mpack_tag_make_map(mpack_load_u16(reader->data + 1));
            return MPACK_TAG_SIZE_MAP16;

        // map32
        case 0xdf:
            if (!mpack_reader_ensure(reader, MPACK_TAG_SIZE_MAP32))
                return 0;
            *tag = mpack_tag_make_map(mpack_load_u32(reader->data + 1));
            return MPACK_TAG_SIZE_MAP32;

        // reserved
        case 0xc1:
            mpack_reader_flag_error(reader, mpack_error_invalid);
            return 0;

        #if !MPACK_EXTENSIONS
        // ext
        case 0xc7: // fallthrough
        case 0xc8: // fallthrough
        case 0xc9: // fallthrough
        // fixext
        case 0xd4: // fallthrough
        case 0xd5: // fallthrough
        case 0xd6: // fallthrough
        case 0xd7: // fallthrough
        case 0xd8:
            mpack_reader_flag_error(reader, mpack_error_unsupported);
            return 0;
        #endif

        #if MPACK_OPTIMIZE_FOR_SIZE
        // any other bytes should have been handled by the infix switch
        default:
            break;
        #endif
    }

    mpack_assert(0, "unreachable");
    return 0;
}

mpack_tag_t mpack_read_tag(mpack_reader_t* reader) {
    mpack_log("reading tag\n");

    // make sure we can read a tag
    if (mpack_reader_error(reader) != mpack_ok)
        return mpack_tag_nil();
    if (mpack_reader_track_element(reader) != mpack_ok)
        return mpack_tag_nil();

    mpack_tag_t tag = MPACK_TAG_ZERO;
    size_t count = mpack_parse_tag(reader, &tag);
    if (count == 0)
        return mpack_tag_nil();

    #if MPACK_READ_TRACKING
    mpack_error_t track_error = mpack_ok;

    switch (tag.type) {
        case mpack_type_map:
        case mpack_type_array:
            track_error = mpack_track_push(&reader->track, tag.type, tag.v.n);
            break;
        #if MPACK_EXTENSIONS
        case mpack_type_ext:
        #endif
        case mpack_type_str:
        case mpack_type_bin:
            track_error = mpack_track_push(&reader->track, tag.type, tag.v.l);
            break;
        default:
            break;
    }

    if (track_error != mpack_ok) {
        mpack_reader_flag_error(reader, track_error);
        return mpack_tag_nil();
    }
    #endif

    reader->data += count;
    return tag;
}

mpack_tag_t mpack_peek_tag(mpack_reader_t* reader) {
    mpack_log("peeking tag\n");

    // make sure we can peek a tag
    if (mpack_reader_error(reader) != mpack_ok)
        return mpack_tag_nil();
    if (mpack_reader_track_peek_element(reader) != mpack_ok)
        return mpack_tag_nil();

    mpack_tag_t tag = MPACK_TAG_ZERO;
    if (mpack_parse_tag(reader, &tag) == 0)
        return mpack_tag_nil();
    return tag;
}

void mpack_discard(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (mpack_reader_error(reader))
        return;
    switch (var.type) {
        case mpack_type_str:
            mpack_skip_bytes(reader, var.v.l);
            mpack_done_str(reader);
            break;
        case mpack_type_bin:
            mpack_skip_bytes(reader, var.v.l);
            mpack_done_bin(reader);
            break;
        #if MPACK_EXTENSIONS
        case mpack_type_ext:
            mpack_skip_bytes(reader, var.v.l);
            mpack_done_ext(reader);
            break;
        #endif
        case mpack_type_array: {
            for (; var.v.n > 0; --var.v.n) {
                mpack_discard(reader);
                if (mpack_reader_error(reader))
                    break;
            }
            mpack_done_array(reader);
            break;
        }
        case mpack_type_map: {
            for (; var.v.n > 0; --var.v.n) {
                mpack_discard(reader);
                mpack_discard(reader);
                if (mpack_reader_error(reader))
                    break;
            }
            mpack_done_map(reader);
            break;
        }
        default:
            break;
    }
}

#if MPACK_EXTENSIONS
mpack_timestamp_t mpack_read_timestamp(mpack_reader_t* reader, size_t size) {
    mpack_timestamp_t timestamp = {0, 0};

    if (size != 4 && size != 8 && size != 12) {
        mpack_reader_flag_error(reader, mpack_error_invalid);
        return timestamp;
    }

    char buf[12];
    mpack_read_bytes(reader, buf, size);
    mpack_done_ext(reader);
    if (mpack_reader_error(reader) != mpack_ok)
        return timestamp;

    switch (size) {
        case 4:
            timestamp.seconds = (int64_t)(uint64_t)mpack_load_u32(buf);
            break;

        case 8: {
            uint64_t packed = mpack_load_u64(buf);
            timestamp.seconds = (int64_t)(packed & ((MPACK_UINT64_C(1) << 34) - 1));
            timestamp.nanoseconds = (uint32_t)(packed >> 34);
            break;
        }

        case 12:
            timestamp.nanoseconds = mpack_load_u32(buf);
            timestamp.seconds = mpack_load_i64(buf + 4);
            break;

        default:
            mpack_assert(false, "unreachable");
            break;
    }

    if (timestamp.nanoseconds > MPACK_TIMESTAMP_NANOSECONDS_MAX) {
        mpack_reader_flag_error(reader, mpack_error_invalid);
        mpack_timestamp_t zero = {0, 0};
        return zero;
    }

    return timestamp;
}
#endif

#if MPACK_READ_TRACKING
void mpack_done_type(mpack_reader_t* reader, mpack_type_t type) {
    if (mpack_reader_error(reader) == mpack_ok)
        mpack_reader_flag_if_error(reader, mpack_track_pop(&reader->track, type));
}
#endif

#if MPACK_DEBUG && MPACK_STDIO
static size_t mpack_print_read_prefix(mpack_reader_t* reader, size_t length, char* buffer, size_t buffer_size) {
    if (length == 0)
        return 0;

    size_t read = (length < buffer_size) ? length : buffer_size;
    mpack_read_bytes(reader, buffer, read);
    if (mpack_reader_error(reader) != mpack_ok)
        return 0;

    mpack_skip_bytes(reader, length - read);
    return read;
}

static void mpack_print_element(mpack_reader_t* reader, mpack_print_t* print, size_t depth) {
    mpack_tag_t val = mpack_read_tag(reader);
    if (mpack_reader_error(reader) != mpack_ok)
        return;

    // We read some bytes from bin and ext so we can print its prefix in hex.
    char buffer[MPACK_PRINT_BYTE_COUNT];
    size_t count = 0;
    size_t i, j;

    switch (val.type) {
        case mpack_type_str:
            mpack_print_append_cstr(print, "\"");
            for (i = 0; i < val.v.l; ++i) {
                char c;
                mpack_read_bytes(reader, &c, 1);
                if (mpack_reader_error(reader) != mpack_ok)
                    return;
                switch (c) {
                    case '\n': mpack_print_append_cstr(print, "\\n"); break;
                    case '\\': mpack_print_append_cstr(print, "\\\\"); break;
                    case '"': mpack_print_append_cstr(print, "\\\""); break;
                    default: mpack_print_append(print, &c, 1); break;
                }
            }
            mpack_print_append_cstr(print, "\"");
            mpack_done_str(reader);
            return;

        case mpack_type_array:
            mpack_print_append_cstr(print, "[\n");
            for (i = 0; i < val.v.n; ++i) {
                for (j = 0; j < depth + 1; ++j)
                    mpack_print_append_cstr(print, "    ");
                mpack_print_element(reader, print, depth + 1);
                if (mpack_reader_error(reader) != mpack_ok)
                    return;
                if (i != val.v.n - 1)
                    mpack_print_append_cstr(print, ",");
                mpack_print_append_cstr(print, "\n");
            }
            for (i = 0; i < depth; ++i)
                mpack_print_append_cstr(print, "    ");
            mpack_print_append_cstr(print, "]");
            mpack_done_array(reader);
            return;

        case mpack_type_map:
            mpack_print_append_cstr(print, "{\n");
            for (i = 0; i < val.v.n; ++i) {
                for (j = 0; j < depth + 1; ++j)
                    mpack_print_append_cstr(print, "    ");
                mpack_print_element(reader, print, depth + 1);
                if (mpack_reader_error(reader) != mpack_ok)
                    return;
                mpack_print_append_cstr(print, ": ");
                mpack_print_element(reader, print, depth + 1);
                if (mpack_reader_error(reader) != mpack_ok)
                    return;
                if (i != val.v.n - 1)
                    mpack_print_append_cstr(print, ",");
                mpack_print_append_cstr(print, "\n");
            }
            for (i = 0; i < depth; ++i)
                mpack_print_append_cstr(print, "    ");
            mpack_print_append_cstr(print, "}");
            mpack_done_map(reader);
            return;

        // The above cases return so as not to print a pseudo-json value. The
        // below cases break and print pseudo-json.

        case mpack_type_bin:
            count = mpack_print_read_prefix(reader, mpack_tag_bin_length(&val), buffer, sizeof(buffer));
            mpack_done_bin(reader);
            break;

        #if MPACK_EXTENSIONS
        case mpack_type_ext:
            count = mpack_print_read_prefix(reader, mpack_tag_ext_length(&val), buffer, sizeof(buffer));
            mpack_done_ext(reader);
            break;
        #endif

        default:
            break;
    }

    char buf[256];
    mpack_tag_debug_pseudo_json(val, buf, sizeof(buf), buffer, count);
    mpack_print_append_cstr(print, buf);
}

static void mpack_print_and_destroy(mpack_reader_t* reader, mpack_print_t* print, size_t depth) {
    size_t i;
    for (i = 0; i < depth; ++i)
        mpack_print_append_cstr(print, "    ");
    mpack_print_element(reader, print, depth);

    size_t remaining = mpack_reader_remaining(reader, NULL);

    char buf[256];
    if (mpack_reader_destroy(reader) != mpack_ok) {
        mpack_snprintf(buf, sizeof(buf), "\n<mpack parsing error %s>", mpack_error_to_string(mpack_reader_error(reader)));
        buf[sizeof(buf) - 1] = '\0';
        mpack_print_append_cstr(print, buf);
    } else if (remaining > 0) {
        mpack_snprintf(buf, sizeof(buf), "\n<%i extra bytes at end of message>", (int)remaining);
        buf[sizeof(buf) - 1] = '\0';
        mpack_print_append_cstr(print, buf);
    }
}

static void mpack_print_data(const char* data, size_t len, mpack_print_t* print, size_t depth) {
    mpack_reader_t reader;
    mpack_reader_init_data(&reader, data, len);
    mpack_print_and_destroy(&reader, print, depth);
}

void mpack_print_data_to_buffer(const char* data, size_t data_size, char* buffer, size_t buffer_size) {
    if (buffer_size == 0) {
        mpack_assert(false, "buffer size is zero!");
        return;
    }

    mpack_print_t print;
    mpack_memset(&print, 0, sizeof(print));
    print.buffer = buffer;
    print.size = buffer_size;
    mpack_print_data(data, data_size, &print, 0);
    mpack_print_append(&print, "",  1); // null-terminator
    mpack_print_flush(&print);

    // we always make sure there's a null-terminator at the end of the buffer
    // in case we ran out of space.
    print.buffer[print.size - 1] = '\0';
}

void mpack_print_data_to_callback(const char* data, size_t size, mpack_print_callback_t callback, void* context) {
    char buffer[1024];
    mpack_print_t print;
    mpack_memset(&print, 0, sizeof(print));
    print.buffer = buffer;
    print.size = sizeof(buffer);
    print.callback = callback;
    print.context = context;
    mpack_print_data(data, size, &print, 0);
    mpack_print_flush(&print);
}

void mpack_print_data_to_file(const char* data, size_t len, FILE* file) {
    mpack_assert(data != NULL, "data is NULL");
    mpack_assert(file != NULL, "file is NULL");

    char buffer[1024];
    mpack_print_t print;
    mpack_memset(&print, 0, sizeof(print));
    print.buffer = buffer;
    print.size = sizeof(buffer);
    print.callback = &mpack_print_file_callback;
    print.context = file;

    mpack_print_data(data, len, &print, 2);
    mpack_print_append_cstr(&print, "\n");
    mpack_print_flush(&print);
}

void mpack_print_stdfile_to_callback(FILE* file, mpack_print_callback_t callback, void* context) {
    char buffer[1024];
    mpack_print_t print;
    mpack_memset(&print, 0, sizeof(print));
    print.buffer = buffer;
    print.size = sizeof(buffer);
    print.callback = callback;
    print.context = context;

    mpack_reader_t reader;
    mpack_reader_init_stdfile(&reader, file, false);
    mpack_print_and_destroy(&reader, &print, 0);
    mpack_print_flush(&print);
}
#endif

#endif

MPACK_SILENCE_WARNINGS_END

/* mpack/mpack-expect.c.c */

#define MPACK_INTERNAL 1

/* #include "mpack-expect.h" */

MPACK_SILENCE_WARNINGS_BEGIN

#if MPACK_EXPECT


// Helpers

MPACK_STATIC_INLINE uint8_t mpack_expect_native_u8(mpack_reader_t* reader) {
    if (mpack_reader_error(reader) != mpack_ok)
        return 0;
    uint8_t type;
    if (!mpack_reader_ensure(reader, sizeof(type)))
        return 0;
    type = mpack_load_u8(reader->data);
    reader->data += sizeof(type);
    return type;
}

#if !MPACK_OPTIMIZE_FOR_SIZE
MPACK_STATIC_INLINE uint16_t mpack_expect_native_u16(mpack_reader_t* reader) {
    if (mpack_reader_error(reader) != mpack_ok)
        return 0;
    uint16_t type;
    if (!mpack_reader_ensure(reader, sizeof(type)))
        return 0;
    type = mpack_load_u16(reader->data);
    reader->data += sizeof(type);
    return type;
}

MPACK_STATIC_INLINE uint32_t mpack_expect_native_u32(mpack_reader_t* reader) {
    if (mpack_reader_error(reader) != mpack_ok)
        return 0;
    uint32_t type;
    if (!mpack_reader_ensure(reader, sizeof(type)))
        return 0;
    type = mpack_load_u32(reader->data);
    reader->data += sizeof(type);
    return type;
}
#endif

MPACK_STATIC_INLINE uint8_t mpack_expect_type_byte(mpack_reader_t* reader) {
    mpack_reader_track_element(reader);
    return mpack_expect_native_u8(reader);
}


// Basic Number Functions

uint8_t mpack_expect_u8(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_uint) {
        if (var.v.u <= MPACK_UINT8_MAX)
            return (uint8_t)var.v.u;
    } else if (var.type == mpack_type_int) {
        if (var.v.i >= 0 && var.v.i <= MPACK_UINT8_MAX)
            return (uint8_t)var.v.i;
    }
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}

uint16_t mpack_expect_u16(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_uint) {
        if (var.v.u <= MPACK_UINT16_MAX)
            return (uint16_t)var.v.u;
    } else if (var.type == mpack_type_int) {
        if (var.v.i >= 0 && var.v.i <= MPACK_UINT16_MAX)
            return (uint16_t)var.v.i;
    }
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}

uint32_t mpack_expect_u32(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_uint) {
        if (var.v.u <= MPACK_UINT32_MAX)
            return (uint32_t)var.v.u;
    } else if (var.type == mpack_type_int) {
        if (var.v.i >= 0 && var.v.i <= MPACK_UINT32_MAX)
            return (uint32_t)var.v.i;
    }
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}

uint64_t mpack_expect_u64(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_uint) {
        return var.v.u;
    } else if (var.type == mpack_type_int) {
        if (var.v.i >= 0)
            return (uint64_t)var.v.i;
    }
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}

int8_t mpack_expect_i8(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_uint) {
        if (var.v.u <= MPACK_INT8_MAX)
            return (int8_t)var.v.u;
    } else if (var.type == mpack_type_int) {
        if (var.v.i >= MPACK_INT8_MIN && var.v.i <= MPACK_INT8_MAX)
            return (int8_t)var.v.i;
    }
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}

int16_t mpack_expect_i16(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_uint) {
        if (var.v.u <= MPACK_INT16_MAX)
            return (int16_t)var.v.u;
    } else if (var.type == mpack_type_int) {
        if (var.v.i >= MPACK_INT16_MIN && var.v.i <= MPACK_INT16_MAX)
            return (int16_t)var.v.i;
    }
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}

int32_t mpack_expect_i32(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_uint) {
        if (var.v.u <= MPACK_INT32_MAX)
            return (int32_t)var.v.u;
    } else if (var.type == mpack_type_int) {
        if (var.v.i >= MPACK_INT32_MIN && var.v.i <= MPACK_INT32_MAX)
            return (int32_t)var.v.i;
    }
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}

int64_t mpack_expect_i64(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_uint) {
        if (var.v.u <= MPACK_INT64_MAX)
            return (int64_t)var.v.u;
    } else if (var.type == mpack_type_int) {
        return var.v.i;
    }
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}

#if MPACK_FLOAT
float mpack_expect_float(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_uint)
        return (float)var.v.u;
    if (var.type == mpack_type_int)
        return (float)var.v.i;
    if (var.type == mpack_type_float)
        return var.v.f;

    if (var.type == mpack_type_double) {
        #if MPACK_DOUBLE
        return (float)var.v.d;
        #else
        return mpack_shorten_raw_double_to_float(var.v.d);
        #endif
    }

    mpack_reader_flag_error(reader, mpack_error_type);
    return 0.0f;
}
#endif

#if MPACK_DOUBLE
double mpack_expect_double(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_uint)
        return (double)var.v.u;
    else if (var.type == mpack_type_int)
        return (double)var.v.i;
    else if (var.type == mpack_type_float)
        return (double)var.v.f;
    else if (var.type == mpack_type_double)
        return var.v.d;
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0.0;
}
#endif

#if MPACK_FLOAT
float mpack_expect_float_strict(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_float)
        return var.v.f;
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0.0f;
}
#endif

#if MPACK_DOUBLE
double mpack_expect_double_strict(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_float)
        return (double)var.v.f;
    else if (var.type == mpack_type_double)
        return var.v.d;
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0.0;
}
#endif

#if !MPACK_FLOAT
uint32_t mpack_expect_raw_float(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_float)
        return var.v.f;
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}
#endif

#if !MPACK_DOUBLE
uint64_t mpack_expect_raw_double(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_double)
        return var.v.d;
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}
#endif


// Ranged Number Functions
//
// All ranged functions are identical other than the type, so we
// define their content with a macro. The prototypes are still written
// out in full to support ctags/IDE tools.

#define MPACK_EXPECT_RANGE_IMPL(name, type_t)                           \
                                                                        \
    /* make sure the range is sensible */                               \
    mpack_assert(min_value <= max_value,                                \
            "min_value %i must be less than or equal to max_value %i",  \
            min_value, max_value);                                      \
                                                                        \
    /* read the value */                                                \
    type_t val = mpack_expect_##name(reader);                           \
    if (mpack_reader_error(reader) != mpack_ok)                         \
        return min_value;                                               \
                                                                        \
    /* make sure it fits */                                             \
    if (val < min_value || val > max_value) {                           \
        mpack_reader_flag_error(reader, mpack_error_type);              \
        return min_value;                                               \
    }                                                                   \
                                                                        \
    return val;

uint8_t mpack_expect_u8_range(mpack_reader_t* reader, uint8_t min_value, uint8_t max_value) {MPACK_EXPECT_RANGE_IMPL(u8, uint8_t)}
uint16_t mpack_expect_u16_range(mpack_reader_t* reader, uint16_t min_value, uint16_t max_value) {MPACK_EXPECT_RANGE_IMPL(u16, uint16_t)}
uint32_t mpack_expect_u32_range(mpack_reader_t* reader, uint32_t min_value, uint32_t max_value) {MPACK_EXPECT_RANGE_IMPL(u32, uint32_t)}
uint64_t mpack_expect_u64_range(mpack_reader_t* reader, uint64_t min_value, uint64_t max_value) {MPACK_EXPECT_RANGE_IMPL(u64, uint64_t)}

int8_t mpack_expect_i8_range(mpack_reader_t* reader, int8_t min_value, int8_t max_value) {MPACK_EXPECT_RANGE_IMPL(i8, int8_t)}
int16_t mpack_expect_i16_range(mpack_reader_t* reader, int16_t min_value, int16_t max_value) {MPACK_EXPECT_RANGE_IMPL(i16, int16_t)}
int32_t mpack_expect_i32_range(mpack_reader_t* reader, int32_t min_value, int32_t max_value) {MPACK_EXPECT_RANGE_IMPL(i32, int32_t)}
int64_t mpack_expect_i64_range(mpack_reader_t* reader, int64_t min_value, int64_t max_value) {MPACK_EXPECT_RANGE_IMPL(i64, int64_t)}

#if MPACK_FLOAT
float mpack_expect_float_range(mpack_reader_t* reader, float min_value, float max_value) {MPACK_EXPECT_RANGE_IMPL(float, float)}
#endif
#if MPACK_DOUBLE
double mpack_expect_double_range(mpack_reader_t* reader, double min_value, double max_value) {MPACK_EXPECT_RANGE_IMPL(double, double)}
#endif

uint32_t mpack_expect_map_range(mpack_reader_t* reader, uint32_t min_value, uint32_t max_value) {MPACK_EXPECT_RANGE_IMPL(map, uint32_t)}
uint32_t mpack_expect_array_range(mpack_reader_t* reader, uint32_t min_value, uint32_t max_value) {MPACK_EXPECT_RANGE_IMPL(array, uint32_t)}


// Matching Number Functions

void mpack_expect_uint_match(mpack_reader_t* reader, uint64_t value) {
    if (mpack_expect_u64(reader) != value)
        mpack_reader_flag_error(reader, mpack_error_type);
}

void mpack_expect_int_match(mpack_reader_t* reader, int64_t value) {
    if (mpack_expect_i64(reader) != value)
        mpack_reader_flag_error(reader, mpack_error_type);
}


// Other Basic Types

void mpack_expect_nil(mpack_reader_t* reader) {
    if (mpack_expect_type_byte(reader) != 0xc0)
        mpack_reader_flag_error(reader, mpack_error_type);
}

bool mpack_expect_bool(mpack_reader_t* reader) {
    uint8_t type = mpack_expect_type_byte(reader);
    if ((type & ~1) != 0xc2)
        mpack_reader_flag_error(reader, mpack_error_type);
    return (bool)(type & 1);
}

void mpack_expect_true(mpack_reader_t* reader) {
    if (mpack_expect_bool(reader) != true)
        mpack_reader_flag_error(reader, mpack_error_type);
}

void mpack_expect_false(mpack_reader_t* reader) {
    if (mpack_expect_bool(reader) != false)
        mpack_reader_flag_error(reader, mpack_error_type);
}

#if MPACK_EXTENSIONS
mpack_timestamp_t mpack_expect_timestamp(mpack_reader_t* reader) {
    mpack_timestamp_t zero = {0, 0};

    mpack_tag_t tag = mpack_read_tag(reader);
    if (tag.type != mpack_type_ext) {
        mpack_reader_flag_error(reader, mpack_error_type);
        return zero;
    }
    if (mpack_tag_ext_exttype(&tag) != MPACK_EXTTYPE_TIMESTAMP) {
        mpack_reader_flag_error(reader, mpack_error_type);
        return zero;
    }

    return mpack_read_timestamp(reader, mpack_tag_ext_length(&tag));
}

int64_t mpack_expect_timestamp_truncate(mpack_reader_t* reader) {
    return mpack_expect_timestamp(reader).seconds;
}
#endif


// Compound Types

uint32_t mpack_expect_map(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_map)
        return var.v.n;
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}

void mpack_expect_map_match(mpack_reader_t* reader, uint32_t count) {
    if (mpack_expect_map(reader) != count)
        mpack_reader_flag_error(reader, mpack_error_type);
}

bool mpack_expect_map_or_nil(mpack_reader_t* reader, uint32_t* count) {
    mpack_assert(count != NULL, "count cannot be NULL");

    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_nil) {
        *count = 0;
        return false;
    }
    if (var.type == mpack_type_map) {
        *count = var.v.n;
        return true;
    }
    mpack_reader_flag_error(reader, mpack_error_type);
    *count = 0;
    return false;
}

bool mpack_expect_map_max_or_nil(mpack_reader_t* reader, uint32_t max_count, uint32_t* count) {
    mpack_assert(count != NULL, "count cannot be NULL");

    bool has_map = mpack_expect_map_or_nil(reader, count);
    if (has_map && *count > max_count) {
        *count = 0;
        mpack_reader_flag_error(reader, mpack_error_type);
        return false;
    }
    return has_map;
}

uint32_t mpack_expect_array(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_array)
        return var.v.n;
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}

void mpack_expect_array_match(mpack_reader_t* reader, uint32_t count) {
    if (mpack_expect_array(reader) != count)
        mpack_reader_flag_error(reader, mpack_error_type);
}

bool mpack_expect_array_or_nil(mpack_reader_t* reader, uint32_t* count) {
    mpack_assert(count != NULL, "count cannot be NULL");

    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_nil) {
        *count = 0;
        return false;
    }
    if (var.type == mpack_type_array) {
        *count = var.v.n;
        return true;
    }
    mpack_reader_flag_error(reader, mpack_error_type);
    *count = 0;
    return false;
}

bool mpack_expect_array_max_or_nil(mpack_reader_t* reader, uint32_t max_count, uint32_t* count) {
    mpack_assert(count != NULL, "count cannot be NULL");

    bool has_array = mpack_expect_array_or_nil(reader, count);
    if (has_array && *count > max_count) {
        *count = 0;
        mpack_reader_flag_error(reader, mpack_error_type);
        return false;
    }
    return has_array;
}

#ifdef MPACK_MALLOC
void* mpack_expect_array_alloc_impl(mpack_reader_t* reader, size_t element_size, uint32_t max_count, uint32_t* out_count, bool allow_nil) {
    mpack_assert(out_count != NULL, "out_count cannot be NULL");
    *out_count = 0;

    uint32_t count;
    bool has_array = true;
    if (allow_nil)
        has_array = mpack_expect_array_max_or_nil(reader, max_count, &count);
    else
        count = mpack_expect_array_max(reader, max_count);
    if (mpack_reader_error(reader))
        return NULL;

    // size 0 is not an error; we return NULL for no elements.
    if (count == 0) {
        // we call mpack_done_array() automatically ONLY if we are using
        // the _or_nil variant. this is the only way to allow nil and empty
        // to work the same way.
        if (allow_nil && has_array)
            mpack_done_array(reader);
        return NULL;
    }

    void* p = MPACK_MALLOC(element_size * count);
    if (p == NULL) {
        mpack_reader_flag_error(reader, mpack_error_memory);
        return NULL;
    }

    *out_count = count;
    return p;
}
#endif


// Str, Bin and Ext Functions

uint32_t mpack_expect_str(mpack_reader_t* reader) {
    #if MPACK_OPTIMIZE_FOR_SIZE
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_str)
        return var.v.l;
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
    #else
    uint8_t type = mpack_expect_type_byte(reader);
    uint32_t count;

    if ((type >> 5) == 5) {
        count = type & (uint8_t)~0xe0;
    } else if (type == 0xd9) {
        count = mpack_expect_native_u8(reader);
    } else if (type == 0xda) {
        count = mpack_expect_native_u16(reader);
    } else if (type == 0xdb) {
        count = mpack_expect_native_u32(reader);
    } else {
        mpack_reader_flag_error(reader, mpack_error_type);
        return 0;
    }

    #if MPACK_READ_TRACKING
    mpack_reader_flag_if_error(reader, mpack_track_push(&reader->track, mpack_type_str, count));
    #endif
    return count;
    #endif
}

size_t mpack_expect_str_buf(mpack_reader_t* reader, char* buf, size_t bufsize) {
    mpack_assert(buf != NULL, "buf cannot be NULL");

    size_t length = mpack_expect_str(reader);
    if (mpack_reader_error(reader))
        return 0;

    if (length > bufsize) {
        mpack_reader_flag_error(reader, mpack_error_too_big);
        return 0;
    }

    mpack_read_bytes(reader, buf, length);
    if (mpack_reader_error(reader))
        return 0;

    mpack_done_str(reader);
    return length;
}

size_t mpack_expect_utf8(mpack_reader_t* reader, char* buf, size_t size) {
    mpack_assert(buf != NULL, "buf cannot be NULL");

    size_t length = mpack_expect_str_buf(reader, buf, size);

    if (!mpack_utf8_check(buf, length)) {
        mpack_reader_flag_error(reader, mpack_error_type);
        return 0;
    }

    return length;
}

uint32_t mpack_expect_bin(mpack_reader_t* reader) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_bin)
        return var.v.l;
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}

size_t mpack_expect_bin_buf(mpack_reader_t* reader, char* buf, size_t bufsize) {
    mpack_assert(buf != NULL, "buf cannot be NULL");

    size_t binsize = mpack_expect_bin(reader);
    if (mpack_reader_error(reader))
        return 0;
    if (binsize > bufsize) {
        mpack_reader_flag_error(reader, mpack_error_too_big);
        return 0;
    }
    mpack_read_bytes(reader, buf, binsize);
    if (mpack_reader_error(reader))
        return 0;
    mpack_done_bin(reader);
    return binsize;
}

void mpack_expect_bin_size_buf(mpack_reader_t* reader, char* buf, uint32_t size) {
    mpack_assert(buf != NULL, "buf cannot be NULL");
    mpack_expect_bin_size(reader, size);
    mpack_read_bytes(reader, buf, size);
    mpack_done_bin(reader);
}

#if MPACK_EXTENSIONS
uint32_t mpack_expect_ext(mpack_reader_t* reader, int8_t* type) {
    mpack_tag_t var = mpack_read_tag(reader);
    if (var.type == mpack_type_ext) {
        *type = mpack_tag_ext_exttype(&var);
        return mpack_tag_ext_length(&var);
    }
    *type = 0;
    mpack_reader_flag_error(reader, mpack_error_type);
    return 0;
}

size_t mpack_expect_ext_buf(mpack_reader_t* reader, int8_t* type, char* buf, size_t bufsize) {
    mpack_assert(buf != NULL, "buf cannot be NULL");

    size_t extsize = mpack_expect_ext(reader, type);
    if (mpack_reader_error(reader))
        return 0;
    if (extsize > bufsize) {
        *type = 0;
        mpack_reader_flag_error(reader, mpack_error_too_big);
        return 0;
    }
    mpack_read_bytes(reader, buf, extsize);
    if (mpack_reader_error(reader)) {
        *type = 0;
        return 0;
    }
    mpack_done_ext(reader);
    return extsize;
}
#endif

void mpack_expect_cstr(mpack_reader_t* reader, char* buf, size_t bufsize) {
    uint32_t length = mpack_expect_str(reader);
    mpack_read_cstr(reader, buf, bufsize, length);
    mpack_done_str(reader);
}

void mpack_expect_utf8_cstr(mpack_reader_t* reader, char* buf, size_t bufsize) {
    uint32_t length = mpack_expect_str(reader);
    mpack_read_utf8_cstr(reader, buf, bufsize, length);
    mpack_done_str(reader);
}

#ifdef MPACK_MALLOC
static char* mpack_expect_cstr_alloc_unchecked(mpack_reader_t* reader, size_t maxsize, size_t* out_length) {
    mpack_assert(out_length != NULL, "out_length cannot be NULL");
    *out_length = 0;

    // make sure argument makes sense
    if (maxsize < 1) {
        mpack_break("maxsize is zero; you must have room for at least a null-terminator");
        mpack_reader_flag_error(reader, mpack_error_bug);
        return NULL;
    }

    if (SIZE_MAX < MPACK_UINT32_MAX) {
        if (maxsize > SIZE_MAX)
            maxsize = SIZE_MAX;
    } else {
        if (maxsize > (size_t)MPACK_UINT32_MAX)
            maxsize = (size_t)MPACK_UINT32_MAX;
    }

    size_t length = mpack_expect_str_max(reader, (uint32_t)maxsize - 1);
    char* str = mpack_read_bytes_alloc_impl(reader, length, true);
    mpack_done_str(reader);

    if (str)
        *out_length = length;
    return str;
}

char* mpack_expect_cstr_alloc(mpack_reader_t* reader, size_t maxsize) {
    size_t length;
    char* str = mpack_expect_cstr_alloc_unchecked(reader, maxsize, &length);

    if (str && !mpack_str_check_no_null(str, length)) {
        MPACK_FREE(str);
        mpack_reader_flag_error(reader, mpack_error_type);
        return NULL;
    }

    return str;
}

char* mpack_expect_utf8_cstr_alloc(mpack_reader_t* reader, size_t maxsize) {
    size_t length;
    char* str = mpack_expect_cstr_alloc_unchecked(reader, maxsize, &length);

    if (str && !mpack_utf8_check_no_null(str, length)) {
        MPACK_FREE(str);
        mpack_reader_flag_error(reader, mpack_error_type);
        return NULL;
    }

    return str;
}
#endif

void mpack_expect_str_match(mpack_reader_t* reader, const char* str, size_t len) {
    mpack_assert(str != NULL, "str cannot be NULL");

    // expect a str the correct length
    if (len > MPACK_UINT32_MAX)
        mpack_reader_flag_error(reader, mpack_error_type);
    mpack_expect_str_length(reader, (uint32_t)len);
    if (mpack_reader_error(reader))
        return;
    mpack_reader_track_bytes(reader, (uint32_t)len);

    // check each byte one by one (matched strings are likely to be very small)
    for (; len > 0; --len) {
        if (mpack_expect_native_u8(reader) != *str++) {
            mpack_reader_flag_error(reader, mpack_error_type);
            return;
        }
    }

    mpack_done_str(reader);
}

void mpack_expect_tag(mpack_reader_t* reader, mpack_tag_t expected) {
    mpack_tag_t actual = mpack_read_tag(reader);
    if (!mpack_tag_equal(actual, expected))
        mpack_reader_flag_error(reader, mpack_error_type);
}

#ifdef MPACK_MALLOC
char* mpack_expect_bin_alloc(mpack_reader_t* reader, size_t maxsize, size_t* size) {
    mpack_assert(size != NULL, "size cannot be NULL");
    *size = 0;

    if (SIZE_MAX < MPACK_UINT32_MAX) {
        if (maxsize > SIZE_MAX)
            maxsize = SIZE_MAX;
    } else {
        if (maxsize > (size_t)MPACK_UINT32_MAX)
            maxsize = (size_t)MPACK_UINT32_MAX;
    }

    size_t length = mpack_expect_bin_max(reader, (uint32_t)maxsize);
    if (mpack_reader_error(reader))
        return NULL;

    char* data = mpack_read_bytes_alloc(reader, length);
    mpack_done_bin(reader);

    if (data)
        *size = length;
    return data;
}
#endif

#if MPACK_EXTENSIONS && defined(MPACK_MALLOC)
char* mpack_expect_ext_alloc(mpack_reader_t* reader, int8_t* type, size_t maxsize, size_t* size) {
    mpack_assert(size != NULL, "size cannot be NULL");
    *size = 0;

    if (SIZE_MAX < MPACK_UINT32_MAX) {
        if (maxsize > SIZE_MAX)
            maxsize = SIZE_MAX;
    } else {
        if (maxsize > (size_t)MPACK_UINT32_MAX)
            maxsize = (size_t)MPACK_UINT32_MAX;
    }

    size_t length = mpack_expect_ext_max(reader, type, (uint32_t)maxsize);
    if (mpack_reader_error(reader))
        return NULL;

    char* data = mpack_read_bytes_alloc(reader, length);
    mpack_done_ext(reader);

    if (data) {
        *size = length;
    } else {
        *type = 0;
    }
    return data;
}
#endif

size_t mpack_expect_enum(mpack_reader_t* reader, const char* strings[], size_t count) {

    // read the string in-place
    size_t keylen = mpack_expect_str(reader);
    const char* key = mpack_read_bytes_inplace(reader, keylen);
    mpack_done_str(reader);
    if (mpack_reader_error(reader) != mpack_ok)
        return count;

    // find what key it matches
    size_t i;
    for (i = 0; i < count; ++i) {
        const char* other = strings[i];
        size_t otherlen = mpack_strlen(other);
        if (keylen == otherlen && mpack_memcmp(key, other, keylen) == 0)
            return i;
    }

    // no matches
    mpack_reader_flag_error(reader, mpack_error_type);
    return count;
}

size_t mpack_expect_enum_optional(mpack_reader_t* reader, const char* strings[], size_t count) {
    if (mpack_reader_error(reader) != mpack_ok)
        return count;

    mpack_assert(count != 0, "count cannot be zero; no strings are valid!");
    mpack_assert(strings != NULL, "strings cannot be NULL");

    // the key is only recognized if it is a string
    if (mpack_peek_tag(reader).type != mpack_type_str) {
        mpack_discard(reader);
        return count;
    }

    // read the string in-place
    size_t keylen = mpack_expect_str(reader);
    const char* key = mpack_read_bytes_inplace(reader, keylen);
    mpack_done_str(reader);
    if (mpack_reader_error(reader) != mpack_ok)
        return count;

    // find what key it matches
    size_t i;
    for (i = 0; i < count; ++i) {
        const char* other = strings[i];
        size_t otherlen = mpack_strlen(other);
        if (keylen == otherlen && mpack_memcmp(key, other, keylen) == 0)
            return i;
    }

    // no matches
    return count;
}

size_t mpack_expect_key_uint(mpack_reader_t* reader, bool found[], size_t count) {
    if (mpack_reader_error(reader) != mpack_ok)
        return count;

    if (count == 0) {
        mpack_break("count cannot be zero; no keys are valid!");
        mpack_reader_flag_error(reader, mpack_error_bug);
        return count;
    }
    mpack_assert(found != NULL, "found cannot be NULL");

    // the key is only recognized if it is an unsigned int
    if (mpack_peek_tag(reader).type != mpack_type_uint) {
        mpack_discard(reader);
        return count;
    }

    // read the key
    uint64_t value = mpack_expect_u64(reader);
    if (mpack_reader_error(reader) != mpack_ok)
        return count;

    // unrecognized keys are fine, we just return count
    if (value >= count)
        return count;

    // check if this key is a duplicate
    if (found[value]) {
        mpack_reader_flag_error(reader, mpack_error_invalid);
        return count;
    }

    found[value] = true;
    return (size_t)value;
}

size_t mpack_expect_key_cstr(mpack_reader_t* reader, const char* keys[], bool found[], size_t count) {
    size_t i = mpack_expect_enum_optional(reader, keys, count);

    // unrecognized keys are fine, we just return count
    if (i == count)
        return count;

    // check if this key is a duplicate
    mpack_assert(found != NULL, "found cannot be NULL");
    if (found[i]) {
        mpack_reader_flag_error(reader, mpack_error_invalid);
        return count;
    }

    found[i] = true;
    return i;
}

#endif

MPACK_SILENCE_WARNINGS_END

/* mpack/mpack-node.c.c */

#define MPACK_INTERNAL 1

/* #include "mpack-node.h" */

MPACK_SILENCE_WARNINGS_BEGIN

#if MPACK_NODE

MPACK_STATIC_INLINE const char* mpack_node_data_unchecked(mpack_node_t node) {
    mpack_assert(mpack_node_error(node) == mpack_ok, "tree is in an error state!");

    mpack_type_t type = node.data->type;
    MPACK_UNUSED(type);
    #if MPACK_EXTENSIONS
    mpack_assert(type == mpack_type_str || type == mpack_type_bin || type == mpack_type_ext,
            "node of type %i (%s) is not a data type!", type, mpack_type_to_string(type));
    #else
    mpack_assert(type == mpack_type_str || type == mpack_type_bin,
            "node of type %i (%s) is not a data type!", type, mpack_type_to_string(type));
    #endif

    return node.tree->data + node.data->value.offset;
}

#if MPACK_EXTENSIONS
MPACK_STATIC_INLINE int8_t mpack_node_exttype_unchecked(mpack_node_t node) {
    mpack_assert(mpack_node_error(node) == mpack_ok, "tree is in an error state!");

    mpack_type_t type = node.data->type;
    MPACK_UNUSED(type);
    mpack_assert(type == mpack_type_ext, "node of type %i (%s) is not an ext type!",
            type, mpack_type_to_string(type));

    // the exttype of an ext node is stored in the byte preceding the data
    return mpack_load_i8(mpack_node_data_unchecked(node) - 1);
}
#endif



/*
 * Tree Parsing
 */

#ifdef MPACK_MALLOC

// fix up the alloc size to make sure it exactly fits the
// maximum number of nodes it can contain (the allocator will
// waste it back anyway, but we round it down just in case)

#define MPACK_NODES_PER_PAGE \
    ((MPACK_NODE_PAGE_SIZE - sizeof(mpack_tree_page_t)) / sizeof(mpack_node_data_t) + 1)

#define MPACK_PAGE_ALLOC_SIZE \
    (sizeof(mpack_tree_page_t) + sizeof(mpack_node_data_t) * (MPACK_NODES_PER_PAGE - 1))

#endif

#ifdef MPACK_MALLOC
/*
 * Fills the tree until we have at least enough bytes for the current node.
 */
static bool mpack_tree_reserve_fill(mpack_tree_t* tree) {
    mpack_assert(tree->parser.state == mpack_tree_parse_state_in_progress);

    size_t bytes = tree->parser.current_node_reserved;
    mpack_assert(bytes > tree->parser.possible_nodes_left,
            "there are already enough bytes! call mpack_tree_ensure() instead.");
    mpack_log("filling to reserve %i bytes\n", (int)bytes);

    // if the necessary bytes would put us over the maximum tree
    // size, fail right away.
    // TODO: check for overflow?
    if (tree->data_length + bytes > tree->max_size) {
        mpack_tree_flag_error(tree, mpack_error_too_big);
        return false;
    }

    // we'll need a read function to fetch more data. if there's
    // no read function, the data should contain an entire message
    // (or messages), so we flag it as invalid.
    if (tree->read_fn == NULL) {
        mpack_log("tree has no read function!\n");
        mpack_tree_flag_error(tree, mpack_error_invalid);
        return false;
    }

    // expand the buffer if needed
    if (tree->data_length + bytes > tree->buffer_capacity) {

        // TODO: check for overflow?
        size_t new_capacity = (tree->buffer_capacity == 0) ? MPACK_BUFFER_SIZE : tree->buffer_capacity;
        while (new_capacity < tree->data_length + bytes)
            new_capacity *= 2;
        if (new_capacity > tree->max_size)
            new_capacity = tree->max_size;

        mpack_log("expanding buffer from %i to %i\n", (int)tree->buffer_capacity, (int)new_capacity);

        char* new_buffer;
        if (tree->buffer == NULL)
            new_buffer = (char*)MPACK_MALLOC(new_capacity);
        else
            new_buffer = (char*)mpack_realloc(tree->buffer, tree->data_length, new_capacity);

        if (new_buffer == NULL) {
            mpack_tree_flag_error(tree, mpack_error_memory);
            return false;
        }

        tree->data = new_buffer;
        tree->buffer = new_buffer;
        tree->buffer_capacity = new_capacity;
    }

    // request as much data as possible, looping until we have
    // all the data we need
    do {
        size_t read = tree->read_fn(tree, tree->buffer + tree->data_length, tree->buffer_capacity - tree->data_length);

        // If the fill function encounters an error, it should flag an error on
        // the tree.
        if (mpack_tree_error(tree) != mpack_ok)
            return false;

        // We guard against fill functions that return -1 just in case.
        if (read == (size_t)(-1)) {
            mpack_tree_flag_error(tree, mpack_error_io);
            return false;
        }

        // If the fill function returns 0, the data is not available yet. We
        // return false to stop parsing the current node.
        if (read == 0) {
            mpack_log("not enough data.\n");
            return false;
        }

        mpack_log("read %u more bytes\n", (uint32_t)read);
        tree->data_length += read;
        tree->parser.possible_nodes_left += read;
    } while (tree->parser.possible_nodes_left < bytes);

    return true;
}
#endif

/*
 * Ensures there are enough additional bytes in the tree for the current node
 * (including reserved bytes for the children of this node, and in addition to
 * the reserved bytes for children of previous compound nodes), reading more
 * data if needed.
 *
 * extra_bytes is the number of additional bytes to reserve for the current
 * node beyond the type byte (since one byte is already reserved for each node
 * by its parent array or map.)
 *
 * This may reallocate the tree, which means the tree->data pointer may change!
 *
 * Returns false if not enough bytes could be read.
 */
MPACK_STATIC_INLINE bool mpack_tree_reserve_bytes(mpack_tree_t* tree, size_t extra_bytes) {
    mpack_assert(tree->parser.state == mpack_tree_parse_state_in_progress);

    // We guard against overflow here. A compound type could declare more than
    // MPACK_UINT32_MAX contents which overflows SIZE_MAX on 32-bit platforms. We
    // flag mpack_error_invalid instead of mpack_error_too_big since it's far
    // more likely that the message is corrupt than that the data is valid but
    // not parseable on this architecture (see test_read_node_possible() in
    // test-node.c .)
    if ((uint64_t)tree->parser.current_node_reserved + (uint64_t)extra_bytes > SIZE_MAX) {
        mpack_tree_flag_error(tree, mpack_error_invalid);
        return false;
    }

    tree->parser.current_node_reserved += extra_bytes;

    // Note that possible_nodes_left already accounts for reserved bytes for
    // children of previous compound nodes. So even if there are hundreds of
    // bytes left in the buffer, we might need to read anyway.
    if (tree->parser.current_node_reserved <= tree->parser.possible_nodes_left)
        return true;

    #ifdef MPACK_MALLOC
    return mpack_tree_reserve_fill(tree);
    #else
    return false;
    #endif
}

MPACK_STATIC_INLINE size_t mpack_tree_parser_stack_capacity(mpack_tree_t* tree) {
    #ifdef MPACK_MALLOC
    return tree->parser.stack_capacity;
    #else
    return sizeof(tree->parser.stack) / sizeof(tree->parser.stack[0]);
    #endif
}

static bool mpack_tree_push_stack(mpack_tree_t* tree, mpack_node_data_t* first_child, size_t total) {
    mpack_tree_parser_t* parser = &tree->parser;
    mpack_assert(parser->state == mpack_tree_parse_state_in_progress);

    // No need to push empty containers
    if (total == 0)
        return true;

    // Make sure we have enough room in the stack
    if (parser->level + 1 == mpack_tree_parser_stack_capacity(tree)) {
        #ifdef MPACK_MALLOC
        size_t new_capacity = parser->stack_capacity * 2;
        mpack_log("growing parse stack to capacity %i\n", (int)new_capacity);

        // Replace the stack-allocated parsing stack
        if (!parser->stack_owned) {
            mpack_level_t* new_stack = (mpack_level_t*)MPACK_MALLOC(sizeof(mpack_level_t) * new_capacity);
            if (!new_stack) {
                mpack_tree_flag_error(tree, mpack_error_memory);
                return false;
            }
            mpack_memcpy(new_stack, parser->stack, sizeof(mpack_level_t) * parser->stack_capacity);
            parser->stack = new_stack;
            parser->stack_owned = true;

        // Realloc the allocated parsing stack
        } else {
            mpack_level_t* new_stack = (mpack_level_t*)mpack_realloc(parser->stack,
                    sizeof(mpack_level_t) * parser->stack_capacity, sizeof(mpack_level_t) * new_capacity);
            if (!new_stack) {
                mpack_tree_flag_error(tree, mpack_error_memory);
                return false;
            }
            parser->stack = new_stack;
        }
        parser->stack_capacity = new_capacity;
        #else
        mpack_tree_flag_error(tree, mpack_error_too_big);
        return false;
        #endif
    }

    // Push the contents of this node onto the parsing stack
    ++parser->level;
    parser->stack[parser->level].child = first_child;
    parser->stack[parser->level].left = total;
    return true;
}

static bool mpack_tree_parse_children(mpack_tree_t* tree, mpack_node_data_t* node) {
    mpack_tree_parser_t* parser = &tree->parser;
    mpack_assert(parser->state == mpack_tree_parse_state_in_progress);

    mpack_type_t type = node->type;
    size_t total = node->len;

    // Calculate total elements to read
    if (type == mpack_type_map) {
        if ((uint64_t)total * 2 > SIZE_MAX) {
            mpack_tree_flag_error(tree, mpack_error_too_big);
            return false;
        }
        total *= 2;
    }

    // Make sure we are under our total node limit (TODO can this overflow?)
    tree->node_count += total;
    if (tree->node_count > tree->max_nodes) {
        mpack_tree_flag_error(tree, mpack_error_too_big);
        return false;
    }

    // Each node is at least one byte. Count these bytes now to make
    // sure there is enough data left.
    if (!mpack_tree_reserve_bytes(tree, total))
        return false;

    // If there are enough nodes left in the current page, no need to grow
    if (total <= parser->nodes_left) {
        node->value.children = parser->nodes;
        parser->nodes += total;
        parser->nodes_left -= total;

    } else {

        #ifdef MPACK_MALLOC

        // We can't grow if we're using a fixed pool (i.e. we didn't start with a page)
        if (!tree->next) {
            mpack_tree_flag_error(tree, mpack_error_too_big);
            return false;
        }

        // Otherwise we need to grow, and the node's children need to be contiguous.
        // This is a heuristic to decide whether we should waste the remaining space
        // in the current page and start a new one, or give the children their
        // own page. With a fraction of 1/8, this causes at most 12% additional
        // waste. Note that reducing this too much causes less cache coherence and
        // more malloc() overhead due to smaller allocations, so there's a tradeoff
        // here. This heuristic could use some improvement, especially with custom
        // page sizes.

        mpack_tree_page_t* page;

        if (total > MPACK_NODES_PER_PAGE || parser->nodes_left > MPACK_NODES_PER_PAGE / 8) {
            // TODO: this should check for overflow
            page = (mpack_tree_page_t*)MPACK_MALLOC(
                    sizeof(mpack_tree_page_t) + sizeof(mpack_node_data_t) * (total - 1));
            if (page == NULL) {
                mpack_tree_flag_error(tree, mpack_error_memory);
                return false;
            }
            mpack_log("allocated seperate page %p for %i children, %i left in page of %i total\n",
                    (void*)page, (int)total, (int)parser->nodes_left, (int)MPACK_NODES_PER_PAGE);

            node->value.children = page->nodes;

        } else {
            page = (mpack_tree_page_t*)MPACK_MALLOC(MPACK_PAGE_ALLOC_SIZE);
            if (page == NULL) {
                mpack_tree_flag_error(tree, mpack_error_memory);
                return false;
            }
            mpack_log("allocated new page %p for %i children, wasting %i in page of %i total\n",
                    (void*)page, (int)total, (int)parser->nodes_left, (int)MPACK_NODES_PER_PAGE);

            node->value.children = page->nodes;
            parser->nodes = page->nodes + total;
            parser->nodes_left = MPACK_NODES_PER_PAGE - total;
        }

        page->next = tree->next;
        tree->next = page;

        #else
        // We can't grow if we don't have an allocator
        mpack_tree_flag_error(tree, mpack_error_too_big);
        return false;
        #endif
    }

    return mpack_tree_push_stack(tree, node->value.children, total);
}

static bool mpack_tree_parse_bytes(mpack_tree_t* tree, mpack_node_data_t* node) {
    node->value.offset = tree->size + tree->parser.current_node_reserved + 1;
    return mpack_tree_reserve_bytes(tree, node->len);
}

#if MPACK_EXTENSIONS
static bool mpack_tree_parse_ext(mpack_tree_t* tree, mpack_node_data_t* node) {
    // reserve space for exttype
    tree->parser.current_node_reserved += sizeof(int8_t);
    node->type = mpack_type_ext;
    return mpack_tree_parse_bytes(tree, node);
}
#endif

static bool mpack_tree_parse_node_contents(mpack_tree_t* tree, mpack_node_data_t* node) {
    mpack_assert(tree->parser.state == mpack_tree_parse_state_in_progress);
    mpack_assert(node != NULL, "null node?");

    // read the type. we've already accounted for this byte in
    // possible_nodes_left, so we already know it is in bounds, and we don't
    // need to reserve it for this node.
    mpack_assert(tree->data_length > tree->size);
    uint8_t type = mpack_load_u8(tree->data + tree->size);
    mpack_log("node type %x\n", type);
    tree->parser.current_node_reserved = 0;

    // as with mpack_read_tag(), the fastest way to parse a node is to switch
    // on the first byte, and to explicitly list every possible byte. we switch
    // on the first four bits in size-optimized builds.

    #if MPACK_OPTIMIZE_FOR_SIZE
    switch (type >> 4) {

        // positive fixnum
        case 0x0: case 0x1: case 0x2: case 0x3:
        case 0x4: case 0x5: case 0x6: case 0x7:
            node->type = mpack_type_uint;
            node->value.u = type;
            return true;

        // negative fixnum
        case 0xe: case 0xf:
            node->type = mpack_type_int;
            node->value.i = (int8_t)type;
            return true;

        // fixmap
        case 0x8:
            node->type = mpack_type_map;
            node->len = (uint32_t)(type & ~0xf0);
            return mpack_tree_parse_children(tree, node);

        // fixarray
        case 0x9:
            node->type = mpack_type_array;
            node->len = (uint32_t)(type & ~0xf0);
            return mpack_tree_parse_children(tree, node);

        // fixstr
        case 0xa: case 0xb:
            node->type = mpack_type_str;
            node->len = (uint32_t)(type & ~0xe0);
            return mpack_tree_parse_bytes(tree, node);

        // not one of the common infix types
        default:
            break;
    }
    #endif

    switch (type) {

        #if !MPACK_OPTIMIZE_FOR_SIZE
        // positive fixnum
        case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05: case 0x06: case 0x07:
        case 0x08: case 0x09: case 0x0a: case 0x0b: case 0x0c: case 0x0d: case 0x0e: case 0x0f:
        case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15: case 0x16: case 0x17:
        case 0x18: case 0x19: case 0x1a: case 0x1b: case 0x1c: case 0x1d: case 0x1e: case 0x1f:
        case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25: case 0x26: case 0x27:
        case 0x28: case 0x29: case 0x2a: case 0x2b: case 0x2c: case 0x2d: case 0x2e: case 0x2f:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37:
        case 0x38: case 0x39: case 0x3a: case 0x3b: case 0x3c: case 0x3d: case 0x3e: case 0x3f:
        case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4a: case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f:
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f:
        case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: case 0x67:
        case 0x68: case 0x69: case 0x6a: case 0x6b: case 0x6c: case 0x6d: case 0x6e: case 0x6f:
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7a: case 0x7b: case 0x7c: case 0x7d: case 0x7e: case 0x7f:
            node->type = mpack_type_uint;
            node->value.u = type;
            return true;

        // negative fixnum
        case 0xe0: case 0xe1: case 0xe2: case 0xe3: case 0xe4: case 0xe5: case 0xe6: case 0xe7:
        case 0xe8: case 0xe9: case 0xea: case 0xeb: case 0xec: case 0xed: case 0xee: case 0xef:
        case 0xf0: case 0xf1: case 0xf2: case 0xf3: case 0xf4: case 0xf5: case 0xf6: case 0xf7:
        case 0xf8: case 0xf9: case 0xfa: case 0xfb: case 0xfc: case 0xfd: case 0xfe: case 0xff:
            node->type = mpack_type_int;
            node->value.i = (int8_t)type;
            return true;

        // fixmap
        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8a: case 0x8b: case 0x8c: case 0x8d: case 0x8e: case 0x8f:
            node->type = mpack_type_map;
            node->len = (uint32_t)(type & ~0xf0);
            return mpack_tree_parse_children(tree, node);

        // fixarray
        case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9a: case 0x9b: case 0x9c: case 0x9d: case 0x9e: case 0x9f:
            node->type = mpack_type_array;
            node->len = (uint32_t)(type & ~0xf0);
            return mpack_tree_parse_children(tree, node);

        // fixstr
        case 0xa0: case 0xa1: case 0xa2: case 0xa3: case 0xa4: case 0xa5: case 0xa6: case 0xa7:
        case 0xa8: case 0xa9: case 0xaa: case 0xab: case 0xac: case 0xad: case 0xae: case 0xaf:
        case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4: case 0xb5: case 0xb6: case 0xb7:
        case 0xb8: case 0xb9: case 0xba: case 0xbb: case 0xbc: case 0xbd: case 0xbe: case 0xbf:
            node->type = mpack_type_str;
            node->len = (uint32_t)(type & ~0xe0);
            return mpack_tree_parse_bytes(tree, node);
        #endif

        // nil
        case 0xc0:
            node->type = mpack_type_nil;
            return true;

        // bool
        case 0xc2: case 0xc3:
            node->type = mpack_type_bool;
            node->value.b = type & 1;
            return true;

        // bin8
        case 0xc4:
            node->type = mpack_type_bin;
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint8_t)))
                return false;
            node->len = mpack_load_u8(tree->data + tree->size + 1);
            return mpack_tree_parse_bytes(tree, node);

        // bin16
        case 0xc5:
            node->type = mpack_type_bin;
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint16_t)))
                return false;
            node->len = mpack_load_u16(tree->data + tree->size + 1);
            return mpack_tree_parse_bytes(tree, node);

        // bin32
        case 0xc6:
            node->type = mpack_type_bin;
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint32_t)))
                return false;
            node->len = mpack_load_u32(tree->data + tree->size + 1);
            return mpack_tree_parse_bytes(tree, node);

        #if MPACK_EXTENSIONS
        // ext8
        case 0xc7:
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint8_t)))
                return false;
            node->len = mpack_load_u8(tree->data + tree->size + 1);
            return mpack_tree_parse_ext(tree, node);

        // ext16
        case 0xc8:
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint16_t)))
                return false;
            node->len = mpack_load_u16(tree->data + tree->size + 1);
            return mpack_tree_parse_ext(tree, node);

        // ext32
        case 0xc9:
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint32_t)))
                return false;
            node->len = mpack_load_u32(tree->data + tree->size + 1);
            return mpack_tree_parse_ext(tree, node);
        #endif

        // float
        case 0xca:
            #if MPACK_FLOAT
            if (!mpack_tree_reserve_bytes(tree, sizeof(float)))
                return false;
            node->value.f = mpack_load_float(tree->data + tree->size + 1);
            #else
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint32_t)))
                return false;
            node->value.f = mpack_load_u32(tree->data + tree->size + 1);
            #endif
            node->type = mpack_type_float;
            return true;

        // double
        case 0xcb:
            #if MPACK_DOUBLE
            if (!mpack_tree_reserve_bytes(tree, sizeof(double)))
                return false;
            node->value.d = mpack_load_double(tree->data + tree->size + 1);
            #else
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint64_t)))
                return false;
            node->value.d = mpack_load_u64(tree->data + tree->size + 1);
            #endif
            node->type = mpack_type_double;
            return true;

        // uint8
        case 0xcc:
            node->type = mpack_type_uint;
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint8_t)))
                return false;
            node->value.u = mpack_load_u8(tree->data + tree->size + 1);
            return true;

        // uint16
        case 0xcd:
            node->type = mpack_type_uint;
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint16_t)))
                return false;
            node->value.u = mpack_load_u16(tree->data + tree->size + 1);
            return true;

        // uint32
        case 0xce:
            node->type = mpack_type_uint;
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint32_t)))
                return false;
            node->value.u = mpack_load_u32(tree->data + tree->size + 1);
            return true;

        // uint64
        case 0xcf:
            node->type = mpack_type_uint;
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint64_t)))
                return false;
            node->value.u = mpack_load_u64(tree->data + tree->size + 1);
            return true;

        // int8
        case 0xd0:
            node->type = mpack_type_int;
            if (!mpack_tree_reserve_bytes(tree, sizeof(int8_t)))
                return false;
            node->value.i = mpack_load_i8(tree->data + tree->size + 1);
            return true;

        // int16
        case 0xd1:
            node->type = mpack_type_int;
            if (!mpack_tree_reserve_bytes(tree, sizeof(int16_t)))
                return false;
            node->value.i = mpack_load_i16(tree->data + tree->size + 1);
            return true;

        // int32
        case 0xd2:
            node->type = mpack_type_int;
            if (!mpack_tree_reserve_bytes(tree, sizeof(int32_t)))
                return false;
            node->value.i = mpack_load_i32(tree->data + tree->size + 1);
            return true;

        // int64
        case 0xd3:
            node->type = mpack_type_int;
            if (!mpack_tree_reserve_bytes(tree, sizeof(int64_t)))
                return false;
            node->value.i = mpack_load_i64(tree->data + tree->size + 1);
            return true;

        #if MPACK_EXTENSIONS
        // fixext1
        case 0xd4:
            node->len = 1;
            return mpack_tree_parse_ext(tree, node);

        // fixext2
        case 0xd5:
            node->len = 2;
            return mpack_tree_parse_ext(tree, node);

        // fixext4
        case 0xd6:
            node->len = 4;
            return mpack_tree_parse_ext(tree, node);

        // fixext8
        case 0xd7:
            node->len = 8;
            return mpack_tree_parse_ext(tree, node);

        // fixext16
        case 0xd8:
            node->len = 16;
            return mpack_tree_parse_ext(tree, node);
        #endif

        // str8
        case 0xd9:
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint8_t)))
                return false;
            node->len = mpack_load_u8(tree->data + tree->size + 1);
            node->type = mpack_type_str;
            return mpack_tree_parse_bytes(tree, node);

        // str16
        case 0xda:
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint16_t)))
                return false;
            node->len = mpack_load_u16(tree->data + tree->size + 1);
            node->type = mpack_type_str;
            return mpack_tree_parse_bytes(tree, node);

        // str32
        case 0xdb:
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint32_t)))
                return false;
            node->len = mpack_load_u32(tree->data + tree->size + 1);
            node->type = mpack_type_str;
            return mpack_tree_parse_bytes(tree, node);

        // array16
        case 0xdc:
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint16_t)))
                return false;
            node->len = mpack_load_u16(tree->data + tree->size + 1);
            node->type = mpack_type_array;
            return mpack_tree_parse_children(tree, node);

        // array32
        case 0xdd:
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint32_t)))
                return false;
            node->len = mpack_load_u32(tree->data + tree->size + 1);
            node->type = mpack_type_array;
            return mpack_tree_parse_children(tree, node);

        // map16
        case 0xde:
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint16_t)))
                return false;
            node->len = mpack_load_u16(tree->data + tree->size + 1);
            node->type = mpack_type_map;
            return mpack_tree_parse_children(tree, node);

        // map32
        case 0xdf:
            if (!mpack_tree_reserve_bytes(tree, sizeof(uint32_t)))
                return false;
            node->len = mpack_load_u32(tree->data + tree->size + 1);
            node->type = mpack_type_map;
            return mpack_tree_parse_children(tree, node);

        // reserved
        case 0xc1:
            mpack_tree_flag_error(tree, mpack_error_invalid);
            return false;

        #if !MPACK_EXTENSIONS
        // ext
        case 0xc7: // fallthrough
        case 0xc8: // fallthrough
        case 0xc9: // fallthrough
        // fixext
        case 0xd4: // fallthrough
        case 0xd5: // fallthrough
        case 0xd6: // fallthrough
        case 0xd7: // fallthrough
        case 0xd8:
            mpack_tree_flag_error(tree, mpack_error_unsupported);
            return false;
        #endif

        #if MPACK_OPTIMIZE_FOR_SIZE
        // any other bytes should have been handled by the infix switch
        default:
            break;
        #endif
    }

    mpack_assert(0, "unreachable");
    return false;
}

static bool mpack_tree_parse_node(mpack_tree_t* tree, mpack_node_data_t* node) {
    mpack_log("parsing a node at position %i in level %i\n",
            (int)tree->size, (int)tree->parser.level);

    if (!mpack_tree_parse_node_contents(tree, node)) {
        mpack_log("node parsing returned false\n");
        return false;
    }

    tree->parser.possible_nodes_left -= tree->parser.current_node_reserved;

    // The reserve for the current node does not include the initial byte
    // previously reserved as part of its parent.
    size_t node_size = tree->parser.current_node_reserved + 1;

    // If the parsed type is a map or array, the reserve includes one byte for
    // each child. We want to subtract these out of possible_nodes_left, but
    // not out of the current size of the tree.
    if (node->type == mpack_type_array)
        node_size -= node->len;
    else if (node->type == mpack_type_map)
        node_size -= node->len * 2;
    tree->size += node_size;

    mpack_log("parsed a node of type %s of %i bytes and "
            "%i additional bytes reserved for children.\n",
            mpack_type_to_string(node->type), (int)node_size,
            (int)tree->parser.current_node_reserved + 1 - (int)node_size);

    return true;
}

/*
 * We read nodes in a loop instead of recursively for maximum performance. The
 * stack holds the amount of children left to read in each level of the tree.
 * Parsing can pause and resume when more data becomes available.
 */
static bool mpack_tree_continue_parsing(mpack_tree_t* tree) {
    if (mpack_tree_error(tree) != mpack_ok)
        return false;

    mpack_tree_parser_t* parser = &tree->parser;
    mpack_assert(parser->state == mpack_tree_parse_state_in_progress);
    mpack_log("parsing tree elements, %i bytes in buffer\n", (int)tree->data_length);

    // we loop parsing nodes until the parse stack is empty. we break
    // by returning out of the function.
    while (true) {
        mpack_node_data_t* node = parser->stack[parser->level].child;
        size_t level = parser->level;
        if (!mpack_tree_parse_node(tree, node))
            return false;
        --parser->stack[level].left;
        ++parser->stack[level].child;

        mpack_assert(mpack_tree_error(tree) == mpack_ok,
                "mpack_tree_parse_node() should have returned false due to error!");

        // pop empty stack levels, exiting the outer loop when the stack is empty.
        // (we could tail-optimize containers by pre-emptively popping empty
        // stack levels before reading the new element, this way we wouldn't
        // have to loop. but we eventually want to use the parse stack to give
        // better error messages that contain the location of the error, so
        // it needs to be complete.)
        while (parser->stack[parser->level].left == 0) {
            if (parser->level == 0)
                return true;
            --parser->level;
        }
    }
}

static void mpack_tree_cleanup(mpack_tree_t* tree) {
    MPACK_UNUSED(tree);

    #ifdef MPACK_MALLOC
    if (tree->parser.stack_owned) {
        MPACK_FREE(tree->parser.stack);
        tree->parser.stack = NULL;
        tree->parser.stack_owned = false;
    }

    mpack_tree_page_t* page = tree->next;
    while (page != NULL) {
        mpack_tree_page_t* next = page->next;
        mpack_log("freeing page %p\n", (void*)page);
        MPACK_FREE(page);
        page = next;
    }
    tree->next = NULL;
    #endif
}

static bool mpack_tree_parse_start(mpack_tree_t* tree) {
    if (mpack_tree_error(tree) != mpack_ok)
        return false;

    mpack_tree_parser_t* parser = &tree->parser;
    mpack_assert(parser->state != mpack_tree_parse_state_in_progress,
            "previous parsing was not finished!");

    if (parser->state == mpack_tree_parse_state_parsed)
        mpack_tree_cleanup(tree);

    mpack_log("starting parse\n");
    tree->parser.state = mpack_tree_parse_state_in_progress;
    tree->parser.current_node_reserved = 0;

    // check if we previously parsed a tree
    if (tree->size > 0) {
        #ifdef MPACK_MALLOC
        // if we're buffered, move the remaining data back to the
        // start of the buffer
        // TODO: This is not ideal performance-wise. We should only move data
        // when we need to call the fill function.
        // TODO: We could consider shrinking the buffer here, especially if we
        // determine that the fill function is providing less than a quarter of
        // the buffer size or if messages take up less than a quarter of the
        // buffer size. Maybe this should be configurable.
        if (tree->buffer != NULL) {
            mpack_memmove(tree->buffer, tree->buffer + tree->size, tree->data_length - tree->size);
        }
        else
        #endif
        // otherwise advance past the parsed data
        {
            tree->data += tree->size;
        }
        tree->data_length -= tree->size;
        tree->size = 0;
        tree->node_count = 0;
    }

    // make sure we have at least one byte available before allocating anything
    parser->possible_nodes_left = tree->data_length;
    if (!mpack_tree_reserve_bytes(tree, sizeof(uint8_t))) {
        tree->parser.state = mpack_tree_parse_state_not_started;
        return false;
    }
    mpack_log("parsing tree at %p starting with byte %x\n", tree->data, (uint8_t)tree->data[0]);
    parser->possible_nodes_left -= 1;
    tree->node_count = 1;

    #ifdef MPACK_MALLOC
    parser->stack = parser->stack_local;
    parser->stack_owned = false;
    parser->stack_capacity = sizeof(parser->stack_local) / sizeof(*parser->stack_local);

    if (tree->pool == NULL) {

        // allocate first page
        mpack_tree_page_t* page = (mpack_tree_page_t*)MPACK_MALLOC(MPACK_PAGE_ALLOC_SIZE);
        mpack_log("allocated initial page %p of size %i count %i\n",
                (void*)page, (int)MPACK_PAGE_ALLOC_SIZE, (int)MPACK_NODES_PER_PAGE);
        if (page == NULL) {
            tree->error = mpack_error_memory;
            return false;
        }
        page->next = NULL;
        tree->next = page;

        parser->nodes = page->nodes;
        parser->nodes_left = MPACK_NODES_PER_PAGE;
    }
    else
    #endif
    {
        // otherwise use the provided pool
        mpack_assert(tree->pool != NULL, "no pool provided?");
        parser->nodes = tree->pool;
        parser->nodes_left = tree->pool_count;
    }

    tree->root = parser->nodes;
    ++parser->nodes;
    --parser->nodes_left;

    parser->level = 0;
    parser->stack[0].child = tree->root;
    parser->stack[0].left = 1;

    return true;
}

void mpack_tree_parse(mpack_tree_t* tree) {
    if (mpack_tree_error(tree) != mpack_ok)
        return;

    if (tree->parser.state != mpack_tree_parse_state_in_progress) {
        if (!mpack_tree_parse_start(tree)) {
            mpack_tree_flag_error(tree, (tree->read_fn == NULL) ?
                    mpack_error_invalid : mpack_error_io);
            return;
        }
    }

    if (!mpack_tree_continue_parsing(tree)) {
        if (mpack_tree_error(tree) != mpack_ok)
            return;

        // We're parsing synchronously on a blocking fill function. If we
        // didn't completely finish parsing the tree, it's an error.
        mpack_log("tree parsing incomplete. flagging error.\n");
        mpack_tree_flag_error(tree, (tree->read_fn == NULL) ?
                mpack_error_invalid : mpack_error_io);
        return;
    }

    mpack_assert(mpack_tree_error(tree) == mpack_ok);
    mpack_assert(tree->parser.level == 0);
    tree->parser.state = mpack_tree_parse_state_parsed;
    mpack_log("parsed tree of %i bytes, %i bytes left\n", (int)tree->size, (int)tree->parser.possible_nodes_left);
    mpack_log("%i nodes in final page\n", (int)tree->parser.nodes_left);
}

bool mpack_tree_try_parse(mpack_tree_t* tree) {
    if (mpack_tree_error(tree) != mpack_ok)
        return false;

    if (tree->parser.state != mpack_tree_parse_state_in_progress)
        if (!mpack_tree_parse_start(tree))
            return false;

    if (!mpack_tree_continue_parsing(tree))
        return false;

    mpack_assert(mpack_tree_error(tree) == mpack_ok);
    mpack_assert(tree->parser.level == 0);
    tree->parser.state = mpack_tree_parse_state_parsed;
    return true;
}



/*
 * Tree functions
 */

mpack_node_t mpack_tree_root(mpack_tree_t* tree) {
    if (mpack_tree_error(tree) != mpack_ok)
        return mpack_tree_nil_node(tree);

    // We check that a tree was parsed successfully and assert if not. You must
    // call mpack_tree_parse() (or mpack_tree_try_parse() with a success
    // result) in order to access the root node.
    if (tree->parser.state != mpack_tree_parse_state_parsed) {
        mpack_break("Tree has not been parsed! "
                "Did you call mpack_tree_parse() or mpack_tree_try_parse()?");
        mpack_tree_flag_error(tree, mpack_error_bug);
        return mpack_tree_nil_node(tree);
    }

    return mpack_node(tree, tree->root);
}

static void mpack_tree_init_clear(mpack_tree_t* tree) {
    mpack_memset(tree, 0, sizeof(*tree));
    tree->nil_node.type = mpack_type_nil;
    tree->missing_node.type = mpack_type_missing;
    tree->max_size = SIZE_MAX;
    tree->max_nodes = SIZE_MAX;
}

#ifdef MPACK_MALLOC
void mpack_tree_init_data(mpack_tree_t* tree, const char* data, size_t length) {
    mpack_tree_init_clear(tree);

    MPACK_STATIC_ASSERT(MPACK_NODE_PAGE_SIZE >= sizeof(mpack_tree_page_t),
            "MPACK_NODE_PAGE_SIZE is too small");

    MPACK_STATIC_ASSERT(MPACK_PAGE_ALLOC_SIZE <= MPACK_NODE_PAGE_SIZE,
            "incorrect page rounding?");

    tree->data = data;
    tree->data_length = length;
    tree->pool = NULL;
    tree->pool_count = 0;
    tree->next = NULL;

    mpack_log("===========================\n");
    mpack_log("initializing tree with data of size %i\n", (int)length);
}
#endif

void mpack_tree_init_pool(mpack_tree_t* tree, const char* data, size_t length,
        mpack_node_data_t* node_pool, size_t node_pool_count)
{
    mpack_tree_init_clear(tree);
    #ifdef MPACK_MALLOC
    tree->next = NULL;
    #endif

    if (node_pool_count == 0) {
        mpack_break("initial page has no nodes!");
        mpack_tree_flag_error(tree, mpack_error_bug);
        return;
    }

    tree->data = data;
    tree->data_length = length;
    tree->pool = node_pool;
    tree->pool_count = node_pool_count;

    mpack_log("===========================\n");
    mpack_log("initializing tree with data of size %i and pool of count %i\n",
            (int)length, (int)node_pool_count);
}

void mpack_tree_init_error(mpack_tree_t* tree, mpack_error_t error) {
    mpack_tree_init_clear(tree);
    tree->error = error;

    mpack_log("===========================\n");
    mpack_log("initializing tree error state %i\n", (int)error);
}

#ifdef MPACK_MALLOC
void mpack_tree_init_stream(mpack_tree_t* tree, mpack_tree_read_t read_fn, void* context,
        size_t max_message_size, size_t max_message_nodes) {
    mpack_tree_init_clear(tree);

    tree->read_fn = read_fn;
    tree->context = context;

    mpack_tree_set_limits(tree, max_message_size, max_message_nodes);
    tree->max_size = max_message_size;
    tree->max_nodes = max_message_nodes;

    mpack_log("===========================\n");
    mpack_log("initializing tree with stream, max size %i max nodes %i\n",
            (int)max_message_size, (int)max_message_nodes);
}
#endif

void mpack_tree_set_limits(mpack_tree_t* tree, size_t max_message_size, size_t max_message_nodes) {
    mpack_assert(max_message_size > 0);
    mpack_assert(max_message_nodes > 0);
    tree->max_size = max_message_size;
    tree->max_nodes = max_message_nodes;
}

#if MPACK_STDIO
typedef struct mpack_file_tree_t {
    char* data;
    size_t size;
    char buffer[MPACK_BUFFER_SIZE];
} mpack_file_tree_t;

static void mpack_file_tree_teardown(mpack_tree_t* tree) {
    mpack_file_tree_t* file_tree = (mpack_file_tree_t*)tree->context;
    MPACK_FREE(file_tree->data);
    MPACK_FREE(file_tree);
}

static bool mpack_file_tree_read(mpack_tree_t* tree, mpack_file_tree_t* file_tree, FILE* file, size_t max_bytes) {

    // get the file size
    errno = 0;
    int error = 0;
    fseek(file, 0, SEEK_END);
    error |= errno;
    long size = ftell(file);
    error |= errno;
    fseek(file, 0, SEEK_SET);
    error |= errno;

    // check for errors
    if (error != 0 || size < 0) {
        mpack_tree_init_error(tree, mpack_error_io);
        return false;
    }
    if (size == 0) {
        mpack_tree_init_error(tree, mpack_error_invalid);
        return false;
    }

    // make sure the size is less than max_bytes
    // (this mess exists to safely convert between long and size_t regardless of their widths)
    if (max_bytes != 0 && (((uint64_t)LONG_MAX > (uint64_t)SIZE_MAX && size > (long)SIZE_MAX) || (size_t)size > max_bytes)) {
        mpack_tree_init_error(tree, mpack_error_too_big);
        return false;
    }

    // allocate data
    file_tree->data = (char*)MPACK_MALLOC((size_t)size);
    if (file_tree->data == NULL) {
        mpack_tree_init_error(tree, mpack_error_memory);
        return false;
    }

    // read the file
    long total = 0;
    while (total < size) {
        size_t read = fread(file_tree->data + total, 1, (size_t)(size - total), file);
        if (read <= 0) {
            mpack_tree_init_error(tree, mpack_error_io);
            MPACK_FREE(file_tree->data);
            return false;
        }
        total += (long)read;
    }

    file_tree->size = (size_t)size;
    return true;
}

static bool mpack_tree_file_check_max_bytes(mpack_tree_t* tree, size_t max_bytes) {

    // the C STDIO family of file functions use long (e.g. ftell)
    if (max_bytes > LONG_MAX) {
        mpack_break("max_bytes of %" PRIu64 " is invalid, maximum is LONG_MAX", (uint64_t)max_bytes);
        mpack_tree_init_error(tree, mpack_error_bug);
        return false;
    }

    return true;
}

static void mpack_tree_init_stdfile_noclose(mpack_tree_t* tree, FILE* stdfile, size_t max_bytes) {

    // allocate file tree
    mpack_file_tree_t* file_tree = (mpack_file_tree_t*) MPACK_MALLOC(sizeof(mpack_file_tree_t));
    if (file_tree == NULL) {
        mpack_tree_init_error(tree, mpack_error_memory);
        return;
    }

    // read all data
    if (!mpack_file_tree_read(tree, file_tree, stdfile, max_bytes)) {
        MPACK_FREE(file_tree);
        return;
    }

    mpack_tree_init_data(tree, file_tree->data, file_tree->size);
    mpack_tree_set_context(tree, file_tree);
    mpack_tree_set_teardown(tree, mpack_file_tree_teardown);
}

void mpack_tree_init_stdfile(mpack_tree_t* tree, FILE* stdfile, size_t max_bytes, bool close_when_done) {
    if (!mpack_tree_file_check_max_bytes(tree, max_bytes))
        return;

    mpack_tree_init_stdfile_noclose(tree, stdfile, max_bytes);

    if (close_when_done)
        fclose(stdfile);
}

void mpack_tree_init_filename(mpack_tree_t* tree, const char* filename, size_t max_bytes) {
    if (!mpack_tree_file_check_max_bytes(tree, max_bytes))
        return;

    // open the file
    FILE* file = fopen(filename, "rb");
    if (!file) {
        mpack_tree_init_error(tree, mpack_error_io);
        return;
    }

    mpack_tree_init_stdfile(tree, file, max_bytes, true);
}
#endif

mpack_error_t mpack_tree_destroy(mpack_tree_t* tree) {
    mpack_tree_cleanup(tree);

    #ifdef MPACK_MALLOC
    if (tree->buffer)
        MPACK_FREE(tree->buffer);
    #endif

    if (tree->teardown)
        tree->teardown(tree);
    tree->teardown = NULL;

    return tree->error;
}

void mpack_tree_flag_error(mpack_tree_t* tree, mpack_error_t error) {
    if (tree->error == mpack_ok) {
        mpack_log("tree %p setting error %i: %s\n", (void*)tree, (int)error, mpack_error_to_string(error));
        tree->error = error;
        if (tree->error_fn)
            tree->error_fn(tree, error);
    }

}



/*
 * Node misc functions
 */

void mpack_node_flag_error(mpack_node_t node, mpack_error_t error) {
    mpack_tree_flag_error(node.tree, error);
}

mpack_tag_t mpack_node_tag(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return mpack_tag_nil();

    mpack_tag_t tag = MPACK_TAG_ZERO;

    tag.type = node.data->type;
    switch (node.data->type) {
        case mpack_type_missing:
            // If a node is missing, I don't know if it makes sense to ask for
            // a tag for it. We'll return a missing tag to match the missing
            // node I guess, but attempting to use the tag for anything (like
            // writing it for example) will flag mpack_error_bug.
            break;
        case mpack_type_nil:                                            break;
        case mpack_type_bool:    tag.v.b = node.data->value.b;          break;
        case mpack_type_float:   tag.v.f = node.data->value.f;          break;
        case mpack_type_double:  tag.v.d = node.data->value.d;          break;
        case mpack_type_int:     tag.v.i = node.data->value.i;          break;
        case mpack_type_uint:    tag.v.u = node.data->value.u;          break;

        case mpack_type_str:     tag.v.l = node.data->len;     break;
        case mpack_type_bin:     tag.v.l = node.data->len;     break;

        #if MPACK_EXTENSIONS
        case mpack_type_ext:
            tag.v.l = node.data->len;
            tag.exttype = mpack_node_exttype_unchecked(node);
            break;
        #endif

        case mpack_type_array:   tag.v.n = node.data->len;  break;
        case mpack_type_map:     tag.v.n = node.data->len;  break;

        default:
            mpack_assert(0, "unrecognized type %i", (int)node.data->type);
            break;
    }
    return tag;
}

#if MPACK_DEBUG && MPACK_STDIO
static void mpack_node_print_element(mpack_node_t node, mpack_print_t* print, size_t depth) {
    mpack_node_data_t* data = node.data;
    size_t i,j;
    switch (data->type) {
        case mpack_type_str:
            {
                mpack_print_append_cstr(print, "\"");
                const char* bytes = mpack_node_data_unchecked(node);
                for (i = 0; i < data->len; ++i) {
                    char c = bytes[i];
                    switch (c) {
                        case '\n': mpack_print_append_cstr(print, "\\n"); break;
                        case '\\': mpack_print_append_cstr(print, "\\\\"); break;
                        case '"': mpack_print_append_cstr(print, "\\\""); break;
                        default: mpack_print_append(print, &c, 1); break;
                    }
                }
                mpack_print_append_cstr(print, "\"");
            }
            break;

        case mpack_type_array:
            mpack_print_append_cstr(print, "[\n");
            for (i = 0; i < data->len; ++i) {
                for (j = 0; j < depth + 1; ++j)
                    mpack_print_append_cstr(print, "    ");
                mpack_node_print_element(mpack_node_array_at(node, i), print, depth + 1);
                if (i != data->len - 1)
                    mpack_print_append_cstr(print, ",");
                mpack_print_append_cstr(print, "\n");
            }
            for (i = 0; i < depth; ++i)
                mpack_print_append_cstr(print, "    ");
            mpack_print_append_cstr(print, "]");
            break;

        case mpack_type_map:
            mpack_print_append_cstr(print, "{\n");
            for (i = 0; i < data->len; ++i) {
                for (j = 0; j < depth + 1; ++j)
                    mpack_print_append_cstr(print, "    ");
                mpack_node_print_element(mpack_node_map_key_at(node, i), print, depth + 1);
                mpack_print_append_cstr(print, ": ");
                mpack_node_print_element(mpack_node_map_value_at(node, i), print, depth + 1);
                if (i != data->len - 1)
                    mpack_print_append_cstr(print, ",");
                mpack_print_append_cstr(print, "\n");
            }
            for (i = 0; i < depth; ++i)
                mpack_print_append_cstr(print, "    ");
            mpack_print_append_cstr(print, "}");
            break;

        default:
            {
                const char* prefix = NULL;
                size_t prefix_length = 0;
                if (mpack_node_type(node) == mpack_type_bin
                        #if MPACK_EXTENSIONS
                        || mpack_node_type(node) == mpack_type_ext
                        #endif
                ) {
                    prefix = mpack_node_data(node);
                    prefix_length = mpack_node_data_len(node);
                }

                char buf[256];
                mpack_tag_t tag = mpack_node_tag(node);
                mpack_tag_debug_pseudo_json(tag, buf, sizeof(buf), prefix, prefix_length);
                mpack_print_append_cstr(print, buf);
            }
            break;
    }
}

void mpack_node_print_to_buffer(mpack_node_t node, char* buffer, size_t buffer_size) {
    if (buffer_size == 0) {
        mpack_assert(false, "buffer size is zero!");
        return;
    }

    mpack_print_t print;
    mpack_memset(&print, 0, sizeof(print));
    print.buffer = buffer;
    print.size = buffer_size;
    mpack_node_print_element(node, &print, 0);
    mpack_print_append(&print, "",  1); // null-terminator
    mpack_print_flush(&print);

    // we always make sure there's a null-terminator at the end of the buffer
    // in case we ran out of space.
    print.buffer[print.size - 1] = '\0';
}

void mpack_node_print_to_callback(mpack_node_t node, mpack_print_callback_t callback, void* context) {
    char buffer[1024];
    mpack_print_t print;
    mpack_memset(&print, 0, sizeof(print));
    print.buffer = buffer;
    print.size = sizeof(buffer);
    print.callback = callback;
    print.context = context;
    mpack_node_print_element(node, &print, 0);
    mpack_print_flush(&print);
}

void mpack_node_print_to_file(mpack_node_t node, FILE* file) {
    mpack_assert(file != NULL, "file is NULL");

    char buffer[1024];
    mpack_print_t print;
    mpack_memset(&print, 0, sizeof(print));
    print.buffer = buffer;
    print.size = sizeof(buffer);
    print.callback = &mpack_print_file_callback;
    print.context = file;

    size_t depth = 2;
    size_t i;
    for (i = 0; i < depth; ++i)
        mpack_print_append_cstr(&print, "    ");
    mpack_node_print_element(node, &print, depth);
    mpack_print_append_cstr(&print, "\n");
    mpack_print_flush(&print);
}
#endif



/*
 * Node Value Functions
 */

#if MPACK_EXTENSIONS
mpack_timestamp_t mpack_node_timestamp(mpack_node_t node) {
    mpack_timestamp_t timestamp = {0, 0};

    // we'll let mpack_node_exttype() do most checks
    if (mpack_node_exttype(node) != MPACK_EXTTYPE_TIMESTAMP) {
        mpack_log("exttype %i\n", mpack_node_exttype(node));
        mpack_node_flag_error(node, mpack_error_type);
        return timestamp;
    }

    const char* p = mpack_node_data_unchecked(node);

    switch (node.data->len) {
        case 4:
            timestamp.nanoseconds = 0;
            timestamp.seconds = mpack_load_u32(p);
            break;

        case 8: {
            uint64_t value = mpack_load_u64(p);
            timestamp.nanoseconds = (uint32_t)(value >> 34);
            timestamp.seconds = value & ((MPACK_UINT64_C(1) << 34) - 1);
            break;
        }

        case 12:
            timestamp.nanoseconds = mpack_load_u32(p);
            timestamp.seconds = mpack_load_i64(p + 4);
            break;

        default:
            mpack_tree_flag_error(node.tree, mpack_error_invalid);
            return timestamp;
    }

    if (timestamp.nanoseconds > MPACK_TIMESTAMP_NANOSECONDS_MAX) {
        mpack_tree_flag_error(node.tree, mpack_error_invalid);
        mpack_timestamp_t zero = {0, 0};
        return zero;
    }

    return timestamp;
}

int64_t mpack_node_timestamp_seconds(mpack_node_t node) {
    return mpack_node_timestamp(node).seconds;
}

uint32_t mpack_node_timestamp_nanoseconds(mpack_node_t node) {
    return mpack_node_timestamp(node).nanoseconds;
}
#endif



/*
 * Node Data Functions
 */

void mpack_node_check_utf8(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return;
    mpack_node_data_t* data = node.data;
    if (data->type != mpack_type_str || !mpack_utf8_check(mpack_node_data_unchecked(node), data->len))
        mpack_node_flag_error(node, mpack_error_type);
}

void mpack_node_check_utf8_cstr(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return;
    mpack_node_data_t* data = node.data;
    if (data->type != mpack_type_str || !mpack_utf8_check_no_null(mpack_node_data_unchecked(node), data->len))
        mpack_node_flag_error(node, mpack_error_type);
}

size_t mpack_node_copy_data(mpack_node_t node, char* buffer, size_t bufsize) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    mpack_assert(bufsize == 0 || buffer != NULL, "buffer is NULL for maximum of %i bytes", (int)bufsize);

    mpack_type_t type = node.data->type;
    if (type != mpack_type_str && type != mpack_type_bin
            #if MPACK_EXTENSIONS
            && type != mpack_type_ext
            #endif
    ) {
        mpack_node_flag_error(node, mpack_error_type);
        return 0;
    }

    if (node.data->len > bufsize) {
        mpack_node_flag_error(node, mpack_error_too_big);
        return 0;
    }

    mpack_memcpy(buffer, mpack_node_data_unchecked(node), node.data->len);
    return (size_t)node.data->len;
}

size_t mpack_node_copy_utf8(mpack_node_t node, char* buffer, size_t bufsize) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    mpack_assert(bufsize == 0 || buffer != NULL, "buffer is NULL for maximum of %i bytes", (int)bufsize);

    mpack_type_t type = node.data->type;
    if (type != mpack_type_str) {
        mpack_node_flag_error(node, mpack_error_type);
        return 0;
    }

    if (node.data->len > bufsize) {
        mpack_node_flag_error(node, mpack_error_too_big);
        return 0;
    }

    if (!mpack_utf8_check(mpack_node_data_unchecked(node), node.data->len)) {
        mpack_node_flag_error(node, mpack_error_type);
        return 0;
    }

    mpack_memcpy(buffer, mpack_node_data_unchecked(node), node.data->len);
    return (size_t)node.data->len;
}

void mpack_node_copy_cstr(mpack_node_t node, char* buffer, size_t bufsize) {

    // we can't break here because the error isn't recoverable; we
    // have to add a null-terminator.
    mpack_assert(buffer != NULL, "buffer is NULL");
    mpack_assert(bufsize >= 1, "buffer size is zero; you must have room for at least a null-terminator");

    if (mpack_node_error(node) != mpack_ok) {
        buffer[0] = '\0';
        return;
    }

    if (node.data->type != mpack_type_str) {
        buffer[0] = '\0';
        mpack_node_flag_error(node, mpack_error_type);
        return;
    }

    if (node.data->len > bufsize - 1) {
        buffer[0] = '\0';
        mpack_node_flag_error(node, mpack_error_too_big);
        return;
    }

    if (!mpack_str_check_no_null(mpack_node_data_unchecked(node), node.data->len)) {
        buffer[0] = '\0';
        mpack_node_flag_error(node, mpack_error_type);
        return;
    }

    mpack_memcpy(buffer, mpack_node_data_unchecked(node), node.data->len);
    buffer[node.data->len] = '\0';
}

void mpack_node_copy_utf8_cstr(mpack_node_t node, char* buffer, size_t bufsize) {

    // we can't break here because the error isn't recoverable; we
    // have to add a null-terminator.
    mpack_assert(buffer != NULL, "buffer is NULL");
    mpack_assert(bufsize >= 1, "buffer size is zero; you must have room for at least a null-terminator");

    if (mpack_node_error(node) != mpack_ok) {
        buffer[0] = '\0';
        return;
    }

    if (node.data->type != mpack_type_str) {
        buffer[0] = '\0';
        mpack_node_flag_error(node, mpack_error_type);
        return;
    }

    if (node.data->len > bufsize - 1) {
        buffer[0] = '\0';
        mpack_node_flag_error(node, mpack_error_too_big);
        return;
    }

    if (!mpack_utf8_check_no_null(mpack_node_data_unchecked(node), node.data->len)) {
        buffer[0] = '\0';
        mpack_node_flag_error(node, mpack_error_type);
        return;
    }

    mpack_memcpy(buffer, mpack_node_data_unchecked(node), node.data->len);
    buffer[node.data->len] = '\0';
}

#ifdef MPACK_MALLOC
char* mpack_node_data_alloc(mpack_node_t node, size_t maxlen) {
    if (mpack_node_error(node) != mpack_ok)
        return NULL;

    // make sure this is a valid data type
    mpack_type_t type = node.data->type;
    if (type != mpack_type_str && type != mpack_type_bin
            #if MPACK_EXTENSIONS
            && type != mpack_type_ext
            #endif
    ) {
        mpack_node_flag_error(node, mpack_error_type);
        return NULL;
    }

    if (node.data->len > maxlen) {
        mpack_node_flag_error(node, mpack_error_too_big);
        return NULL;
    }

    char* ret = (char*) MPACK_MALLOC((size_t)node.data->len);
    if (ret == NULL) {
        mpack_node_flag_error(node, mpack_error_memory);
        return NULL;
    }

    mpack_memcpy(ret, mpack_node_data_unchecked(node), node.data->len);
    return ret;
}

char* mpack_node_cstr_alloc(mpack_node_t node, size_t maxlen) {
    if (mpack_node_error(node) != mpack_ok)
        return NULL;

    // make sure maxlen makes sense
    if (maxlen < 1) {
        mpack_break("maxlen is zero; you must have room for at least a null-terminator");
        mpack_node_flag_error(node, mpack_error_bug);
        return NULL;
    }

    if (node.data->type != mpack_type_str) {
        mpack_node_flag_error(node, mpack_error_type);
        return NULL;
    }

    if (node.data->len > maxlen - 1) {
        mpack_node_flag_error(node, mpack_error_too_big);
        return NULL;
    }

    if (!mpack_str_check_no_null(mpack_node_data_unchecked(node), node.data->len)) {
        mpack_node_flag_error(node, mpack_error_type);
        return NULL;
    }

    char* ret = (char*) MPACK_MALLOC((size_t)(node.data->len + 1));
    if (ret == NULL) {
        mpack_node_flag_error(node, mpack_error_memory);
        return NULL;
    }

    mpack_memcpy(ret, mpack_node_data_unchecked(node), node.data->len);
    ret[node.data->len] = '\0';
    return ret;
}

char* mpack_node_utf8_cstr_alloc(mpack_node_t node, size_t maxlen) {
    if (mpack_node_error(node) != mpack_ok)
        return NULL;

    // make sure maxlen makes sense
    if (maxlen < 1) {
        mpack_break("maxlen is zero; you must have room for at least a null-terminator");
        mpack_node_flag_error(node, mpack_error_bug);
        return NULL;
    }

    if (node.data->type != mpack_type_str) {
        mpack_node_flag_error(node, mpack_error_type);
        return NULL;
    }

    if (node.data->len > maxlen - 1) {
        mpack_node_flag_error(node, mpack_error_too_big);
        return NULL;
    }

    if (!mpack_utf8_check_no_null(mpack_node_data_unchecked(node), node.data->len)) {
        mpack_node_flag_error(node, mpack_error_type);
        return NULL;
    }

    char* ret = (char*) MPACK_MALLOC((size_t)(node.data->len + 1));
    if (ret == NULL) {
        mpack_node_flag_error(node, mpack_error_memory);
        return NULL;
    }

    mpack_memcpy(ret, mpack_node_data_unchecked(node), node.data->len);
    ret[node.data->len] = '\0';
    return ret;
}
#endif


/*
 * Compound Node Functions
 */

static mpack_node_data_t* mpack_node_map_int_impl(mpack_node_t node, int64_t num) {
    if (mpack_node_error(node) != mpack_ok)
        return NULL;

    if (node.data->type != mpack_type_map) {
        mpack_node_flag_error(node, mpack_error_type);
        return NULL;
    }

    mpack_node_data_t* found = NULL;

    size_t i;
    for (i = 0; i < node.data->len; ++i) {
        mpack_node_data_t* key = mpack_node_child(node, i * 2);

        if ((key->type == mpack_type_int && key->value.i == num) ||
            (key->type == mpack_type_uint && num >= 0 && key->value.u == (uint64_t)num))
        {
            if (found) {
                mpack_node_flag_error(node, mpack_error_data);
                return NULL;
            }
            found = mpack_node_child(node, i * 2 + 1);
        }
    }

    if (found)
        return found;

    return NULL;
}

static mpack_node_data_t* mpack_node_map_uint_impl(mpack_node_t node, uint64_t num) {
    if (mpack_node_error(node) != mpack_ok)
        return NULL;

    if (node.data->type != mpack_type_map) {
        mpack_node_flag_error(node, mpack_error_type);
        return NULL;
    }

    mpack_node_data_t* found = NULL;

    size_t i;
    for (i = 0; i < node.data->len; ++i) {
        mpack_node_data_t* key = mpack_node_child(node, i * 2);

        if ((key->type == mpack_type_uint && key->value.u == num) ||
            (key->type == mpack_type_int && key->value.i >= 0 && (uint64_t)key->value.i == num))
        {
            if (found) {
                mpack_node_flag_error(node, mpack_error_data);
                return NULL;
            }
            found = mpack_node_child(node, i * 2 + 1);
        }
    }

    if (found)
        return found;

    return NULL;
}

static mpack_node_data_t* mpack_node_map_str_impl(mpack_node_t node, const char* str, size_t length) {
    if (mpack_node_error(node) != mpack_ok)
        return NULL;

    mpack_assert(length == 0 || str != NULL, "str of length %i is NULL", (int)length);

    if (node.data->type != mpack_type_map) {
        mpack_node_flag_error(node, mpack_error_type);
        return NULL;
    }

    mpack_tree_t* tree = node.tree;
    mpack_node_data_t* found = NULL;

    size_t i;
    for (i = 0; i < node.data->len; ++i) {
        mpack_node_data_t* key = mpack_node_child(node, i * 2);

        if (key->type == mpack_type_str && key->len == length &&
                mpack_memcmp(str, mpack_node_data_unchecked(mpack_node(tree, key)), length) == 0) {
            if (found) {
                mpack_node_flag_error(node, mpack_error_data);
                return NULL;
            }
            found = mpack_node_child(node, i * 2 + 1);
        }
    }

    if (found)
        return found;

    return NULL;
}

static mpack_node_t mpack_node_wrap_lookup(mpack_tree_t* tree, mpack_node_data_t* data) {
    if (!data) {
        if (tree->error == mpack_ok)
            mpack_tree_flag_error(tree, mpack_error_data);
        return mpack_tree_nil_node(tree);
    }
    return mpack_node(tree, data);
}

static mpack_node_t mpack_node_wrap_lookup_optional(mpack_tree_t* tree, mpack_node_data_t* data) {
    if (!data) {
        if (tree->error == mpack_ok)
            return mpack_tree_missing_node(tree);
        return mpack_tree_nil_node(tree);
    }
    return mpack_node(tree, data);
}

mpack_node_t mpack_node_map_int(mpack_node_t node, int64_t num) {
    return mpack_node_wrap_lookup(node.tree, mpack_node_map_int_impl(node, num));
}

mpack_node_t mpack_node_map_int_optional(mpack_node_t node, int64_t num) {
    return mpack_node_wrap_lookup_optional(node.tree, mpack_node_map_int_impl(node, num));
}

mpack_node_t mpack_node_map_uint(mpack_node_t node, uint64_t num) {
    return mpack_node_wrap_lookup(node.tree, mpack_node_map_uint_impl(node, num));
}

mpack_node_t mpack_node_map_uint_optional(mpack_node_t node, uint64_t num) {
    return mpack_node_wrap_lookup_optional(node.tree, mpack_node_map_uint_impl(node, num));
}

mpack_node_t mpack_node_map_str(mpack_node_t node, const char* str, size_t length) {
    return mpack_node_wrap_lookup(node.tree, mpack_node_map_str_impl(node, str, length));
}

mpack_node_t mpack_node_map_str_optional(mpack_node_t node, const char* str, size_t length) {
    return mpack_node_wrap_lookup_optional(node.tree, mpack_node_map_str_impl(node, str, length));
}

mpack_node_t mpack_node_map_cstr(mpack_node_t node, const char* cstr) {
    mpack_assert(cstr != NULL, "cstr is NULL");
    return mpack_node_map_str(node, cstr, mpack_strlen(cstr));
}

mpack_node_t mpack_node_map_cstr_optional(mpack_node_t node, const char* cstr) {
    mpack_assert(cstr != NULL, "cstr is NULL");
    return mpack_node_map_str_optional(node, cstr, mpack_strlen(cstr));
}

bool mpack_node_map_contains_int(mpack_node_t node, int64_t num) {
    return mpack_node_map_int_impl(node, num) != NULL;
}

bool mpack_node_map_contains_uint(mpack_node_t node, uint64_t num) {
    return mpack_node_map_uint_impl(node, num) != NULL;
}

bool mpack_node_map_contains_str(mpack_node_t node, const char* str, size_t length) {
    return mpack_node_map_str_impl(node, str, length) != NULL;
}

bool mpack_node_map_contains_cstr(mpack_node_t node, const char* cstr) {
    mpack_assert(cstr != NULL, "cstr is NULL");
    return mpack_node_map_contains_str(node, cstr, mpack_strlen(cstr));
}

size_t mpack_node_enum_optional(mpack_node_t node, const char* strings[], size_t count) {
    if (mpack_node_error(node) != mpack_ok)
        return count;

    // the value is only recognized if it is a string
    if (mpack_node_type(node) != mpack_type_str)
        return count;

    // fetch the string
    const char* key = mpack_node_str(node);
    size_t keylen = mpack_node_strlen(node);
    mpack_assert(mpack_node_error(node) == mpack_ok, "these should not fail");

    // find what key it matches
    size_t i;
    for (i = 0; i < count; ++i) {
        const char* other = strings[i];
        size_t otherlen = mpack_strlen(other);
        if (keylen == otherlen && mpack_memcmp(key, other, keylen) == 0)
            return i;
    }

    // no matches
    return count;
}

size_t mpack_node_enum(mpack_node_t node, const char* strings[], size_t count) {
    size_t value = mpack_node_enum_optional(node, strings, count);
    if (value == count)
        mpack_node_flag_error(node, mpack_error_type);
    return value;
}

mpack_type_t mpack_node_type(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return mpack_type_nil;
    return node.data->type;
}

bool mpack_node_is_nil(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok) {
        // All nodes are treated as nil nodes when we are in error.
        return true;
    }
    return node.data->type == mpack_type_nil;
}

bool mpack_node_is_missing(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok) {
        // errors still return nil nodes, not missing nodes.
        return false;
    }
    return node.data->type == mpack_type_missing;
}

void mpack_node_nil(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return;
    if (node.data->type != mpack_type_nil)
        mpack_node_flag_error(node, mpack_error_type);
}

void mpack_node_missing(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return;
    if (node.data->type != mpack_type_missing)
        mpack_node_flag_error(node, mpack_error_type);
}

bool mpack_node_bool(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return false;

    if (node.data->type == mpack_type_bool)
        return node.data->value.b;

    mpack_node_flag_error(node, mpack_error_type);
    return false;
}

void mpack_node_true(mpack_node_t node) {
    if (mpack_node_bool(node) != true)
        mpack_node_flag_error(node, mpack_error_type);
}

void mpack_node_false(mpack_node_t node) {
    if (mpack_node_bool(node) != false)
        mpack_node_flag_error(node, mpack_error_type);
}

uint8_t mpack_node_u8(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_uint) {
        if (node.data->value.u <= MPACK_UINT8_MAX)
            return (uint8_t)node.data->value.u;
    } else if (node.data->type == mpack_type_int) {
        if (node.data->value.i >= 0 && node.data->value.i <= MPACK_UINT8_MAX)
            return (uint8_t)node.data->value.i;
    }

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

int8_t mpack_node_i8(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_uint) {
        if (node.data->value.u <= MPACK_INT8_MAX)
            return (int8_t)node.data->value.u;
    } else if (node.data->type == mpack_type_int) {
        if (node.data->value.i >= MPACK_INT8_MIN && node.data->value.i <= MPACK_INT8_MAX)
            return (int8_t)node.data->value.i;
    }

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

uint16_t mpack_node_u16(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_uint) {
        if (node.data->value.u <= MPACK_UINT16_MAX)
            return (uint16_t)node.data->value.u;
    } else if (node.data->type == mpack_type_int) {
        if (node.data->value.i >= 0 && node.data->value.i <= MPACK_UINT16_MAX)
            return (uint16_t)node.data->value.i;
    }

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

int16_t mpack_node_i16(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_uint) {
        if (node.data->value.u <= MPACK_INT16_MAX)
            return (int16_t)node.data->value.u;
    } else if (node.data->type == mpack_type_int) {
        if (node.data->value.i >= MPACK_INT16_MIN && node.data->value.i <= MPACK_INT16_MAX)
            return (int16_t)node.data->value.i;
    }

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

uint32_t mpack_node_u32(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_uint) {
        if (node.data->value.u <= MPACK_UINT32_MAX)
            return (uint32_t)node.data->value.u;
    } else if (node.data->type == mpack_type_int) {
        if (node.data->value.i >= 0 && node.data->value.i <= MPACK_UINT32_MAX)
            return (uint32_t)node.data->value.i;
    }

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

int32_t mpack_node_i32(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_uint) {
        if (node.data->value.u <= MPACK_INT32_MAX)
            return (int32_t)node.data->value.u;
    } else if (node.data->type == mpack_type_int) {
        if (node.data->value.i >= MPACK_INT32_MIN && node.data->value.i <= MPACK_INT32_MAX)
            return (int32_t)node.data->value.i;
    }

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

uint64_t mpack_node_u64(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_uint) {
        return node.data->value.u;
    } else if (node.data->type == mpack_type_int) {
        if (node.data->value.i >= 0)
            return (uint64_t)node.data->value.i;
    }

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

int64_t mpack_node_i64(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_uint) {
        if (node.data->value.u <= (uint64_t)MPACK_INT64_MAX)
            return (int64_t)node.data->value.u;
    } else if (node.data->type == mpack_type_int) {
        return node.data->value.i;
    }

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

unsigned int mpack_node_uint(mpack_node_t node) {

    // This should be true at compile-time, so this just wraps the 32-bit function.
    if (sizeof(unsigned int) == 4)
        return (unsigned int)mpack_node_u32(node);

    // Otherwise we use u64 and check the range.
    uint64_t val = mpack_node_u64(node);
    if (val <= MPACK_UINT_MAX)
        return (unsigned int)val;

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

int mpack_node_int(mpack_node_t node) {

    // This should be true at compile-time, so this just wraps the 32-bit function.
    if (sizeof(int) == 4)
        return (int)mpack_node_i32(node);

    // Otherwise we use i64 and check the range.
    int64_t val = mpack_node_i64(node);
    if (val >= MPACK_INT_MIN && val <= MPACK_INT_MAX)
        return (int)val;

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

#if MPACK_FLOAT
float mpack_node_float(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0.0f;

    if (node.data->type == mpack_type_uint)
        return (float)node.data->value.u;
    if (node.data->type == mpack_type_int)
        return (float)node.data->value.i;
    if (node.data->type == mpack_type_float)
        return node.data->value.f;

    if (node.data->type == mpack_type_double) {
        #if MPACK_DOUBLE
        return (float)node.data->value.d;
        #else
        return mpack_shorten_raw_double_to_float(node.data->value.d);
        #endif
    }

    mpack_node_flag_error(node, mpack_error_type);
    return 0.0f;
}
#endif

#if MPACK_DOUBLE
double mpack_node_double(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0.0;

    if (node.data->type == mpack_type_uint)
        return (double)node.data->value.u;
    else if (node.data->type == mpack_type_int)
        return (double)node.data->value.i;
    else if (node.data->type == mpack_type_float)
        return (double)node.data->value.f;
    else if (node.data->type == mpack_type_double)
        return node.data->value.d;

    mpack_node_flag_error(node, mpack_error_type);
    return 0.0;
}
#endif

#if MPACK_FLOAT
float mpack_node_float_strict(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0.0f;

    if (node.data->type == mpack_type_float)
        return node.data->value.f;

    mpack_node_flag_error(node, mpack_error_type);
    return 0.0f;
}
#endif

#if MPACK_DOUBLE
double mpack_node_double_strict(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0.0;

    if (node.data->type == mpack_type_float)
        return (double)node.data->value.f;
    else if (node.data->type == mpack_type_double)
        return node.data->value.d;

    mpack_node_flag_error(node, mpack_error_type);
    return 0.0;
}
#endif

#if !MPACK_FLOAT
uint32_t mpack_node_raw_float(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_float)
        return node.data->value.f;

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}
#endif

#if !MPACK_DOUBLE
uint64_t mpack_node_raw_double(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_double)
        return node.data->value.d;

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}
#endif

#if MPACK_EXTENSIONS
int8_t mpack_node_exttype(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_ext)
        return mpack_node_exttype_unchecked(node);

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}
#endif

uint32_t mpack_node_data_len(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    mpack_type_t type = node.data->type;
    if (type == mpack_type_str || type == mpack_type_bin
            #if MPACK_EXTENSIONS
            || type == mpack_type_ext
            #endif
            )
        return (uint32_t)node.data->len;

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

size_t mpack_node_strlen(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_str)
        return (size_t)node.data->len;

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

const char* mpack_node_str(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return NULL;

    mpack_type_t type = node.data->type;
    if (type == mpack_type_str)
        return mpack_node_data_unchecked(node);

    mpack_node_flag_error(node, mpack_error_type);
    return NULL;
}

const char* mpack_node_data(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return NULL;

    mpack_type_t type = node.data->type;
    if (type == mpack_type_str || type == mpack_type_bin
            #if MPACK_EXTENSIONS
            || type == mpack_type_ext
            #endif
            )
        return mpack_node_data_unchecked(node);

    mpack_node_flag_error(node, mpack_error_type);
    return NULL;
}

const char* mpack_node_bin_data(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return NULL;

    if (node.data->type == mpack_type_bin)
        return mpack_node_data_unchecked(node);

    mpack_node_flag_error(node, mpack_error_type);
    return NULL;
}

size_t mpack_node_bin_size(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type == mpack_type_bin)
        return (size_t)node.data->len;

    mpack_node_flag_error(node, mpack_error_type);
    return 0;
}

size_t mpack_node_array_length(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type != mpack_type_array) {
        mpack_node_flag_error(node, mpack_error_type);
        return 0;
    }

    return (size_t)node.data->len;
}

mpack_node_t mpack_node_array_at(mpack_node_t node, size_t index) {
    if (mpack_node_error(node) != mpack_ok)
        return mpack_tree_nil_node(node.tree);

    if (node.data->type != mpack_type_array) {
        mpack_node_flag_error(node, mpack_error_type);
        return mpack_tree_nil_node(node.tree);
    }

    if (index >= node.data->len) {
        mpack_node_flag_error(node, mpack_error_data);
        return mpack_tree_nil_node(node.tree);
    }

    return mpack_node(node.tree, mpack_node_child(node, index));
}

size_t mpack_node_map_count(mpack_node_t node) {
    if (mpack_node_error(node) != mpack_ok)
        return 0;

    if (node.data->type != mpack_type_map) {
        mpack_node_flag_error(node, mpack_error_type);
        return 0;
    }

    return node.data->len;
}

// internal node map lookup
static mpack_node_t mpack_node_map_at(mpack_node_t node, size_t index, size_t offset) {
    if (mpack_node_error(node) != mpack_ok)
        return mpack_tree_nil_node(node.tree);

    if (node.data->type != mpack_type_map) {
        mpack_node_flag_error(node, mpack_error_type);
        return mpack_tree_nil_node(node.tree);
    }

    if (index >= node.data->len) {
        mpack_node_flag_error(node, mpack_error_data);
        return mpack_tree_nil_node(node.tree);
    }

    return mpack_node(node.tree, mpack_node_child(node, index * 2 + offset));
}

mpack_node_t mpack_node_map_key_at(mpack_node_t node, size_t index) {
    return mpack_node_map_at(node, index, 0);
}

mpack_node_t mpack_node_map_value_at(mpack_node_t node, size_t index) {
    return mpack_node_map_at(node, index, 1);
}

#endif

MPACK_SILENCE_WARNINGS_END
