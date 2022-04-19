/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
 *  Copyright (C) 2005-2017 The Android Open Source Project
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

#include "logprint.h"
#include <string.h>

int parseLogEntry(log_msg * buf, int length, AndroidLogEntry * entry,
                  struct flb_input_instance *ins)
{
    /* The following code is a modified copy of AOSP's android_log_processLogBuffer */

    if (length < (int) (sizeof(buf->entry))) {
        flb_plg_error(ins,
                      "Failed to read log entry header, actual size: %d, expected size: %d",
                      length, sizeof(buf->entry));
        return -1;
    }

    if (buf->entry.hdr_size < sizeof(buf->entry) - sizeof(buf->entry.uid)) {
        flb_plg_error(ins,
                      "hdr_size (%d) should not be less than actual header size (%d)",
                      buf->entry.hdr_size, sizeof(buf->entry));
        return -1;
    }

    bool hasPermission = true;
    if (buf->entry.hdr_size == sizeof(buf->entry) - sizeof(buf->entry.uid)) {
        /*
         * When application doesn't have READ_LOGS permission, logd gives only logs
         * of this application, and it's header misses 'uid' field
         * */
        hasPermission = false;
    }

    if (buf->entry.len > length - buf->entry.hdr_size) {
        flb_plg_error(ins,
                      "entry length should not be more than %d, actual length: %d",
                      length - buf->entry.hdr_size, buf->entry.len);
        return -1;
    }

    entry->message = NULL;
    entry->messageLen = 0;

    entry->tv_sec = buf->entry.sec;
    entry->tv_nsec = buf->entry.nsec;
    entry->uid = -1;
    entry->pid = buf->entry.pid;
    entry->tid = buf->entry.tid;

    /*
     * format: <priority:1><tag:N>\0<message:N>\0
     *
     * tag str
     *   starts at buf + buf->hdr_size + 1
     * msg
     *   starts at buf + buf->hdr_size + 1 + len(tag) + 1
     *
     * The message may have been truncated.  When that happens, we must null-terminate
     * the message ourselves.
     */
    if (buf->entry.len < 3) {
        /*
         * A well-formed entry must consist of at least a priority
         * and two null characters
         */
        flb_plg_error(ins, "+++ LOG: entry too small");
        return -1;
    }

    char *msg = buf->buf + buf->entry.hdr_size;

    if (hasPermission) {
        entry->uid = buf->entry.uid;
    }

    char *msgStart = memchr(msg, '\0', buf->entry.len) + 1;
    if (msgStart == NULL) {
        /* +++ LOG: malformed log message, DYB */
        for (int i = 1; i < buf->entry.len; i++) {
            /* odd characters in tag? */
            if ((msg[i] <= ' ') || (msg[i] == ':') || (msg[i] >= 0x7f)) {
                msg[i] = '\0';
                msgStart = &msg[i + 1];
                break;
            }
        }
        if (msgStart == NULL) {
            msgStart = &msg[buf->entry.len - 1];        /* All tag, no message, print truncates */
        }
    }

    char *msgEnd = memchr(msgStart, '\0', buf->entry.len - (msgStart - msg));
    if (msgEnd == NULL) {
        /* incoming message not null-terminated; force it */
        msgEnd = &msg[buf->entry.len - 1];      /* may result in msgEnd < msgStart */
        *msgEnd = '\0';
    }

    entry->priority = (android_LogPriority) (msg[0]);
    entry->tag = msg + 1;
    entry->tagLen = msgStart - msg - 1;
    entry->message = msgStart;
    entry->messageLen = (msgEnd < msgStart) ? 0 : (msgEnd - msgStart);

    return 0;
}

static char filterPriToChar(android_LogPriority pri)
{
    switch (pri) {
    case ANDROID_LOG_VERBOSE:
        return 'V';
    case ANDROID_LOG_DEBUG:
        return 'D';
    case ANDROID_LOG_INFO:
        return 'I';
    case ANDROID_LOG_WARN:
        return 'W';
    case ANDROID_LOG_ERROR:
        return 'E';
    case ANDROID_LOG_FATAL:
        return 'F';
    case ANDROID_LOG_SILENT:
        return 'S';

    case ANDROID_LOG_DEFAULT:
    case ANDROID_LOG_UNKNOWN:
    default:
        return '?';
    }
}

/**
 * Formats a log message into a buffer
 *
 * Uses defaultBuffer if it can, otherwise malloc()'s a new buffer
 * If return value != defaultBuffer, caller must call free()
 * Returns NULL on malloc error
 */
char *formatLogLine(char *defaultBuffer,
                    size_t defaultBufferSize, const AndroidLogEntry * entry,
                    size_t * p_outLength)
{
    /* The following code is a modified copy of AOSP's android_log_formatLogLine */
    struct tm tmBuf;
    struct tm *ptm;
    /* good margin, 23+nul for msec, 26+nul for usec, 29+nul to nsec */
    char timeBuf[64];
    char prefixBuf[128];
    char priChar;
    char *ret;
    time_t now;
    unsigned long nsec;

    priChar = filterPriToChar(entry->priority);
    size_t prefixLen = 0;
    size_t len;

    /*
     * Get the current date/time in pretty form
     */
    now = entry->tv_sec;
    nsec = entry->tv_nsec;
    if (now < 0) {
        nsec = NS_PER_SEC - nsec;
    }
    ptm = localtime_r(&now, &tmBuf);
    strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", ptm);

    len = strlen(timeBuf);
    snprintf(timeBuf + len, sizeof(timeBuf) - len, ".%03ld",
             nsec / MS_PER_NSEC);
    prefixLen =
        snprintf(prefixBuf, sizeof(prefixBuf), "%s %5d %5d %c %-8.*s: ",
                 timeBuf, entry->pid, entry->tid, priChar,
                 (int) entry->tagLen, entry->tag);

    /*
     * snprintf has a weird return value.   It returns what would have been
     * written given a large enough buffer.  In the case that the prefix is
     * longer then our buffer(128), it messes up the calculations below
     * possibly causing heap corruption.  To avoid this we double check and
     * set the length at the maximum (size minus null byte)
     */
    if (prefixLen >= sizeof(prefixBuf)) {
        prefixLen = sizeof(prefixBuf) - 1;
        prefixBuf[sizeof(prefixBuf) - 1] = '\0';
    }

    /* the following code is tragically unreadable */

    size_t numLines;
    char *p;
    size_t bufferSize;
    const char *pm;

    pm = entry->message;
    numLines = 0;

    /*
     * The line-end finding here must match the line-end finding
     * in for ( ... numLines...) loop below
     */
    while (pm < (entry->message + entry->messageLen)) {
        if (*pm++ == '\n') {
            numLines++;
        }
    }
    /* plus one line for anything not newline-terminated at the end */
    if (pm > entry->message && *(pm - 1) != '\n') {
        numLines++;
    }

    /*
     * this is an upper bound--newlines in message may be counted
     * extraneously
     */
    bufferSize = (numLines * prefixLen) + 1;
    bufferSize += entry->messageLen;

    if (defaultBufferSize >= bufferSize) {
        ret = defaultBuffer;
    }
    else {
        ret = (char *) malloc(bufferSize);

        if (ret == NULL) {
            return ret;
        }
    }

    ret[0] = '\0';              /* to start strcat off */

    p = ret;
    pm = entry->message;

    do {
        const char *lineStart;
        size_t lineLen;
        lineStart = pm;

        /* Find the next end-of-line in message */
        while (pm < (entry->message + entry->messageLen) && *pm != '\n') {
            pm++;
        }
        lineLen = pm - lineStart;

        strcat(p, prefixBuf);
        p += prefixLen;
        strncat(p, lineStart, lineLen);
        p += lineLen;

        if (*pm == '\n') {
            pm++;
        }
    } while (pm < (entry->message + entry->messageLen));

    if (p_outLength != NULL) {
        *p_outLength = p - ret;
    }

    return ret;
}
