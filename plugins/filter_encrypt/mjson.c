/****************************************************************************

NAME
   mjson.c - parse JSON into fixed-extent data structures

DESCRIPTION
   This module parses a large subset of JSON (JavaScript Object
Notation).  Unlike more general JSON parsers, it doesn't use malloc(3)
and doesn't support polymorphism; you need to give it a set of
template structures describing the expected shape of the incoming
JSON, and it will error out if that shape is not matched.  When the
parse succeeds, attribute values will be extracted into static
locations specified in the template structures.

   The "shape" of a JSON object in the type signature of its
attributes (and attribute values, and so on recursively down through
all nestings of objects and arrays).  This parser is indifferent to
the order of attributes at any level, but you have to tell it in
advance what the type of each attribute value will be and where the
parsed value will be stored. The template structures may supply
default values to be used when an expected attribute is omitted.

   The preceding paragraph told one fib.  A single attribute may
actually have a span of multiple specifications with different
syntactically distinguishable types (e.g. string vs. real vs. integer
vs. boolean, but not signed integer vs. unsigned integer).  The parser
will match the right spec against the actual data.

   The dialect this parses has some limitations.  First, it cannot
recognize the JSON "null" value. Second, all elements of an array must
be of the same type. Third, characters may not be array elements (this
restriction could be lifted)

   There are separate entry points for beginning a parse of either
JSON object or a JSON array. JSON "float" quantities are actually
stored as doubles.

   This parser processes object arrays in one of two different ways,
defending on whether the array subtype is declared as object or
structobject.

   Object arrays take one base address per object subfield, and are
mapped into parallel C arrays (one per subfield).  Strings are not
supported in this kind of array, as they don't have a "natural" size
to use as an offset multiplier.

   Structobjects arrays are a way to parse a list of objects to a set
of modifications to a corresponding array of C structs.  The trick is
that the array object initialization has to specify both the C struct
array's base address and the stride length (the size of the C struct).
If you initialize the offset fields with the correct offsetof calls,
everything will work. Strings are supported but all string storage
has to be inline in the struct.

PERMISSIONS
   This file is Copyright (c) 2014 by Eric S. Raymond
   SPDX-License-Identifier: BSD-2-Clause

***************************************************************************/
/* The strptime prototype is not provided unless explicitly requested.
 * We also need to set the value high enough to signal inclusion of
 * newer features (like clock_gettime).  See the POSIX spec for more info:
 * http://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_02_01_02 */
#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <math.h>    /* for HUGE_VAL */

//#include <fluent-bit/flb_filter.h>
//#include <fluent-bit/flb_filter_plugin.h>

#include "mjson.h"

#define str_starts_with(s, p)    (strncmp(s, p, strlen(p)) == 0)


static char *json_target_address(const struct json_attr_t *cursor,
                                 const struct json_array_t
                                 *parent, int offset) {
    char *targetaddr = NULL;
    if (parent == NULL || parent->element_type != t_structobject) {
        /* ordinary case - use the address in the cursor structure */
        switch (cursor->type) {
            case t_ignore:
                targetaddr = NULL;
                break;
            case t_integer:
                targetaddr = (char *) &cursor->addr.integer[offset];
                break;
            case t_uinteger:
                targetaddr = (char *) &cursor->addr.uinteger[offset];
                break;
            case t_short:
                targetaddr = (char *) &cursor->addr.shortint[offset];
                break;
            case t_ushort:
                targetaddr = (char *) &cursor->addr.ushortint[offset];
                break;
            case t_time:
            case t_real:
                targetaddr = (char *) &cursor->addr.real[offset];
                break;
            case t_string:
                targetaddr = cursor->addr.string;
                break;
            case t_boolean:
                targetaddr = (char *) &cursor->addr.boolean[offset];
                break;
            case t_character:
                targetaddr = (char *) &cursor->addr.character[offset];
                break;
            default:
                targetaddr = NULL;
                break;
        }
    } else
        /* tricky case - hacking a member in an array of structures */
        targetaddr =
                parent->arr.objects.base + (offset * parent->arr.objects.stride) +
                cursor->addr.offset;
//    flb_plg_trace(ctx->ins, "[JSON] Target address for %s (offset %d) is %p\n",
//              cursor->attribute, offset, targetaddr);
    return targetaddr;
}

#ifdef TIME_ENABLE
static double iso8601_to_unix(char *isotime)
/* ISO8601 UTC to Unix UTC */
{
    double usec;
    struct tm tm;

    char *dp = strptime(isotime, "%Y-%m-%dT%H:%M:%S", &tm);
    if (dp == NULL)
    return (double)HUGE_VAL;
    if (*dp == '.')
    usec = strtod(dp, NULL);
    else
    usec = 0;
    return (double)timegm(&tm) + usec;
}
#endif /* TIME_ENABLE */

static int json_internal_read_object(const char *cp,
                                     const struct json_attr_t *attrs,
                                     const struct json_array_t *parent,
                                     int offset,
                                     const char **end) {
    enum {
        init, await_attr, in_attr, await_value, in_val_string,
        in_escape, in_val_token, post_val, post_element
    } state = 0;

    char *statenames[] = {
            "init", "await_attr", "in_attr", "await_value", "in_val_string",
            "in_escape", "in_val_token", "post_val", "post_element",
    };

    char attrbuf[JSON_ATTR_MAX + 1], *pattr = NULL;
    char valbuf[JSON_VAL_MAX + 1], *pval = NULL;
    bool value_quoted = false;
    char uescape[5];        /* enough space for 4 hex digits and a NUL */
    const struct json_attr_t *cursor;
    int substatus, n, maxlen = 0;
    unsigned int u;
    const struct json_enum_t *mp;
    char *lptr;

    if (end != NULL)
        *end = NULL;    /* give it a well-defined value on parse failure */

    /* stuff fields with defaults in case they're omitted in the JSON input */
    for (cursor = attrs; cursor->attribute != NULL; cursor++)
        if (!cursor->nodefault) {
            lptr = json_target_address(cursor, parent, offset);
            if (lptr != NULL)
                switch (cursor->type) {
                    case t_integer:
                        memcpy(lptr, &cursor->dflt.integer, sizeof(int));
                        break;
                    case t_uinteger:
                        memcpy(lptr, &cursor->dflt.uinteger, sizeof(unsigned int));
                        break;
                    case t_short:
                        memcpy(lptr, &cursor->dflt.shortint, sizeof(short));
                        break;
                    case t_ushort:
                        memcpy(lptr, &cursor->dflt.ushortint,
                               sizeof(unsigned short));
                        break;
                    case t_time:
                    case t_real:
                        memcpy(lptr, &cursor->dflt.real, sizeof(double));
                        break;
                    case t_string:
                        if (parent != NULL
                            && parent->element_type != t_structobject
                            && offset > 0)
                            return JSON_ERR_NOPARSTR;
                        lptr[0] = '\0';
                        break;
                    case t_boolean:
                        memcpy(lptr, &cursor->dflt.boolean, sizeof(bool));
                        break;
                    case t_character:
                        lptr[0] = cursor->dflt.character;
                        break;
                    case t_object:    /* silences a compiler warning */
                    case t_structobject:
                    case t_array:
                    case t_check:
                    case t_ignore:
                        break;
                }
        }

    //flb_plg_debug(ctx->ins, "JSON parse of '%s' begins.\n", cp);

    /* parse input JSON */
    for (; *cp != '\0'; cp++) {
//        flb_plg_trace(ctx->ins, "State %-14s, looking at '%c' (%p)\n",
//                  statenames[state], *cp, cp);
        switch (state) {
            case init:
                if (isspace((unsigned char) *cp))
                    continue;
                else if (*cp == '{')
                    state = await_attr;
                else {
//                    flb_plg_debug(ctx->ins, "Non-WS when expecting object start.\n");
                    if (end != NULL)
                        *end = cp;
                    return JSON_ERR_OBSTART;
                }
                break;
            case await_attr:
                if (isspace((unsigned char) *cp))
                    continue;
                else if (*cp == '"') {
                    state = in_attr;
                    pattr = attrbuf;
                    if (end != NULL)
                        *end = cp;
                } else if (*cp == '}')
                    break;
                else {
                    if (end != NULL)
                        *end = cp;
//                    flb_plg_debug("Non-WS when expecting attribute.\n");
                    return JSON_ERR_ATTRSTART;
                }
                break;
            case in_attr:
                if (pattr == NULL)
                    /* don't update end here, leave at attribute start */
                    return JSON_ERR_NULLPTR;
                if (*cp == '"') {
                    *pattr++ = '\0';
//                    flb_plg_trace("Collected attribute name %s\n",
//                              attrbuf);
                    for (cursor = attrs; cursor->attribute != NULL; cursor++) {
//                        flb_plg_trace("Checking against %s\n",
//                                  cursor->attribute);
                        if (strcmp(cursor->attribute, attrbuf) == 0)
                            break;
                        if (strcmp(cursor->attribute, "") == 0 &&
                            cursor->type == t_ignore) {
                            break;
                        }
                    }
                    if (cursor->attribute == NULL) {
//                        flb_plg_debug("Unknown attribute name '%s'"
//                                  " (attributes begin with '%s').\n",
//                                  attrbuf, attrs->attribute);
                        /* don't update end here, leave at attribute start */
                        return JSON_ERR_BADATTR;
                    }
                    state = await_value;
                    if (cursor->type == t_string)
                        maxlen = (int) cursor->len - 1;
                    else if (cursor->type == t_check)
                        maxlen = (int) strlen(cursor->dflt.check);
                    else if (cursor->type == t_time || cursor->type == t_ignore)
                        maxlen = JSON_VAL_MAX;
                    else if (cursor->map != NULL)
                        maxlen = (int) sizeof(valbuf) - 1;
                    pval = valbuf;
                } else if (pattr >= attrbuf + JSON_ATTR_MAX - 1) {
                    /* don't update end here, leave at attribute start */
//                    flb_plg_debug("Attribute name too long.\n");
                    return JSON_ERR_ATTRLEN;
                } else
                    *pattr++ = *cp;
                break;
            case await_value:
                if (isspace((unsigned char) *cp) || *cp == ':')
                    continue;
                else if (*cp == '[') {
                    if (cursor->type != t_array) {
//                        flb_plg_debug("Saw [ when not expecting array.\n");
                        if (end != NULL)
                            *end = cp;
                        return JSON_ERR_NOARRAY;
                    }
                    substatus = json_read_array(cp, &cursor->addr.array, &cp);
                    if (substatus != 0)
                        return substatus;
                    state = post_element;
                } else if (cursor->type == t_array) {
//                    flb_plg_debug("Array element was specified, but no [.\n");
                    if (end != NULL)
                        *end = cp;
                    return JSON_ERR_NOBRAK;
                } else if (*cp == '{') {
                    if (cursor->type != t_object) {
//                        flb_plg_debug("Saw { when not expecting object.\n");
                        if (end != NULL)
                            *end = cp;
                        return JSON_ERR_NOARRAY;
                    }
                    substatus = json_read_object(cp, cursor->addr.attrs, &cp);
                    if (substatus != 0)
                        return substatus;
                    --cp;    // last } will be re-consumed by cp++ at end of loop
                    state = post_element;
                } else if (cursor->type == t_object) {
//                    flb_plg_debug("Object element was specified, but no {.\n");
                    if (end != NULL)
                        *end = cp;
                    return JSON_ERR_NOCURLY;
                } else if (*cp == '"') {
                    value_quoted = true;
                    state = in_val_string;
                    pval = valbuf;
                } else {
                    value_quoted = false;
                    state = in_val_token;
                    pval = valbuf;
                    *pval++ = *cp;
                }
                break;
            case in_val_string:
                if (pval == NULL)
                    /* don't update end here, leave at value start */
                    return JSON_ERR_NULLPTR;
                if (*cp == '\\')
                    state = in_escape;
                else if (*cp == '"') {
                    *pval++ = '\0';
//                    flb_plg_debug("Collected string value %s\n", valbuf);
                    state = post_val;
                } else if (pval > valbuf + JSON_VAL_MAX - 1
                           || pval > valbuf + maxlen) {
//                    flb_plg_debug("String value too long.\n");
                    /* don't update end here, leave at value start */
                    return JSON_ERR_STRLONG;    /*  */
                } else
                    *pval++ = *cp;
                break;
            case in_escape:
                if (pval == NULL)
                    /* don't update end here, leave at value start */
                    return JSON_ERR_NULLPTR;
                else if (pval > valbuf + JSON_VAL_MAX - 1
                         || pval > valbuf + maxlen) {
//                    flb_plg_debug("String value too long.\n");
                    /* don't update end here, leave at value start */
                    return JSON_ERR_STRLONG;    /*  */
                }
                switch (*cp) {
                    case 'b':
                        *pval++ = '\b';
                        break;
                    case 'f':
                        *pval++ = '\f';
                        break;
                    case 'n':
                        *pval++ = '\n';
                        break;
                    case 'r':
                        *pval++ = '\r';
                        break;
                    case 't':
                        *pval++ = '\t';
                        break;
                    case 'u':
                        cp++;                   /* skip the 'u' */
                        for (n = 0; n < 4 && isxdigit(*cp); n++)
                            uescape[n] = *cp++;
                        uescape[n] = '\0';      /* terminate */
                        --cp;
                        /* ECMA-404 says JSON \u must have 4 hex digits */
                        if ((4 != n) || (1 != sscanf(uescape, "%4x", &u))) {
                            return JSON_ERR_BADSTRING;
                        }
                        *pval++ = (unsigned char) u;  /* truncate values above 0xff */
                        break;
                    default:        /* handles double quote and solidus */
                        *pval++ = *cp;
                        break;
                }
                state = in_val_string;
                break;
            case in_val_token:
                if (pval == NULL)
                    /* don't update end here, leave at value start */
                    return JSON_ERR_NULLPTR;
                if (isspace((unsigned char) *cp) || *cp == ',' || *cp == '}') {
                    *pval = '\0';
//                    flb_plg_debug("Collected token value %s.\n", valbuf);
                    state = post_val;
                    if (*cp == '}' || *cp == ',')
                        --cp;
                } else if (pval > valbuf + JSON_VAL_MAX - 1) {
//                    flb_plg_debug("Token value too long.\n");
                    /* don't update end here, leave at value start */
                    return JSON_ERR_TOKLONG;
                } else
                    *pval++ = *cp;
                break;
            case post_val:
                // Ignore whitespace after either string or token values.
                if (isspace(*cp)) {
                    while (*cp != '\0' && isspace((unsigned char) *cp)) {
                        ++cp;
                    }
//                    flb_plg_debug("Skipped trailing whitespace: value \"%s\"\n", valbuf);
                }
                /*
                 * We know that cursor points at the first spec matching
                 * the current attribute.  We don't know that it's *the*
                 * correct spec; our dialect allows there to be any number
                 * of adjacent ones with the same attrname but different
                 * types.  Here's where we try to seek forward for a
                 * matching type/attr pair if we're not looking at one.
                 */
                for (;;) {
                    int seeking = cursor->type;
                    if (value_quoted && (cursor->type == t_string
                                         || cursor->type == t_time))
                        break;
                    if ((strcmp(valbuf, "true") == 0 || strcmp(valbuf, "false") == 0
                         || isdigit((unsigned char) valbuf[0]))
                        && seeking == t_boolean)
                        break;
                    if (isdigit((unsigned char) valbuf[0])) {
                        bool decimal = strchr(valbuf, '.') != NULL;
                        if (decimal && seeking == t_real)
                            break;
                        if (!decimal && (seeking == t_integer
                                         || seeking == t_uinteger))
                            break;
                    }
                    if (cursor[1].attribute == NULL)    /* out of possiblities */
                        break;
                    if (strcmp(cursor[1].attribute, attrbuf) != 0)
                        break;
                    ++cursor;
                }
                if (value_quoted
                    && (cursor->type != t_string && cursor->type != t_character
                        && cursor->type != t_check && cursor->type != t_time
                        && cursor->type != t_ignore && cursor->map == 0)) {
//                    flb_plg_debug("Saw quoted value when expecting non-string.\n");
                    return JSON_ERR_QNONSTRING;
                }
                if (!value_quoted
                    && (cursor->type == t_string || cursor->type == t_check
                        || cursor->type == t_time || cursor->map != 0)) {
//                    flb_plg_debug("Didn't see quoted value when expecting string\n");
                    return JSON_ERR_NONQSTRING;
                }
                if (cursor->map != 0) {
                    for (mp = cursor->map; mp->name != NULL; mp++)
                        if (strcmp(mp->name, valbuf) == 0) {
                            goto foundit;
                        }
//                    flb_plg_debug("Invalid enumerated value string \"%s\".\n",  valbuf);
                    return JSON_ERR_BADENUM;
                    foundit:
                    (void) snprintf(valbuf, sizeof(valbuf), "%d", mp->value);
                }
                if (cursor->type == t_check) {
                    lptr = cursor->dflt.check;
                } else {
                    lptr = json_target_address(cursor, parent, offset);
                }
                if (lptr != NULL)
                    switch (cursor->type) {
                        case t_integer: {
                            int tmp = atoi(valbuf);
                            memcpy(lptr, &tmp, sizeof(int));
                        }
                            break;
                        case t_uinteger: {
                            unsigned int tmp = (unsigned int) atoi(valbuf);
                            memcpy(lptr, &tmp, sizeof(unsigned int));
                        }
                            break;
                        case t_short: {
                            short tmp = atoi(valbuf);
                            memcpy(lptr, &tmp, sizeof(short));
                        }
                            break;
                        case t_ushort: {
                            unsigned short tmp = (unsigned int) atoi(valbuf);
                            memcpy(lptr, &tmp, sizeof(unsigned short));
                        }
                            break;
                        case t_time:
#ifdef TIME_ENABLE
                            {
                            double tmp = iso8601_to_unix(valbuf);
                            memcpy(lptr, &tmp, sizeof(double));
                            }
#endif /* TIME_ENABLE */
                            break;
                        case t_real: {
                            double tmp = atof(valbuf);
                            memcpy(lptr, &tmp, sizeof(double));
                        }
                            break;
                        case t_string:
                            if (parent != NULL
                                && parent->element_type != t_structobject
                                && offset > 0)
                                return JSON_ERR_NOPARSTR;
                            else {
                                size_t vl = strlen(valbuf), cl = cursor->len - 1;
                                memset(lptr, '\0', cl);
                                memcpy(lptr, valbuf, vl < cl ? vl : cl);
                            }
                            break;
                        case t_boolean: {
                            bool tmp = (strcmp(valbuf, "true") == 0 || strtol(valbuf, NULL, 0));
                            memcpy(lptr, &tmp, sizeof(bool));
                        }
                            break;
                        case t_character:
                            if (strlen(valbuf) > 1)
                                /* don't update end here, leave at value start */
                                return JSON_ERR_STRLONG;
                            else
                                lptr[0] = valbuf[0];
                            break;
                        case t_ignore:    /* silences a compiler warning */
                        case t_object:    /* silences a compiler warning */
                        case t_structobject:
                        case t_array:
                            break;
                        case t_check:
                            if (strcmp(cursor->dflt.check, valbuf) != 0) {
//                                flb_plg_trace("Required attribute value %s not present.\n",
//                                          cursor->dflt.check);
                                /* don't update end here, leave at start of attribute */
                                return JSON_ERR_CHECKFAIL;
                            }
                            break;
                    }
                        __attribute__ ((fallthrough));
            case post_element:
                if (isspace((unsigned char) *cp))
                    continue;
                else if (*cp == ',')
                    state = await_attr;
                else if (*cp == '}') {
                    ++cp;
                    goto good_parse;
                } else {

//                    flb_plg_trace("Garbage while expecting comma or }\n");
                    if (end != NULL)
                        *end = cp;
                    return JSON_ERR_BADTRAIL;
                }
                break;
        }
    }
    if (state == init) {
//        flb_plg_trace("Input was empty or white-space only\n");
        return JSON_ERR_EMPTY;
    }

    good_parse:
    /* in case there's another object following, consume trailing WS */
    while (*cp != '\0' && isspace((unsigned char) *cp))
        ++cp;
    if (end != NULL)
        *end = cp;
//    flb_plg_trace("JSON parse ends.\n");
    return 0;
}

int json_read_array(const char *cp, const struct json_array_t *arr,
                    const char **end) {
    int substatus, offset, arrcount;
    char *tp;

    if (end != NULL)
        *end = NULL;    /* give it a well-defined value on parse failure */

//    flb_plg_trace("Entered json_read_array()\n");

    while (*cp != '\0' && isspace((unsigned char) *cp))
        cp++;
    if (*cp != '[') {
//        flb_plg_trace("Didn't find expected array start\n");
        return JSON_ERR_ARRAYSTART;
    } else
        cp++;

    tp = arr->arr.strings.store;
    arrcount = 0;

    /* Check for empty array */
    while (*cp != '\0' && isspace((unsigned char) *cp))
        cp++;
    if (*cp == ']')
        goto breakout;

    for (offset = 0; offset < arr->maxlen; offset++) {
        char *ep = NULL;
//        flb_plg_trace("Looking at %s\n", cp);
        switch (arr->element_type) {
            case t_string:
                while (*cp != '\0' && isspace((unsigned char) *cp))
                    cp++;
                if (*cp != '"')
                    return JSON_ERR_BADSTRING;
                else
                    ++cp;
                arr->arr.strings.ptrs[offset] = tp;
                for (; tp - arr->arr.strings.store < arr->arr.strings.storelen;
                       tp++)
                    if (*cp == '"') {
                        ++cp;
                        *tp++ = '\0';
                        goto stringend;
                    } else if (*cp == '\0') {
//                        flb_plg_trace("Bad string syntax in string list.\n");
                        return JSON_ERR_BADSTRING;
                    } else {
                        *tp = *cp++;
                    }
//                flb_plg_trace("Bad string syntax in string list.\n");
                return JSON_ERR_BADSTRING;
            stringend:
                break;
            case t_object:
            case t_structobject:
                substatus =
                        json_internal_read_object(cp, arr->arr.objects.subtype, arr,
                                                  offset, &cp);
                if (substatus != 0) {
                    if (end != NULL)
                        end = &cp;
                    return substatus;
                }
                break;
            case t_integer:
                arr->arr.integers.store[offset] = (int) strtol(cp, &ep, 0);
                if (ep == cp)
                    return JSON_ERR_BADNUM;
                else
                    cp = ep;
                break;
            case t_uinteger:
                arr->arr.uintegers.store[offset] = (unsigned int) strtoul(cp,
                                                                          &ep, 0);
                if (ep == cp)
                    return JSON_ERR_BADNUM;
                else
                    cp = ep;
                break;
            case t_short:
                arr->arr.shorts.store[offset] = (short) strtol(cp, &ep, 0);
                if (ep == cp)
                    return JSON_ERR_BADNUM;
                else
                    cp = ep;
                break;
            case t_ushort:
                arr->arr.ushorts.store[offset] = (unsigned short) strtol(cp, &ep, 0);
                if (ep == cp)
                    return JSON_ERR_BADNUM;
                else
                    cp = ep;
                break;
#ifdef TIME_ENABLE
                case t_time:
                    if (*cp != '"')
                    return JSON_ERR_BADSTRING;
                    else
                    ++cp;
                    arr->arr.reals.store[offset] = iso8601_to_unix((char *)cp);
                    if (arr->arr.reals.store[offset] >= HUGE_VAL)
                    return JSON_ERR_BADNUM;
                    while (*cp && *cp != '"')
                    cp++;
                    if (*cp != '"')
                    return JSON_ERR_BADSTRING;
                    else
                    ++cp;
                    break;
#endif /* TIME_ENABLE */
            case t_real:
                arr->arr.reals.store[offset] = strtod(cp, &ep);
                if (ep == cp)
                    return JSON_ERR_BADNUM;
                else
                    cp = ep;
                break;
            case t_boolean:
                if (str_starts_with(cp, "true")) {
                    arr->arr.booleans.store[offset] = true;
                    cp += 4;
                } else if (str_starts_with(cp, "false")) {
                    arr->arr.booleans.store[offset] = false;
                    cp += 5;
                } else {
                    int val = strtol(cp, &ep, 0);
                    if (ep == cp)
                        return JSON_ERR_BADNUM;
                    else {
                        arr->arr.booleans.store[offset] = (bool) val;
                        cp = ep;
                    }
                }
                break;
            case t_character:
            case t_array:
            case t_check:
            case t_ignore:
//                flb_plg_trace("Invalid array subtype.\n");
                return JSON_ERR_SUBTYPE;
        }
        arrcount++;
        while (*cp != '\0' && isspace((unsigned char) *cp))
            cp++;
        if (*cp == ']') {
//            flb_plg_trace("End of array found.\n");
            goto breakout;
        } else if (*cp == ',')
            cp++;
        else {
//            flb_plg_trace("Bad trailing syntax on array.\n");
            return JSON_ERR_BADSUBTRAIL;
        }
    }
//    flb_plg_trace("Too many elements in array.\n");
    if (end != NULL)
        *end = cp;
    return JSON_ERR_SUBTOOLONG;
    breakout:
    if (arr->count != NULL)
        *(arr->count) = arrcount;
    if (end != NULL)
        *end = cp;
//    flb_plg_trace("leaving json_read_array() with %d elements\n",
//              arrcount);
    return 0;
}

int json_read_object(const char *cp, const struct json_attr_t *attrs,
                     const char **end) {
    int st;

//    flb_plg_trace((1, "json_read_object() sees '%s'\n", cp));
    st = json_internal_read_object(cp, attrs, NULL, 0, end);
    return st;
}

const char *json_error_string(int err) {
    const char *errors[] = {
            "unknown error while parsing JSON",
            "non-whitespace when expecting object start",
            "non-whitespace when expecting attribute start",
            "unknown attribute name",
            "attribute name too long",
            "saw [ when not expecting array",
            "array element specified, but no [",
            "string value too long",
            "token value too long",
            "garbage while expecting comma or } or ]",
            "didn't find expected array start",
            "error while parsing object array",
            "too many array elements",
            "garbage while expecting array comma",
            "unsupported array element type",
            "error while string parsing",
            "check attribute not matched",
            "can't support strings in parallel arrays",
            "invalid enumerated value",
            "saw quoted value when expecting nonstring",
            "didn't see quoted value when expecting string",
            "other data conversion error",
            "unexpected null value or attribute pointer",
            "object element specified, but no {",
            "input was empty or white-space only",
    };

    if (err <= 0 || err >= (int) (sizeof(errors) / sizeof(errors[0])))
        return errors[0];
    else
        return errors[err];
}

/* end */

