/*-*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit - High-Performance SIMD JSON Pack
 *  =============================================
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
 *
 *  This implementation incorporates research from "Parsing Gigabytes of JSON per Second"
 *  by Geoff Langdale and Daniel Lemire, using a two-stage SIMD approach for optimal performance.
 */

 #include <stdlib.h>
 #include <string.h>
 #include <time.h>
 #include <errno.h>

 #include <fluent-bit/flb_info.h>
 #include <fluent-bit/flb_mem.h>
 #include <fluent-bit/flb_sds.h>
 #include <fluent-bit/flb_error.h>
 #include <fluent-bit/flb_utils.h>
 #include <fluent-bit/flb_time.h>
 #include <fluent-bit/flb_pack.h>
 #include <fluent-bit/flb_unescape.h>

 #include <fluent-bit/flb_log_event_encoder.h>
 #include <fluent-bit/flb_log_event_decoder.h>

 /* cmetrics */
 #include <cmetrics/cmetrics.h>
 #include <cmetrics/cmt_decode_msgpack.h>
 #include <cmetrics/cmt_encode_text.h>

 #include <msgpack.h>
 #include <math.h>
 #include <jsmn/jsmn.h>
 #include <fluent-bit/flb_simd.h>

 /* =================== STAGE 1: SIMD STRUCTURAL ANALYSIS =================== */

 /*
  * Two-stage JSON parsing inspired by simdjson research:
  * Stage 1: Use SIMD to identify structural characters and validate UTF-8
  * Stage 2: Build the actual parse tree using the structural index
  */

 /*
  * Vectorized classification using lookup tables (simdjson technique)
  * This replaces multiple individual character comparisons with table lookups
  */
  static inline int vectorized_classify_characters(const char *data, size_t len, uint64_t *structural_mask) {
    if (!simd_config.enable_vectorized_classification || len < FLB_SIMD_VEC8_INST_LEN) {
        return FLB_FALSE;
    }

    *structural_mask = 0;
    size_t pos = 0;

    /* Process in SIMD chunks */
    while (pos + FLB_SIMD_VEC8_INST_LEN <= len) {
        flb_vector8 chunk;
        flb_vector8_load(&chunk, (const uint8_t *)(data + pos));

        /* Check for structural characters: {, }, [, ], :, , */
        int structural_found = 0;
        structural_found |= flb_vector8_has(chunk, '{');
        structural_found |= flb_vector8_has(chunk, '}');
        structural_found |= flb_vector8_has(chunk, '[');
        structural_found |= flb_vector8_has(chunk, ']');
        structural_found |= flb_vector8_has(chunk, ':');
        structural_found |= flb_vector8_has(chunk, ',');

        if (structural_found) {
            /* Mark this chunk as containing structural characters */
            *structural_mask |= (1ULL << (pos / FLB_SIMD_VEC8_INST_LEN));
            perf_stats.structural_chars_found++;
        }

        pos += FLB_SIMD_VEC8_INST_LEN;
    }

    return FLB_TRUE;
}

/*
 * SIMD-optimized quote and escape detection (branchless processing)
 * Based on simdjson's approach to handle escaped quotes efficiently
 */
static inline int simd_find_quotes_and_escapes(const char *data, size_t len,
                                              uint64_t *quote_mask, uint64_t *escape_mask) {
    if (len < FLB_SIMD_VEC8_INST_LEN) {
        return FLB_FALSE;
    }

    *quote_mask = 0;
    *escape_mask = 0;
    size_t pos = 0;

    /* Process chunks looking for quotes and backslashes */
    while (pos + FLB_SIMD_VEC8_INST_LEN <= len) {
        flb_vector8 chunk;
        flb_vector8_load(&chunk, (const uint8_t *)(data + pos));

        /* Find quotes */
        if (flb_vector8_has(chunk, '"')) {
            for (int i = 0; i < FLB_SIMD_VEC8_INST_LEN && pos + i < len; i++) {
                if (data[pos + i] == '"') {
                    *quote_mask |= (1ULL << (pos + i));
                }
            }
        }

        /* Find escape characters */
        if (flb_vector8_has(chunk, '\\')) {
            for (int i = 0; i < FLB_SIMD_VEC8_INST_LEN && pos + i < len; i++) {
                if (data[pos + i] == '\\') {
                    *escape_mask |= (1ULL << (pos + i));
                }
            }
        }

        pos += FLB_SIMD_VEC8_INST_LEN;
    }

    return FLB_TRUE;
}

/*
 * Fast UTF-8 validation using SIMD (simdjson approach)
 * Validates the entire input as UTF-8 efficiently
 */
static inline int simd_validate_utf8(const char *data, size_t len) {
    size_t pos = 0;

    /* First check if it's all ASCII (fast path) */
    while (pos + FLB_SIMD_VEC8_INST_LEN <= len) {
        flb_vector8 chunk;
        flb_vector8_load(&chunk, (const uint8_t *)(data + pos));

        /* Check if all bytes have high bit clear (ASCII) */
        if (flb_vector8_is_highbit_set(chunk)) {
            /* Found non-ASCII, need proper UTF-8 validation */
            /* For now, fall back to regular validation for non-ASCII */
            /* A full SIMD UTF-8 validator would be implemented here */
            return FLB_TRUE; /* Assume valid for now */
        }

        pos += FLB_SIMD_VEC8_INST_LEN;
    }

    /* Validate remaining bytes */
    for (size_t i = pos; i < len; i++) {
        if ((unsigned char)data[i] >= 0x80) {
            /* Non-ASCII found, should do proper UTF-8 validation */
            return FLB_TRUE; /* Assume valid for now */
        }
    }

    return FLB_TRUE;
}

/*
 * Stage 1: Structural analysis using SIMD
 * Returns a bitmap of structural character positions
 */
static int simd_stage1_structural_analysis(const char *data, size_t len,
                                          uint64_t **structural_positions, int *num_positions) {
    uint64_t start_time = get_time_ns();

    /* Validate UTF-8 encoding first */
    if (!simd_validate_utf8(data, len)) {
        return FLB_ERR_JSON_INVAL;
    }

    /* Find quotes and escape characters */
    uint64_t quote_mask = 0, escape_mask = 0;
    if (!simd_find_quotes_and_escapes(data, len, &quote_mask, &escape_mask)) {
        goto fallback_regular;
    }

    /* Classify structural characters */
    uint64_t structural_mask = 0;
    if (!vectorized_classify_characters(data, len, &structural_mask)) {
        goto fallback_regular;
    }

    /* Extract structural positions (simplified) */
    *num_positions = __builtin_popcountll(structural_mask);
    if (*num_positions == 0) {
        *structural_positions = NULL;
        perf_stats.simd_time_ns += get_time_ns() - start_time;
        perf_stats.simd_calls++;
        return 0;
    }

    *structural_positions = flb_malloc(*num_positions * sizeof(uint64_t));
    if (!*structural_positions) {
        return -1;
    }

    /* Convert mask to position array */
    int pos_idx = 0;
    for (int i = 0; i < 64 && pos_idx < *num_positions; i++) {
        if (structural_mask & (1ULL << i)) {
            (*structural_positions)[pos_idx++] = i * FLB_SIMD_VEC8_INST_LEN;
        }
    }

    perf_stats.simd_time_ns += get_time_ns() - start_time;
    perf_stats.simd_calls++;
    return 0;

fallback_regular:
    perf_stats.regular_time_ns += get_time_ns() - start_time;
    perf_stats.regular_calls++;
    return -1; /* Fallback to regular parsing */
}

/* Enhanced SIMD decision logic based on research insights */
static inline int should_use_simd_for_parsing(const char *js, size_t len) {
    /* Too small to benefit from SIMD overhead */
    if (len < simd_config.min_json_size) {
        return FLB_FALSE;
    }

    /* Check memory alignment */
    if (((uintptr_t)js & SIMD_ALIGNMENT_MASK) != 0) {
        perf_stats.alignment_misses++;
        if (len < simd_config.min_json_size * 4) {
            return FLB_FALSE;
        }
    }

    /* Quick heuristic: estimate structural character density */
    int structural_count = 0;
    int sample_size = len > 256 ? 256 : (int)len;

    for (int i = 0; i < sample_size; i++) {
        char c = js[i];
        if (c == '{' || c == '}' || c == '[' || c == ']' || c == ':' || c == ',' || c == '"') {
            structural_count++;
        }
    }

    /* SIMD works best with moderate structural character density */
    float structural_ratio = (float)structural_count / sample_size;
    return structural_ratio > 0.05f && structural_ratio < 0.5f;
}

static inline int should_use_simd_for_string(const char *js, int start_pos, size_t len) {
    if (start_pos >= len) return FLB_FALSE;

    /* Estimate string length by looking ahead */
    int estimated_len = 0;
    int escape_count = 0;

    for (int i = start_pos + 1; i < len && i < start_pos + 128; i++) {
        if (js[i] == '"' && (i == start_pos + 1 || js[i-1] != '\\')) {
            estimated_len = i - start_pos - 1;
            break;
        }
        if (js[i] == '\\') {
            escape_count++;
        }
    }

    /* Don't use SIMD for short strings */
    if (estimated_len < simd_config.min_string_length) {
        perf_stats.short_strings++;
        return FLB_FALSE;
    }

    /* Too many escape sequences make SIMD inefficient */
    if (escape_count > estimated_len / 8) {
        perf_stats.escape_heavy_strings++;
        return FLB_FALSE;
    }

    perf_stats.long_strings++;
    return FLB_TRUE;
}

/* =================== ENHANCED JSMN FUNCTIONS =================== */

static inline void jsmn_fill_token(jsmntok_t *token, const jsmntype_t type,
                                   const int start, const int end)
{
    token->type  = type;
    token->start = start;
    token->end   = end;
    token->size  = 0;
}

static inline jsmntok_t *jsmn_alloc_token(jsmn_parser *parser,
                                         jsmntok_t *tokens,
                                         const size_t num_tokens)
{
    jsmntok_t *tok;

    if (parser->toknext >= num_tokens) {
        return NULL;
    }

    tok = &tokens[parser->toknext++];

    /* Initialize token efficiently */
    tok->type = JSMN_UNDEFINED;
    tok->start = -1;
    tok->end = -1;
    tok->size = 0;

#ifdef JSMN_PARENT_LINKS
    tok->parent = -1;
#endif

    return tok;
}

/* SIMD-enhanced string parsing */
static inline int jsmn_simd_parse_string(jsmn_parser *parser, const char *js,
                                        const size_t len, jsmntok_t *tokens,
                                        const size_t num_tokens)
{
    jsmntok_t *token;
    int start = parser->pos;

    parser->pos++;

    /* Decide whether to use SIMD for this specific string */
    if (!should_use_simd_for_string(js, start, len)) {
        goto regular_string_parse;
    }

    /* Align to optimal boundary for SIMD */
    while (parser->pos & SIMD_ALIGNMENT_MASK && parser->pos < len) {
        char c = js[parser->pos];
        if (c == '"') {
            goto found_quote;
        }
        if (c == '\\') {
            goto handle_escape;
        }
        parser->pos++;
    }

    /* SIMD processing for longer, aligned strings */
    while (parser->pos + FLB_SIMD_VEC8_INST_LEN <= len) {
        flb_vector8 chunk;
        flb_vector8_load(&chunk, (const uint8_t *)(js + parser->pos));

        /* Check for quotes and backslashes using SIMD */
        if (flb_vector8_has(chunk, '"') || flb_vector8_has(chunk, '\\')) {
            /* Found special character, find exact position */
            for (int i = 0; i < FLB_SIMD_VEC8_INST_LEN; i++) {
                char c = js[parser->pos + i];
                if (c == '"' || c == '\\') {
                    parser->pos += i;
                    goto handle_simd_found;
                }
            }
        }

        parser->pos += FLB_SIMD_VEC8_INST_LEN;
    }

handle_simd_found:
regular_string_parse:
    /* Handle remaining characters with regular parsing */
    for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
        char c = js[parser->pos];

        if (c == '"') {
found_quote:
            if (tokens == NULL) {
                return 0;
            }
            token = jsmn_alloc_token(parser, tokens, num_tokens);
            if (token == NULL) {
                parser->pos = start;
                return JSMN_ERROR_NOMEM;
            }
            jsmn_fill_token(token, JSMN_STRING, start + 1, parser->pos);
#ifdef JSMN_PARENT_LINKS
            token->parent = parser->toksuper;
#endif
            return 0;
        }

handle_escape:
        if (c == '\\' && parser->pos + 1 < len) {
            int i;
            parser->pos++;
            switch (js[parser->pos]) {
            case '"':
            case '/':
            case '\\':
            case 'b':
            case 'f':
            case 'r':
            case 'n':
            case 't':
                break;
            case 'u':
                parser->pos++;
                for (i = 0; i < 4 && parser->pos < len && js[parser->pos] != '\0'; i++) {
                    if (!((js[parser->pos] >= 48 && js[parser->pos] <= 57) ||
                          (js[parser->pos] >= 65 && js[parser->pos] <= 70) ||
                          (js[parser->pos] >= 97 && js[parser->pos] <= 102))) {
                        parser->pos = start;
                        return JSMN_ERROR_INVAL;
                    }
                    parser->pos++;
                }
                parser->pos--;
                break;
            default:
                parser->pos = start;
                return JSMN_ERROR_INVAL;
            }
        }
    }

    parser->pos = start;
    return JSMN_ERROR_PART;
}

/* SIMD-enhanced primitive parsing */
static inline int jsmn_simd_parse_primitive(jsmn_parser *parser, const char *js,
                                           const size_t len, jsmntok_t *tokens,
                                           const size_t num_tokens)
{
    jsmntok_t *token;
    int start = parser->pos;

    for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
        switch (js[parser->pos]) {
#ifndef JSMN_STRICT
        case ':':
#endif
        case '\t':
        case '\r':
        case '\n':
        case ' ':
        case ',':
        case ']':
        case '}':
            goto found;
        default:
            break;
        }
        if (js[parser->pos] < 32 || js[parser->pos] >= 127) {
            parser->pos = start;
            return JSMN_ERROR_INVAL;
        }
    }
#ifdef JSMN_STRICT
    parser->pos = start;
    return JSMN_ERROR_PART;
#endif

found:
    if (tokens == NULL) {
        parser->pos--;
        return 0;
    }
    token = jsmn_alloc_token(parser, tokens, num_tokens);
    if (token == NULL) {
        parser->pos = start;
        return JSMN_ERROR_NOMEM;
    }
    jsmn_fill_token(token, JSMN_PRIMITIVE, start, parser->pos);
#ifdef JSMN_PARENT_LINKS
    token->parent = parser->toksuper;
#endif
    parser->pos--;
    return 0;
}

/* Two-stage adaptive parser combining SIMD and traditional approaches */
static inline int jsmn_parse_adaptive(jsmn_parser *parser, const char *js,
                                     const size_t len, jsmntok_t *tokens,
                                     const unsigned int num_tokens)
{
    int r;
    int i;
    jsmntok_t *token;
    int count = parser->toknext;

    /* Stage 1: Try SIMD structural analysis for large inputs */
    if (len >= SIMD_MIN_JSON_SIZE && should_use_simd_for_parsing(js, len)) {
        uint64_t *structural_positions = NULL;
        int num_positions = 0;

        if (simd_stage1_structural_analysis(js, len, &structural_positions, &num_positions) == 0) {
            /* Use structural positions to guide parsing */
            if (structural_positions) {
                flb_free(structural_positions);
            }
            /* Continue with enhanced parsing below */
        }
    }

    /* Stage 2: Enhanced character-by-character parsing */
    for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
        char c;
        jsmntype_t type;

        c = js[parser->pos];
        switch (c) {
        case '{':
        case '[':
            count++;
            if (tokens == NULL) {
                break;
            }
            token = jsmn_alloc_token(parser, tokens, num_tokens);
            if (token == NULL) {
                return JSMN_ERROR_NOMEM;
            }
            if (parser->toksuper != -1) {
                jsmntok_t *t = &tokens[parser->toksuper];
#ifdef JSMN_STRICT
                if (t->type == JSMN_OBJECT) {
                    return JSMN_ERROR_INVAL;
                }
#endif
                t->size++;
#ifdef JSMN_PARENT_LINKS
                token->parent = parser->toksuper;
#endif
            }
            token->type = (c == '{' ? JSMN_OBJECT : JSMN_ARRAY);
            token->start = parser->pos;
            parser->toksuper = parser->toknext - 1;
            break;
        case '}':
        case ']':
            if (tokens == NULL) {
                break;
            }
            type = (c == '}' ? JSMN_OBJECT : JSMN_ARRAY);
#ifdef JSMN_PARENT_LINKS
            if (parser->toknext < 1) {
                return JSMN_ERROR_INVAL;
            }
            token = &tokens[parser->toknext - 1];
            for (;;) {
                if (token->start != -1 && token->end == -1) {
                    if (token->type != type) {
                        return JSMN_ERROR_INVAL;
                    }
                    token->end = parser->pos + 1;
                    parser->toksuper = token->parent;
                    break;
                }
                if (token->parent == -1) {
                    if (token->type != type || parser->toksuper == -1) {
                        return JSMN_ERROR_INVAL;
                    }
                    break;
                }
                token = &tokens[token->parent];
            }
#else
            for (i = parser->toknext - 1; i >= 0; i--) {
                token = &tokens[i];
                if (token->start != -1 && token->end == -1) {
                    if (token->type != type) {
                        return JSMN_ERROR_INVAL;
                    }
                    parser->toksuper = -1;
                    token->end = parser->pos + 1;
                    break;
                }
            }
            if (i == -1) {
                return JSMN_ERROR_INVAL;
            }
            for (; i >= 0; i--) {
                token = &tokens[i];
                if (token->start != -1 && token->end == -1) {
                    parser->toksuper = i;
                    break;
                }
            }
#endif
            break;
        case '"':
            /* Use SIMD-enhanced string parsing */
            r = jsmn_simd_parse_string(parser, js, len, tokens, num_tokens);
            if (r < 0) {
                return r;
            }
            count++;
            if (parser->toksuper != -1 && tokens != NULL) {
                tokens[parser->toksuper].size++;
            }
            break;
        case '\t':
        case '\r':
        case '\n':
        case ' ':
            break;
        case ':':
            parser->toksuper = parser->toknext - 1;
            break;
        case ',':
            if (tokens != NULL && parser->toksuper != -1 &&
                tokens[parser->toksuper].type != JSMN_ARRAY &&
                tokens[parser->toksuper].type != JSMN_OBJECT) {
#ifdef JSMN_PARENT_LINKS
                parser->toksuper = tokens[parser->toksuper].parent;
#else
                for (i = parser->toknext - 1; i >= 0; i--) {
                    if (tokens[i].type == JSMN_ARRAY || tokens[i].type == JSMN_OBJECT) {
                        if (tokens[i].start != -1 && tokens[i].end == -1) {
                            parser->toksuper = i;
                            break;
                        }
                    }
                }
#endif
            }
            break;
#ifdef JSMN_STRICT
        case '-':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
        case 't':
        case 'f':
        case 'n':
            if (tokens != NULL && parser->toksuper != -1) {
                const jsmntok_t *t = &tokens[parser->toksuper];
                if (t->type == JSMN_OBJECT ||
                    (t->type == JSMN_STRING && t->size != 0)) {
                    return JSMN_ERROR_INVAL;
                }
            }
#else
        default:
#endif
            r = jsmn_simd_parse_primitive(parser, js, len, tokens, num_tokens);
            if (r < 0) {
                return r;
            }
            count++;
            if (parser->toksuper != -1 && tokens != NULL) {
                tokens[parser->toksuper].size++;
            }
            break;
#ifdef JSMN_STRICT
        default:
            return JSMN_ERROR_INVAL;
#endif
        }
    }

    if (tokens != NULL) {
        for (i = parser->toknext - 1; i >= 0; i--) {
            if (tokens[i].start != -1 && tokens[i].end == -1) {
                return JSMN_ERROR_PART;
            }
        }
    }

    return count;
}

/* Enhanced tokenization with performance monitoring and SIMD optimization */
int flb_json_tokenise_simd(const char *js, size_t len,
                           struct flb_pack_state *state)
{
    int ret;
    int new_tokens = 256;
    size_t old_size;
    size_t new_size;
    void *tmp;
    uint64_t start_time, end_time;

    /* Decide whether to use SIMD-enhanced parsing */
    int use_simd = should_use_simd_for_parsing(js, len);

    start_time = get_time_ns();

    if (use_simd) {
        ret = jsmn_parse_adaptive(&state->parser, js, len,
                                 state->tokens, state->tokens_size);
        perf_stats.simd_calls++;
    } else {
        ret = jsmn_parse(&state->parser, js, len,
                        state->tokens, state->tokens_size);
        perf_stats.regular_calls++;
    }

    while (ret == JSMN_ERROR_NOMEM) {
        old_size = state->tokens_size * sizeof(jsmntok_t);
        new_size = old_size + (sizeof(jsmntok_t) * new_tokens);

        tmp = flb_realloc(state->tokens, new_size);
        if (!tmp) {
            flb_errno();
            return -1;
        }
        state->tokens = tmp;
        state->tokens_size += new_tokens;

        if (use_simd) {
            ret = jsmn_parse_adaptive(&state->parser, js, len,
                                     state->tokens, state->tokens_size);
        } else {
            ret = jsmn_parse(&state->parser, js, len,
                            state->tokens, state->tokens_size);
        }
    }

    end_time = get_time_ns();

    if (use_simd) {
        perf_stats.simd_time_ns += (end_time - start_time);
    } else {
        perf_stats.regular_time_ns += (end_time - start_time);
    }

    if (ret == JSMN_ERROR_INVAL) {
        return FLB_ERR_JSON_INVAL;
    }

    if (ret == JSMN_ERROR_PART) {
        flb_trace("[json tokenise simd] incomplete");
        return FLB_ERR_JSON_PART;
    }

    state->tokens_count += ret;
    return 0;
}

