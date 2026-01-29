/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_typecast.h>
#include <string.h>
#include <inttypes.h>
#include <msgpack.h>

flb_typecast_type_t flb_typecast_str_to_type_t(char *type_str, int type_len)
{
    if (!strncasecmp(type_str, "int", type_len)) {
        return FLB_TYPECAST_TYPE_INT;
    }
    else if (!strncasecmp(type_str, "uint", type_len)) {
        return FLB_TYPECAST_TYPE_UINT;
    }
    else if (!strncasecmp(type_str, "float", type_len)) {
      return FLB_TYPECAST_TYPE_FLOAT;
    }
    else if (!strncasecmp(type_str, "hex", type_len)) {
      return FLB_TYPECAST_TYPE_HEX;
    }
    else if (!strncasecmp(type_str, "string", type_len)) {
      return FLB_TYPECAST_TYPE_STR;
    }
    else if(!strncasecmp(type_str, "bool", type_len)) {
      return FLB_TYPECAST_TYPE_BOOL;
    }

    return FLB_TYPECAST_TYPE_ERROR;
}

const char * flb_typecast_type_t_to_str(flb_typecast_type_t type)
{
    switch(type) {
    case FLB_TYPECAST_TYPE_INT:
        return "int";
    case FLB_TYPECAST_TYPE_UINT:
        return "uint";
    case FLB_TYPECAST_TYPE_FLOAT:
        return "float";
    case FLB_TYPECAST_TYPE_HEX:
        return "hex";
    case FLB_TYPECAST_TYPE_STR:
        return "string";
    case FLB_TYPECAST_TYPE_BOOL:
        return "bool";
    default:
        return "unknown type";
    }

}

static int flb_typecast_conv_str(const char *input, int input_len,
                                 struct flb_typecast_rule *rule,
                                 msgpack_packer *pck,
                                 struct flb_typecast_value *output)
{
    flb_sds_t tmp_str;
    int ret = 0;
    char *endp = NULL;

    if(input == NULL || rule == NULL || output == NULL) {
        return -1;
    }
    else if (rule->from_type != FLB_TYPECAST_TYPE_STR) {
        flb_error("%s: Type is not string.",__FUNCTION__);
        return -1;
    }

    /*
     * msgpack char is not null terminated.
     *  So make a temporary copy.
     */
    tmp_str = flb_sds_create_len(input, input_len);
    if (tmp_str == NULL) {
        flb_errno();
        return -1;
    }

    switch(rule->to_type) {
    case FLB_TYPECAST_TYPE_INT:
      output->val.i_num = strtoimax(tmp_str, &endp, 10);
      if (output->val.i_num == 0 && (tmp_str == endp)) {
          flb_error("%s: convert error. input=%s", __FUNCTION__, tmp_str);
          ret = -1;
          goto typecast_conv_str_end;
      }
      if (pck != NULL) {
          msgpack_pack_int64(pck, output->val.i_num);
      }
      break;
    case FLB_TYPECAST_TYPE_UINT:
      output->val.ui_num = strtoumax(tmp_str, &endp, 10);
      if (output->val.ui_num == 0 && (tmp_str == endp)) {
          flb_error("%s: convert error. input=%s", __FUNCTION__, tmp_str);
          ret = -1;
          goto typecast_conv_str_end;
      }
      if (pck != NULL) {
          msgpack_pack_uint64(pck, output->val.ui_num);
      }
      break;
    case FLB_TYPECAST_TYPE_HEX:
      output->val.ui_num = strtoumax(tmp_str, NULL, 16);
      if (output->val.ui_num == 0) {
          flb_error("%s: convert error. input=%s", __FUNCTION__, tmp_str);
          ret = -1;
          goto typecast_conv_str_end;
      }
      if (pck != NULL) {
          msgpack_pack_uint64(pck, output->val.ui_num);
      }
      break;
    case FLB_TYPECAST_TYPE_FLOAT:
      output->val.d_num = atof(tmp_str);
      if (pck != NULL) {
          msgpack_pack_double(pck, output->val.d_num);
      }
      break;
    case FLB_TYPECAST_TYPE_BOOL:
      if (input_len >= 4 && !strncasecmp(tmp_str, "true", 4)) {
          output->val.boolean = FLB_TRUE;
      }
      else if (input_len >= 5 && !strncasecmp(tmp_str, "false", 5)) {
          output->val.boolean = FLB_FALSE;
      }
      else {
          flb_error("%s: convert error. input=%s", __FUNCTION__, tmp_str);
          ret = -1;
          goto typecast_conv_str_end;
      }

      if (pck != NULL) {
          if (output->val.boolean) {
              msgpack_pack_true(pck);
          }
          else {
              msgpack_pack_false(pck);
          }
      }

      break;
    case FLB_TYPECAST_TYPE_STR:
      flb_error("%s: str to str. nothing to do.", __FUNCTION__);
      return -1;
      break;
    default:
      flb_error("%s: unknown type %d", __FUNCTION__, rule->to_type);
      ret = -1;
    }
 typecast_conv_str_end:
    flb_sds_destroy(tmp_str);
    return ret;
}

static int flb_typecast_conv_bool(int input_bool,
                                  struct flb_typecast_rule *rule,
                                  msgpack_packer *pck,
                                  struct flb_typecast_value *output)
{
    if(rule == NULL || output == NULL) {
        return -1;
    }

    if (rule->to_type != FLB_TYPECAST_TYPE_STR) {
        flb_error("%s: type %s is not supported",__FUNCTION__,
                  flb_typecast_type_t_to_str(rule->to_type));
        return -1;
    }

    if (input_bool == FLB_TRUE) {
        output->val.str = flb_sds_create_len("true", 4);
        if (pck != NULL) {
            msgpack_pack_str(pck, 4);
            msgpack_pack_str_body(pck, "true", 4);
        }
        return 0;
    }
    else if (input_bool == FLB_FALSE) {
        output->val.str = flb_sds_create_len("false", 5);
        if (pck != NULL) {
            msgpack_pack_str(pck, 5);
            msgpack_pack_str_body(pck, "false", 5);
        }
        return 0;
    }
    flb_error("%s: unsupported input %d",__FUNCTION__,
              input_bool);
    return -1;
}

static int flb_typecast_conv_int(int64_t input,
                                 struct flb_typecast_rule *rule,
                                 msgpack_packer *pck,
                                 struct flb_typecast_value *output)
{
    char temp[32] = {0};
    int i;

    if(rule == NULL || output == NULL) {
        return -1;
    }

    switch(rule->to_type) {
    case FLB_TYPECAST_TYPE_STR:
      i = snprintf(temp, sizeof(temp) -1, "%"PRId64, input);
      output->val.str = flb_sds_create_len(temp, i);
      if(pck != NULL) {
          msgpack_pack_str(pck, i);
          msgpack_pack_str_body(pck, output->val.str, i);
      }
      break;

    case FLB_TYPECAST_TYPE_FLOAT:
      output->val.d_num = (double)input;
      if (pck != NULL) {
          msgpack_pack_double(pck, output->val.d_num);
      }
      break;
    case FLB_TYPECAST_TYPE_UINT:
      output->val.ui_num = (uint64_t)input;
      if (pck != NULL) {
          msgpack_pack_uint64(pck, output->val.ui_num);
      }
      break;

    default:
        flb_error("%s: type %s is not supported",__FUNCTION__,
                  flb_typecast_type_t_to_str(rule->to_type));
        return -1;
    }
    return 0;
}

static int flb_typecast_conv_uint(uint64_t input,
                                  struct flb_typecast_rule *rule,
                                  msgpack_packer *pck,
                                  struct flb_typecast_value *output)
{
    char temp[32] = {0};
    int i;

    if(rule == NULL || output == NULL) {
        return -1;
    }

    switch(rule->to_type) {
    case FLB_TYPECAST_TYPE_STR:
      i = snprintf(temp, sizeof(temp) -1, "%"PRIu64, input);
      output->val.str = flb_sds_create_len(temp, i);
      if(pck != NULL) {
          msgpack_pack_str(pck, i);
          msgpack_pack_str_body(pck, output->val.str, i);
      }
      break;

    case FLB_TYPECAST_TYPE_FLOAT:
      output->val.d_num = (double)input;
      if (pck != NULL) {
          msgpack_pack_double(pck, output->val.d_num);
      }
      break;
    case FLB_TYPECAST_TYPE_INT:
      output->val.i_num = (int64_t)input;
      if (pck != NULL) {
          msgpack_pack_int64(pck, output->val.ui_num);
      }
      break;

    default:
        flb_error("%s: type %s is not supported",__FUNCTION__,
                  flb_typecast_type_t_to_str(rule->to_type));
        return -1;
    }
    return 0;
}

static int flb_typecast_conv_float(double input,
                                   struct flb_typecast_rule *rule,
                                   msgpack_packer *pck,
                                   struct flb_typecast_value *output)
{
    char temp[512] = {0};
    int i;

    if(rule == NULL || output == NULL) {
        return -1;
    }

    switch(rule->to_type) {
    case FLB_TYPECAST_TYPE_STR:
      if (input == (double)(long long int)input) {
        i = snprintf(temp, sizeof(temp)-1, "%.1f", input);
      }
      else {
        i = snprintf(temp, sizeof(temp)-1, "%.16g", input);
      }
      output->val.str = flb_sds_create_len(temp, i);
      if(pck != NULL) {
          msgpack_pack_str(pck, i);
          msgpack_pack_str_body(pck, output->val.str, i);
      }
      break;
    case FLB_TYPECAST_TYPE_INT:
      output->val.i_num = (int64_t)input;
      if (pck != NULL) {
          msgpack_pack_int64(pck, output->val.ui_num);
      }
      break;
    case FLB_TYPECAST_TYPE_UINT:
      output->val.ui_num = (uint64_t)input;
      if (pck != NULL) {
          msgpack_pack_uint64(pck, output->val.ui_num);
      }
      break;

    default:
        flb_error("%s: type %s is not supported",__FUNCTION__,
                  flb_typecast_type_t_to_str(rule->to_type));
        return -1;
    }
    return 0;
}

int flb_typecast_rule_destroy(struct flb_typecast_rule *rule)
{
    if(rule == NULL) {
        return 0;
    }
    flb_free(rule);

    return 0;
}

struct flb_typecast_rule *flb_typecast_rule_create(char *from_type, int from_len,
                                                   char *to_type, int to_len)
{
    struct flb_typecast_rule *rule = NULL;

    if (from_type == NULL || to_type == NULL) {
        return NULL;
    }
    rule = flb_malloc(sizeof(struct flb_typecast_rule));
    if (rule == NULL) {
        flb_errno();
        return NULL;
    }

    rule->from_type = flb_typecast_str_to_type_t(from_type, from_len);
    if (rule->from_type == FLB_TYPECAST_TYPE_ERROR) {
        flb_error("%s: unknown from str %s", __FUNCTION__, from_type);
        flb_typecast_rule_destroy(rule);
        return NULL;
    }

    rule->to_type = flb_typecast_str_to_type_t(to_type, to_len);
    if (rule->to_type   == FLB_TYPECAST_TYPE_ERROR) {
        flb_error("%s: unknown to str %s", __FUNCTION__, to_type);
        flb_typecast_rule_destroy(rule);
        return NULL;
    }

    return rule;
}


/**
 * Convert msgpack object according to a rule.
 *
 * @param input msgpack object to be converted
 * @param rule  conversion rule
 * @param pck   msgpack packer to write converted object. If NULL, not to write.
 * @param output converted value. User must call flb_typecast_value_destroy after using.
 *               If NULL, not to be filled.
 *
 * @return 0 : success, !0: fail
 */
static int flb_typecast_value_conv(msgpack_object input,
                                   struct flb_typecast_rule *rule,
                                   msgpack_packer *pck,
                                   struct flb_typecast_value *output)
{
    int ret = -1;

    if (rule == NULL || output == NULL) {
        return -1;
    }

    switch(rule->from_type) {
    case FLB_TYPECAST_TYPE_STR:
        if (input.type != MSGPACK_OBJECT_STR) {
            flb_error("%s: src type is not str", __FUNCTION__);
            return -1;
        }
        ret = flb_typecast_conv_str(input.via.str.ptr,
                                    input.via.str.size,
                                    rule , pck, output);
        break;
    case FLB_TYPECAST_TYPE_BOOL:
        if (input.type != MSGPACK_OBJECT_BOOLEAN) {
            flb_error("%s: src type is not boolean", __FUNCTION__);
            return -1;
        }
        ret = flb_typecast_conv_bool(input.via.boolean ? FLB_TRUE:FLB_FALSE,
                                   rule, pck, output);
        break;
    case FLB_TYPECAST_TYPE_INT:
        if (input.type != MSGPACK_OBJECT_POSITIVE_INTEGER &&
            input.type != MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            flb_error("%s: src type is not int", __FUNCTION__);
            return -1;
        }
        ret = flb_typecast_conv_int(input.via.i64, rule, pck, output);

        break;
    case FLB_TYPECAST_TYPE_UINT:
        if (input.type != MSGPACK_OBJECT_POSITIVE_INTEGER &&
            input.type != MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            flb_error("%s: src type is not uint", __FUNCTION__);
            return -1;
        }
        ret = flb_typecast_conv_uint(input.via.u64, rule, pck, output);

        break;
    case FLB_TYPECAST_TYPE_FLOAT:
        if (input.type != MSGPACK_OBJECT_FLOAT32 &&
            input.type != MSGPACK_OBJECT_FLOAT64) {
            flb_error("%s: src type is not float", __FUNCTION__);
            return -1;
        }
        ret = flb_typecast_conv_float(input.via.f64, rule, pck, output);

        break;

    default:
      flb_error("%s: unknown type %d", __FUNCTION__, rule->from_type);
    }
    return ret;
}

int flb_typecast_value_destroy(struct flb_typecast_value* val)
{
    if (val == NULL) {
        return 0;
    }
    if (val->type == FLB_TYPECAST_TYPE_STR) {
        flb_sds_destroy(val->val.str);
    }
    flb_free(val);
    return 0;
}


struct flb_typecast_value *flb_typecast_value_create(msgpack_object input,
                                              struct flb_typecast_rule *rule)
{
    int ret = -1;
    struct flb_typecast_value *val;

    if (rule == NULL) {
        return NULL;
    }
    val = flb_malloc(sizeof(struct flb_typecast_value));
    if (val == NULL) {
        flb_errno();
        return NULL;
    }
    val->type = FLB_TYPECAST_TYPE_ERROR;
    ret = flb_typecast_value_conv(input, rule, NULL, val);
    if (ret < 0) {
        flb_free(val);
        return NULL;
    }
    val->type = rule->to_type;

    return val;
}

/**
 * Convert msgpack object according to a rule.
 *
 * @param input msgpack object to be converted
 * @param rule  conversion rule
 * @param pck   msgpack packer to write converted object
 *
 * @return 0 : success, !0: fail
 */
int flb_typecast_pack(msgpack_object input,
                      struct flb_typecast_rule *rule,
                      msgpack_packer *pck)
{
    int ret = -1;
    struct flb_typecast_value val;

    if (rule == NULL || pck == NULL) {
        flb_error("%s: input is null", __FUNCTION__);
        return -1;
    }

    ret = flb_typecast_value_conv(input, rule, pck, &val);

    if (ret == 0 && rule->to_type == FLB_TYPECAST_TYPE_STR) {
        flb_sds_destroy(val.val.str);
    }

    return ret;
}
