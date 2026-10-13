#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/fcntl.h>
#include "mem_pool.h"
#include "dex.h"
#include "dex_tools.h"
#include "debug.h"
#include "common/output_error.h"
#include "metadata.h"
#include "dex_meta_helper.h"
#include "decompiler/klass.h"
#include "dalvik/dex_class.h"

/*
 *  android 9.0 libdex/Leb128.h
 */

int read_unsigned_leb128(jd_meta_dex *dex)
{
    u1 uleb = 0;
    /* 累加用无符号：第 5 字节会左移到第 28 位，有符号移位是未定义行为。 */
    u4 result = 0;

    if (jdex_read1(dex, &uleb) == 0) return 0;
    result = uleb;
    if (result > 0x7f) {
        uleb = 0; if (jdex_read1(dex, &uleb) == 0) return result;
        result = (result & 0x7f) | ((uleb & 0x7f) << 7);
        if (uleb > 0x7f) {
            uleb = 0; if (jdex_read1(dex, &uleb) == 0) return result;
            result |= (uleb & 0x7f) << 14;
            if (uleb > 0x7f) {
                uleb = 0; if (jdex_read1(dex, &uleb) == 0) return result;
                result |= (uleb & 0x7f) << 21;
                if (uleb > 0x7f) {
                    uleb = 0; if (jdex_read1(dex, &uleb) == 0) return result;
                    result |= (u4) uleb << 28;
                }
            }
        }
    }
    return (int) result;
}

int read_signed_leb128(jd_meta_dex *dex)
{
    u4 result = 0;
    int shift = 0;
    u1 byte = 0;

    do {
        if (jdex_read1(dex, &byte) == 0)
            return (int) result;
        result |= (u4) (byte & 0x7f) << shift;
        shift += 7;
    } while ((byte & 0x80) != 0 && shift < 32);

    /* 最高有效位已置位时按符号位扩展，仍在无符号域内构造。 */
    if (shift < 32 && (byte & 0x40) != 0)
        result |= ~(u4) 0 << shift;
    return (int) result;
}

static void setup_current_offset(jd_meta_dex *dex, size_t offset)
{
    dex->bin->cur_off = offset;
}

/* 结构非法时置位：解析循环据此尽早停止，不再用错误的偏移或索引继续寻址。 */
static void dex_mark_invalid(jd_meta_dex *dex)
{
    if (dex->bin->error == NULL)
        dex->bin->error = "structure outside the file";
    dex->bin->overrun = true;
}

/* 带原因版本：说明具体是哪条约束被违反，便于报告与定位。 */
static void dex_mark_invalid_reason(jd_meta_dex *dex, const char *reason)
{
    if (dex->bin->error == NULL)
        dex->bin->error = reason;
    dex->bin->overrun = true;
}

static bool dex_invalid(jd_meta_dex *dex)
{
    return dex->bin->overrun;
}

static bool dex_range_ok(jd_meta_dex *dex, u8 offset, u8 length)
{
    if (offset > dex->bin->buffer_size || length > dex->bin->buffer_size - offset)
        return false;
    return true;
}

/* size 为 0 的表允许 offset 为 0；其余情况要求整张表落在文件内并按 4 字节对齐。
 * 对齐是规范要求：解析器把表起始地址直接转换为结构体指针，未对齐访问是未定义行为
 * （ARM 上会出错），参考实现同样拒绝未对齐的表。 */
static bool dex_table_ok(jd_meta_dex *dex, u4 offset, u4 size, u4 stride)
{
    if (size == 0)
        return true;
    if (offset % 4 != 0)
        return false;
    return dex_range_ok(dex, offset, (u8) size * stride);
}

/* 条目数上限：每个条目至少占 min_size 字节，防止按文件里的计数分配超大数组。 */
static bool dex_count_ok_at(jd_meta_dex *dex, size_t offset, u4 count, u4 min_size)
{
    if (offset > dex->bin->buffer_size)
        return false;
    u8 remaining = dex->bin->buffer_size - offset;
    if (min_size == 0)
        return count <= remaining;
    return (u8) count * min_size <= remaining;
}

/* uleb128p1：0 表示 NO_INDEX，其余减一后必须是合法表索引。 */
static u4 read_idx_p1(jd_meta_dex *dex, u4 table_size)
{
    u4 raw = read_unsigned_leb128(dex);
    if (raw == 0)
        return NO_INDEX;
    if (raw - 1 >= table_size) {
        dex_mark_invalid_reason(dex, "index outside its table");
        return NO_INDEX;
    }
    return raw - 1;
}

static void parse_dex_header(jd_meta_dex *dex)
{
    if (dex->bin->buffer_size < sizeof(dex_header)) {
        dex_mark_invalid_reason(dex, "file is smaller than the dex header");
        return;
    }
    dex->header = (dex_header *) dex->bin->buffer;
    if (dex->header->file_size > dex->bin->buffer_size)
        dex_mark_invalid_reason(dex, "header file_size exceeds the file");
    else if (dex->header->header_size != sizeof(dex_header))
        dex_mark_invalid_reason(dex, "unexpected header_size");
    else if (dex->header->endian_tag != 0x12345678u)
        dex_mark_invalid_reason(dex, "unexpected endian_tag");
}

static void parse_dex_links(jd_meta_dex *dex)
{
    if (dex_invalid(dex) || dex->header->link_size == 0) {
        dex->links = NULL;
        return;
    }
    if (!dex_range_ok(dex, dex->header->link_off, (u8) dex->header->link_size * 4)) {
        dex_mark_invalid(dex);
        return;
    }
    dex->links = (dex_link *) (dex->bin->buffer + dex->header->link_off);
}

static void parse_dex_map_list(jd_meta_dex *dex)
{
    if (dex_invalid(dex))
        return;
    u4 map_off = dex->header->map_off;
    if (map_off == 0 || !dex_range_ok(dex, map_off, 4)) {
        dex_mark_invalid(dex);
        return;
    }
    /* map_list 只做校验：map_off 只保证 4 字节对齐，不能按含指针的结构体访问。 */
    setup_current_offset(dex, map_off);
    u4 size = 0;
    jdex_read4(dex, &size);
    if (dex_invalid(dex) ||
        !dex_range_ok(dex, (u8) map_off + 4, (u8) size * sizeof(dex_map_item))) {
        dex_mark_invalid_reason(dex, "map_list outside the file");
    }
}

static int dex_string_byte_size(jd_meta_dex *dex, uint32_t utf16_size)
{
    int real, cnt;
    for (real = 0, cnt = 0; cnt < utf16_size; ++real, ++cnt) {
        /* 字符串内容必须以 NUL 结尾，并完整落在文件内。 */
        if (!dex_range_ok(dex, (u8) real + dex->bin->cur_off, 1)) {
            dex_mark_invalid(dex);
            return real;
        }
        unsigned char c = dex->bin->buffer[real + dex->bin->cur_off];
        if (c == 0) {
            dex_mark_invalid(dex);
            return real;
        }
        if (c > 0 && c < 127) {
        }
        else if (c >= 0xE0) {
            if (!dex_range_ok(dex, (u8) real + dex->bin->cur_off, 3)) {
                dex_mark_invalid(dex);
                return real;
            }
            real += 2;
        }
        else if (c >= 0xC2) {
            if (!dex_range_ok(dex, (u8) real + dex->bin->cur_off, 2)) {
                dex_mark_invalid(dex);
                return real;
            }
            real += 1;
        }
        else if (c == 0xC0) {
            if (!dex_range_ok(dex, (u8) real + 1 + dex->bin->cur_off, 1)) {
                dex_mark_invalid(dex);
                return real;
            }
            unsigned char nc = dex->bin->buffer[real+1 + dex->bin->cur_off];
            if (nc == 0x80)
                real += 1;
        }
        else {
            dex_mark_invalid(dex);
            return real;
        }
    }
    return real;
}

static void parse_dex_string_ids(jd_meta_dex *dex)
{
    dex_header *header = dex->header;
    if (dex_invalid(dex))
        return;
    if (!dex_table_ok(dex, header->string_ids_off, header->string_ids_size, sizeof(dex_string_id))) {
        dex_mark_invalid_reason(dex, "string_ids outside the file");
        return;
    }
    dex->string_ids = (dex_string_id *) (dex->bin->buffer + header->string_ids_off);


    dex->strings = make_obj_arr_in(dex_string_item,
                                   header->string_ids_size,
                                   dex->pool);
    for (int i = 0; i < header->string_ids_size; ++i) {
        if (dex_invalid(dex))
            return;
        dex_string_id *string_id = &dex->string_ids[i];
        dex_string_item *item = &dex->strings[i];

        if (!dex_range_ok(dex, string_id->string_data_off, 1)) {
            dex_mark_invalid(dex);
            return;
        }
        setup_current_offset(dex, string_id->string_data_off);

        int size = read_unsigned_leb128(dex);
        item->utf16_size = size;

        int real = dex_string_byte_size(dex, size);
        if (dex_invalid(dex))
            return;
        /* 长度前缀必须与实际内容一致并以 NUL 结束，否则字符串会被静默截断。
         * cur_off 已越过长度前缀，因此终止符位置是 cur_off + real。 */
        size_t content_off = dex->bin->cur_off;
        if (!dex_range_ok(dex, (u8) content_off + real, 1) ||
            dex->bin->buffer[content_off + real] != '\0') {
            dex_mark_invalid_reason(dex, "string_data_item length does not match utf16_size");
            return;
        }

        item->data = x_alloc_in(dex->pool, real+1);
        memset(item->data, 0, real+1);
        if (real > 0)
            jdex_read(dex, item->data, real);
        item->data[real] = '\0';
    }
}

static void parse_dex_type_ids(jd_meta_dex *dex)
{
    if (dex_invalid(dex))
        return;
    if (!dex_table_ok(dex, dex->header->type_ids_off, dex->header->type_ids_size, sizeof(dex_type_id))) {
        dex_mark_invalid_reason(dex, "type_ids outside the file");
        return;
    }
    dex->type_ids = (dex_type_id *) (dex->bin->buffer + dex->header->type_ids_off);
    for (u4 i = 0; i < dex->header->type_ids_size; ++i) {
        if (dex->type_ids[i].descriptor_idx >= dex->header->string_ids_size) {
            dex_mark_invalid_reason(dex, "type descriptor outside string_ids");
            return;
        }
    }
}

static void parse_dex_proto_ids(jd_meta_dex *dex)
{
    mem_pool *pool = dex->pool;
    u4 size = 0;
    dex_header *header = dex->header;
    if (dex_invalid(dex))
        return;
    if (!dex_table_ok(dex, header->proto_ids_off, header->proto_ids_size, sizeof(dex_proto_id))) {
        dex_mark_invalid_reason(dex, "proto_ids outside the file");
        return;
    }
    setup_current_offset(dex, header->proto_ids_off);
    size_t dex_type_item_size = sizeof(dex_type_item);
    size = header->proto_ids_size;
    dex->proto_ids = make_obj_arr_in(dex_proto_id, size, pool);
    for (int i = 0; i < header->proto_ids_size; ++i)
    {
        dex_proto_id *proto_id = &dex->proto_ids[i];
        jdex_read4(dex, &proto_id->shorty_idx);
        jdex_read4(dex, &proto_id->return_type_idx);
        jdex_read4(dex, &proto_id->parameters_off);
        if (proto_id->shorty_idx >= dex->header->string_ids_size) {
            dex_mark_invalid_reason(dex, "proto shorty outside string_ids");
            return;
        }
        if (proto_id->return_type_idx >= dex->header->type_ids_size) {
            dex_mark_invalid_reason(dex, "proto return type outside type_ids");
            return;
        }
    }

    for (int i = 0; i < header->proto_ids_size; ++i)
    {
        if (dex_invalid(dex))
            return;
        dex_proto_id *proto_id = &dex->proto_ids[i];
        if (proto_id->parameters_off == 0) {
            proto_id->type_list = NULL;
        }
        else {
            if (!dex_range_ok(dex, proto_id->parameters_off, 4)) {
                dex_mark_invalid(dex);
                return;
            }
            setup_current_offset(dex, proto_id->parameters_off);
            proto_id->type_list = make_obj_in(dex_type_list, dex->pool);
            jdex_read4(dex, &proto_id->type_list->size);

            size = proto_id->type_list->size;
            /* 每个条目占 2 字节，先确认整张表在文件内，避免按错误的尺寸分配。 */
            if (!dex_range_ok(dex, (u8) proto_id->parameters_off + 4, (u8) size * 2)) {
                dex_mark_invalid_reason(dex, "proto type_list outside the file");
                proto_id->type_list = NULL;
                return;
            }
            dex_type_item *list = make_obj_arr_in(dex_type_item, size, pool);
            proto_id->type_list->list = list;
            jdex_read(dex, list, dex_type_item_size*size);
        }
    }
    DEBUG_PRINT("[proto_ids_size]: %d\n", header->proto_ids_size);
}

static void parse_dex_field_ids(jd_meta_dex *dex)
{
    if (dex_invalid(dex))
        return;
    if (!dex_table_ok(dex, dex->header->field_ids_off, dex->header->field_ids_size, sizeof(dex_field_id))) {
        dex_mark_invalid_reason(dex, "field_ids outside the file");
        return;
    }
    dex->field_ids = (dex_field_id *) (dex->bin->buffer + dex->header->field_ids_off);
    for (u4 i = 0; i < dex->header->field_ids_size; ++i) {
        dex_field_id *field_id = &dex->field_ids[i];
        if (field_id->class_idx >= dex->header->type_ids_size) {
            dex_mark_invalid_reason(dex, "field class outside type_ids");
            return;
        }
        if (field_id->type_idx >= dex->header->type_ids_size) {
            dex_mark_invalid_reason(dex, "field type outside type_ids");
            return;
        }
        if (field_id->name_idx >= dex->header->string_ids_size) {
            dex_mark_invalid_reason(dex, "field name outside string_ids");
            return;
        }
    }
}

static void parse_dex_method_ids(jd_meta_dex *dex)
{
    if (dex_invalid(dex))
        return;
    if (!dex_table_ok(dex, dex->header->method_ids_off, dex->header->method_ids_size, sizeof(dex_method_id))) {
        dex_mark_invalid_reason(dex, "method_ids outside the file");
        return;
    }
    dex->method_ids = (dex_method_id *) (dex->bin->buffer + dex->header->method_ids_off);
    for (u4 i = 0; i < dex->header->method_ids_size; ++i) {
        dex_method_id *method_id = &dex->method_ids[i];
        if (method_id->class_idx >= dex->header->type_ids_size) {
            dex_mark_invalid_reason(dex, "method class outside type_ids");
            return;
        }
        if (method_id->proto_idx >= dex->header->proto_ids_size) {
            dex_mark_invalid_reason(dex, "method proto outside proto_ids");
            return;
        }
        if (method_id->name_idx >= dex->header->string_ids_size) {
            dex_mark_invalid_reason(dex, "method name outside string_ids");
            return;
        }
    }
}

static void parse_dex_class_interfaces(jd_meta_dex *dex, dex_class_def *cdef)
{
    if (cdef->interfaces_off == 0)
        return;

    if (!dex_range_ok(dex, cdef->interfaces_off, 4)) {
        dex_mark_invalid(dex);
        return;
    }
    setup_current_offset(dex, cdef->interfaces_off);
    cdef->interfaces = make_obj_in(dex_type_list, dex->pool);
    dex_type_list *interfaces = cdef->interfaces;
    jdex_read4(dex, &interfaces->size);

    u4 size = interfaces->size;
    size_t item_size = sizeof(dex_type_item);
    if (!dex_count_ok_at(dex, dex->bin->cur_off, size, item_size)) {
        dex_mark_invalid(dex);
        cdef->interfaces = NULL;
        return;
    }
    cdef->interfaces->list = make_obj_arr_in(dex_type_item, size, dex->pool);
    jdex_read(dex, interfaces->list, item_size*size);
}

/* 嵌套深度上限：每层至少消耗 1 字节，深嵌套会让递归耗尽栈。 */
#define DEX_MAX_ENCODED_DEPTH 32

static void parse_dex_encoded_value_depth(jd_meta_dex *dex, encoded_value *value, int depth);

static void parse_dex_encoded_value(jd_meta_dex *dex, encoded_value *value)
{
    parse_dex_encoded_value_depth(dex, value, 0);
}

static void parse_dex_encoded_value_depth(jd_meta_dex *dex, encoded_value *value, int depth)
{
    if (depth > DEX_MAX_ENCODED_DEPTH) {
        dex_mark_invalid_reason(dex, "encoded_value nesting too deep");
        return;
    }
    mem_pool *pool = dex->pool;
    u4 size = 0;
    jdex_read1(dex, &value->strict_value);
    value->value_type = value->strict_value & 0x1F;
    value->value_arg = value->strict_value >> 5;
    value->value_length = value->value_arg + 1;
    switch (value->value_type) {
        case kDexAnnotationBoolean:
            value->value_length = 0;
            break;
        case kDexAnnotationByte:
            value->value = make_obj_in(u1, pool);
            jdex_read1(dex, value->value);
            break;
        case kDexAnnotationShort:
        case kDexAnnotationChar:
        case kDexAnnotationInt:
        case kDexAnnotationLong:
        case kDexAnnotationFloat:
        case kDexAnnotationMethod:
        case kDexAnnotationDouble:
        case kDexAnnotationString:
        case kDexAnnotationType:
        case kDexAnnotationMethodType:
        case kDexAnnotationMethodHandle:
        case kDexAnnotationField:
        case kDexAnnotationEnum:
            value->value = x_alloc_in(dex->pool, value->value_length);
            memset(value->value, 0, value->value_length);
            jdex_read(dex, value->value, value->value_length);
            break;
        case kDexAnnotationArray: {
            encoded_array *en_array = make_obj_in(encoded_array, pool);
            size = read_unsigned_leb128(dex);
            if (!dex_count_ok_at(dex, dex->bin->cur_off, size, 1)) {
                dex_mark_invalid_reason(dex, "encoded_array size exceeds the file");
                value->value = NULL;
                return;
            }
            en_array->size = size;
            en_array->values = make_obj_arr_in(encoded_value, size, pool);
            for (int i = 0; i < en_array->size; ++i) {
                encoded_value *v = &en_array->values[i];
                parse_dex_encoded_value_depth(dex, v, depth + 1);
            }
            value->value = (u1*)en_array;
            break;
        }
        case kDexAnnotationAnnotation: {
            encoded_annotation *anno = make_obj_in(encoded_annotation, pool);
            anno->type_idx = read_unsigned_leb128(dex);

            size = read_unsigned_leb128(dex);
            if (!dex_count_ok_at(dex, dex->bin->cur_off, size, 2)) {
                dex_mark_invalid_reason(dex, "annotation size exceeds the file");
                value->value = NULL;
                return;
            }
            anno->size = size;
            anno->elements = make_obj_arr_in(annotation_element, size, pool);
            for (int i = 0; i < anno->size; ++i) {
                annotation_element *element = &anno->elements[i];
                element->name_idx = read_unsigned_leb128(dex);
                element->value = make_obj_in(encoded_value, pool);
                parse_dex_encoded_value_depth(dex, element->value, depth + 1);
            }
            value->value = (u1*)anno;
            break;
        }
        case kDexAnnotationNull:
            value->value_length = 0;
            break;
        default:
            /* 未定义的值类型是非法输入，不是内部不变量被破坏：标记后停止解析。 */
            DEBUG_PRINT("[annotation value]: value_type: %0x\n",
                        value->value_type);
            dex_mark_invalid_reason(dex, "unknown encoded_value type");
            value->value = NULL;
            break;
    }
}

static encoded_array *parse_dex_encoded_array(jd_meta_dex *dex)
{
    mem_pool *pool = dex->pool;
    encoded_array *array = make_obj_in(encoded_array, pool);
    array->size = (u4) read_unsigned_leb128(dex);
    if (array->size == 0) {
        array->values = NULL;
        return array;
    }
    if (!dex_count_ok_at(dex, dex->bin->cur_off, array->size, 1)) {
        dex_mark_invalid_reason(dex, "encoded_array size exceeds the file");
        array->size = 0;
        array->values = NULL;
        return array;
    }
    array->values = make_obj_arr_in(encoded_value, array->size, pool);
    for (u4 i = 0; i < array->size; ++i)
        parse_dex_encoded_value_depth(dex, &array->values[i], 1);
    return array;
}

static bool dex_map_find(jd_meta_dex *dex, u2 want, u4 *size, u4 *off)
{
    if (dex->header->map_off == 0)
        return false;
    setup_current_offset(dex, dex->header->map_off);
    u4 count = 0;
    jdex_read4(dex, &count);
    for (u4 i = 0; i < count; ++i) {
        u2 type = 0, unused = 0;
        u4 item_size = 0, item_off = 0;
        jdex_read2(dex, &type);
        jdex_read2(dex, &unused);
        jdex_read4(dex, &item_size);
        jdex_read4(dex, &item_off);
        if (type == want) {
            *size = item_size;
            *off = item_off;
            return true;
        }
    }
    return false;
}

static void parse_dex_method_handles(jd_meta_dex *dex)
{
    dex->method_handles = NULL;
    dex->method_handles_size = 0;
    u4 size = 0, off = 0;
    if (!dex_map_find(dex, kDexTypeMethodHandleItem, &size, &off) || size == 0)
        return;
    if (!dex_count_ok_at(dex, off, size, 8)) {
        dex_mark_invalid_reason(dex, "method_handles section exceeds the file");
        return;
    }
    dex->method_handles = make_obj_arr_in(dex_method_handle_item, size, dex->pool);
    dex->method_handles_size = size;
    setup_current_offset(dex, off);
    for (u4 i = 0; i < size; ++i) {
        dex_method_handle_item *handle = &dex->method_handles[i];
        jdex_read2(dex, &handle->method_handle_type);
        jdex_read2(dex, &handle->reserved1);
        jdex_read2(dex, &handle->field_or_method_idx);
        jdex_read2(dex, &handle->reserved2);
    }
}

static void parse_dex_call_sites(jd_meta_dex *dex)
{
    dex->call_sites = NULL;
    dex->call_sites_size = 0;
    u4 size = 0, off = 0;
    if (!dex_map_find(dex, kDexTypeCallSiteIdItem, &size, &off) || size == 0)
        return;
    if (!dex_count_ok_at(dex, off, size, 4)) {
        dex_mark_invalid_reason(dex, "call_sites section exceeds the file");
        return;
    }
    dex->call_sites = make_obj_arr_in(encoded_array, size, dex->pool);
    dex->call_sites_size = size;
    for (u4 i = 0; i < size; ++i) {
        setup_current_offset(dex, off + i * 4);
        u4 site_off = 0;
        jdex_read4(dex, &site_off);
        setup_current_offset(dex, site_off);
        encoded_array *site = parse_dex_encoded_array(dex);
        dex->call_sites[i] = *site;
    }
}

static void parse_dex_annotation_off_item(jd_meta_dex *dex,
                                          annotation_off_item *off_item)
{
    mem_pool *pool = dex->pool;
    u4 size = 0;

    off_item->annotation_item = make_obj_in(annotation_item, pool);
    setup_current_offset(dex, off_item->annotations_off);

    annotation_item *item = off_item->annotation_item;
    item->encoded_annotation = make_obj_in(encoded_annotation, pool);
    jdex_read1(dex, &item->visibility);

    encoded_annotation *eanno = item->encoded_annotation;
    eanno->type_idx = read_unsigned_leb128(dex);
    size = read_unsigned_leb128(dex);
    if (!dex_count_ok_at(dex, dex->bin->cur_off, size, 2)) {
        dex_mark_invalid_reason(dex, "annotation size exceeds the file");
        return;
    }
    eanno->size = size;
    eanno->elements = make_obj_arr_in(annotation_element, size, pool);
    for (int i = 0; i < eanno->size; ++i) {
        annotation_element *element = &eanno->elements[i];
        element->name_idx = read_unsigned_leb128(dex);
        element->value = make_obj_in(encoded_value, dex->pool);

        parse_dex_encoded_value_depth(dex, element->value, 1);
    }

}

static annotation_set_item* parse_dex_ano_set_item(jd_meta_dex *dex,
                                                   u4 offset)
{
    if (dex_invalid(dex) || !dex_range_ok(dex, offset, 4))
        return NULL;
    setup_current_offset(dex, offset);
    annotation_set_item *item = make_obj_in(annotation_set_item, dex->pool);
    jdex_read4(dex, &item->size);
    if (!dex_count_ok_at(dex, dex->bin->cur_off, item->size, 4)) {
        dex_mark_invalid(dex);
        return NULL;
    }
    item->entries = make_obj_arr_in(annotation_off_item, item->size, dex->pool);
    for (int i = 0; i < item->size; ++i) {
        annotation_off_item *off_item = &item->entries[i];
        jdex_read4(dex, &off_item->annotations_off);
    }

    for (int i = 0; i < item->size; ++i) {
        annotation_off_item *off_item = &item->entries[i];
        parse_dex_annotation_off_item(dex, off_item);
    }
    return item;
}

static ano_ref_list* parse_dex_ano_ref_list(jd_meta_dex *dex, u4 offset)
{
    if (dex_invalid(dex) || !dex_range_ok(dex, offset, 4))
        return NULL;
    setup_current_offset(dex, offset);
    ano_ref_list *ref_list = make_obj_in(ano_ref_list, dex->pool);

    jdex_read4(dex, &ref_list->size);
    if (!dex_count_ok_at(dex, dex->bin->cur_off, ref_list->size, 4)) {
        dex_mark_invalid(dex);
        return NULL;
    }
    ref_list->list = make_obj_arr_in(ano_ref_item, ref_list->size, dex->pool);
    for (int i = 0; i < ref_list->size; ++i) {
        annotation_set_ref_item *item = &ref_list->list[i];
        jdex_read4(dex, &item->annotations_off);
    }

    for (int i = 0; i < ref_list->size; ++i) {
        annotation_set_ref_item *item = &ref_list->list[i];
        u4 off = item->annotations_off;
        if (off > 0)
            item->annotation = parse_dex_ano_set_item(dex,off);
    }

    return ref_list;
}

static void parse_dex_class_defs_anos(jd_meta_dex *dex, dex_class_def *cf)
{
    if (cf->annotations_off == 0)
        return;
    setup_current_offset(dex, cf->annotations_off);

    mem_pool *pool = dex->pool;
    u4 size = 0;
    u4 off = 0;

    dex_ano_dict_item *dict = make_obj_in(dex_ano_dict_item, pool);
    cf->annotations = dict;
    jdex_read4(dex, &dict->class_annotations_off);
    jdex_read4(dex, &dict->fields_size);
    jdex_read4(dex, &dict->methods_size);
    jdex_read4(dex, &dict->parameters_size);

    size = dict->fields_size;
    if (size > 0) {
        if (!dex_count_ok_at(dex, dex->bin->cur_off, size, 8)) {
            dex_mark_invalid_reason(dex, "annotated fields exceed the file");
            return;
        }
        dict->field_annotations = make_obj_arr_in(field_annotation, size, pool);
        for (int j = 0; j < size; ++j) {
            field_annotation *fa = &dict->field_annotations[j];
            jdex_read4(dex, &fa->field_idx);
            jdex_read4(dex, &fa->annotations_off);
        }
    }

    size = dict->methods_size;
    if (size > 0) {
        if (!dex_count_ok_at(dex, dex->bin->cur_off, size, 8)) {
            dex_mark_invalid_reason(dex, "annotated methods exceed the file");
            return;
        }
        dict->method_annotations = make_obj_arr_in(meth_ano, size, pool);
        for (int j = 0; j < size; ++j) {
            meth_ano *ma = &dict->method_annotations[j];
            jdex_read4(dex, &ma->method_idx);
            jdex_read4(dex, &ma->annotations_off);
        }
    }

    size = dict->parameters_size;
    if (size > 0) {
        if (!dex_count_ok_at(dex, dex->bin->cur_off, size, 8)) {
            dex_mark_invalid_reason(dex, "annotated parameters exceed the file");
            return;
        }
        dict->parameter_annotations = make_obj_arr_in(param_ano, size, pool);
        for (int j = 0; j < size; ++j) {
            parameter_annotation *pa = &dict->parameter_annotations[j];
            jdex_read4(dex, &pa->method_idx);
            jdex_read4(dex, &pa->annotations_off);
        }
    }

    off = dict->class_annotations_off;
    if (off > 0)
        dict->class_annotation = parse_dex_ano_set_item(dex,off);

    size = dict->fields_size;
    if (size > 0) {
        for (int j = 0; j < size; ++j) {
            field_annotation *fa = &dict->field_annotations[j];
            fa->annotation = parse_dex_ano_set_item(dex, fa->annotations_off);
        }
    }

    if (dict->methods_size > 0) {
        for (int j = 0; j < dict->methods_size; ++j) {
            method_annotation *ma = &dict->method_annotations[j];
            ma->annotation = parse_dex_ano_set_item(dex, ma->annotations_off);
        }
    }

    if (dict->parameters_size > 0) {
        for (int j = 0; j < dict->parameters_size; ++j) {
            parameter_annotation *pa = &dict->parameter_annotations[j];
            pa->annotation = parse_dex_ano_ref_list(dex, pa->annotations_off);
        }
    }
}

static void parse_dex_encoded_field(jd_meta_dex *dex, encoded_field *field)
{
    field->field_idx_diff = read_unsigned_leb128(dex);
    field->access_flags = read_unsigned_leb128(dex);
}

static void parse_dex_encoded_method(jd_meta_dex *dex, encoded_method *method)
{
    method->method_idx_diff = read_unsigned_leb128(dex);
    method->access_flags = read_unsigned_leb128(dex);
    method->code_off = read_unsigned_leb128(dex);
}

static void parse_dex_code_try_item(jd_meta_dex *dex, dex_code_item *code)
{
    mem_pool *pool = dex->pool;
    if (code->tries_size == 0)
        return;

    if (!dex_count_ok_at(dex, dex->bin->cur_off, code->tries_size, sizeof(dex_try_item))) {
        dex_mark_invalid(dex);
        return;
    }
    if (code->tries_size > 0 && code->insns_size % 2 > 0) {
        jdex_read2(dex, &code->padding);
    }
    if (code->tries_size == 0)
        return;

    code->tries = make_obj_arr_in(dex_try_item, code->tries_size, pool);
    for (int i = 0; i < code->tries_size; ++i) {
        dex_try_item *try_item = &code->tries[i];
        jdex_read4(dex, &try_item->start_addr);
        jdex_read2(dex, &try_item->insn_count);
        jdex_read2(dex, &try_item->handler_off);
        /* 区间必须落在 insns 内，否则异常表会按越界地址寻址。 */
        if ((u8) try_item->start_addr + try_item->insn_count > code->insns_size) {
            dex_mark_invalid_reason(dex, "try range outside insns");
            return;
        }
        if (try_item->handler_off >= dex->bin->buffer_size) {
            dex_mark_invalid_reason(dex, "handler_off outside the handler list");
            return;
        }
        DEBUG_PRINT("[try_item]:"
                    "startAddr: %d "
                    "insnCount: %d, "
                    "range: %d -> %d "
                    "handlerOff: %d\n",
                    try_item->start_addr,
                    try_item->insn_count,
                    try_item->start_addr,
                    try_item->start_addr + try_item->insn_count - 1,
                    try_item->handler_off);
    }

    u4 handler_offset = dex->bin->cur_off;
    code->handlers = make_obj_in(encoded_catch_handler_list, dex->pool);
    u4 size = read_unsigned_leb128(dex);
    code->handlers->size = size;
    if (!dex_count_ok_at(dex, dex->bin->cur_off, size, 0)) {
        dex_mark_invalid(dex);
        return;
    }
    code->handlers->list = make_obj_arr_in(encoded_catch_handler, size, pool);
    DEBUG_PRINT("handlers size: %d\n", code->handlers->size);
    for (int j = 0; j < code->handlers->size; ++j) {
        DEBUG_PRINT("handler: %zu\n", dex->bin->cur_off - handler_offset);
        encoded_catch_handler *handler = &code->handlers->list[j];
        handler->handler_off = dex->bin->cur_off - handler_offset;
        handler->size = read_signed_leb128(dex);

        if (dex_invalid(dex))
            return;
        if (handler->size != 0) {
            int sz = abs(handler->size);
            if (!dex_count_ok_at(dex, dex->bin->cur_off, sz, 2)) {
                dex_mark_invalid(dex);
                return;
            }
            encoded_tp *pairs = make_obj_arr_in(encoded_tp, sz, pool);
            handler->handlers = pairs;
            for (int k = 0; k < abs(handler->size); ++k) {
                encoded_tp *pair = &pairs[k];
                pair->type_idx = read_unsigned_leb128(dex);
                pair->addr = read_unsigned_leb128(dex);
                DEBUG_PRINT("\ttype_idx: %d addr: %d\n",
                            pair->type_idx, pair->addr);
            }
        }
        if (handler->size <= 0) {
            handler->catch_all_addr = read_unsigned_leb128(dex);
            DEBUG_PRINT("\tcatch_all_addr: %d\n", handler->catch_all_addr);
        }
    }
}

static void parse_dex_code_debug_item(jd_meta_dex *dex, dex_code_item *code)
{
    mem_pool *pool = dex->pool;
    if (code->debug_info_off == 0)
        return;

    setup_current_offset(dex, code->debug_info_off);
    code->debug_info = make_obj_in(dex_debug_info_item, pool);
    dex_debug_info_item *debug_info = code->debug_info;
    debug_info->line_start = read_unsigned_leb128(dex);
    debug_info->parameters_size = read_unsigned_leb128(dex);
    /* 每个参数在流中至少占 1 字节，先确认计数与文件剩余字节相符。 */
    if (!dex_count_ok_at(dex, dex->bin->cur_off, debug_info->parameters_size, 0)) {
        dex_mark_invalid_reason(dex, "debug parameters_size exceeds the file");
        return;
    }
    debug_info->parameter_name = make_obj_arr_in(u4, debug_info->parameters_size, pool);

    u4 current_offset = dex->bin->cur_off;

    DEBUG_PRINT("[DEBUG_INFO]: %d line_start: %d, parameters_size: %d\n",
           code->debug_info_off,
           debug_info->line_start,
           debug_info->parameters_size);

    u2 dbg_size = 0;

    /* 每个参数是 uleb128p1，至少占 1 字节；上面的计数检查保证游标不会越过缓冲末尾。 */
    for (int i = 0; i < debug_info->parameters_size; ++i) {
        read_unsigned_leb128(dex);
        if (dex_invalid(dex))
            return;
    }
    dbg_size += debug_info->parameters_size;
    /* 读到缓冲末尾时 jd_bin_read 不写入目标，必须按读取失败退出，否则本循环不会结束。 */
    u1 dbg_opcode = DBG_END_SEQUENCE;
    while (1) {
        if (jdex_read1(dex, &dbg_opcode) == 0 || dex_invalid(dex))
            return;
        if (dbg_opcode == DBG_END_SEQUENCE)
            break;
        switch (dbg_opcode) {
            case DBG_ADVANCE_LINE: {
                read_signed_leb128(dex);
                break;
            }
            case DBG_START_LOCAL: {
                read_unsigned_leb128(dex);
                read_unsigned_leb128(dex);
                read_unsigned_leb128(dex);
                dbg_size ++;
                break;
            }
            case DBG_START_LOCAL_EXTENDED: {
                s4 reg = read_unsigned_leb128(dex);
                u4 name_idx = read_unsigned_leb128(dex);
                u4 type_idx = read_unsigned_leb128(dex);
                u4 sig_idx = read_unsigned_leb128(dex);
                dbg_size ++;
                break;
            }
            case DBG_SET_FILE:
            case DBG_END_LOCAL:
            case DBG_RESTART_LOCAL:
                read_unsigned_leb128(dex);
                dbg_size++;
                break;
            case DBG_ADVANCE_PC:
                read_unsigned_leb128(dex);
                break;
            case DBG_SET_PROLOGUE_END:
            case DBG_SET_EPILOGUE_BEGIN:
                dbg_size++;
                break;
            default:
                dbg_size++;
                break;
        }
    }

    setup_current_offset(dex, current_offset);
    dex_dbg_item *items = make_obj_arr_in(dex_dbg_item, dbg_size, pool);
    memset(items, 0, sizeof(*items) * dbg_size);
    debug_info->dbg_size = dbg_size;
    debug_info->items = items;
    u4 itor = 0;
    for (int i = 0; i < debug_info->parameters_size; ++i) {
        u4 name_idx = read_idx_p1(dex, dex->header->string_ids_size);
        debug_info->parameter_name[i] = name_idx;
        if (name_idx != NO_INDEX) {
            string param_name = dex_str_of_idx(dex, name_idx);
            DEBUG_PRINT("\tparameter_name: %d %s index: %d\n",
                   name_idx, param_name, i);
        }
        dex_dbg_item *dbg_item = &items[itor];
        dbg_item->name_idx = debug_info->parameter_name[i];
        dbg_item->type_idx = NO_INDEX;
        dbg_item->sig_idx = NO_INDEX;
        dbg_item->code = DBG_START_LOCAL;
        dbg_item->offset = 0;
        dbg_item->reg_num = i;
        itor++;
    }

    dbg_opcode = 0;
    u4 address = 0;
    s4 line = (s4) debug_info->line_start;
    while (1) {
        /* 同第一趟：读取失败必须退出；条目数超过第一趟的计数说明流被截断。 */
        if (jdex_read1(dex, &dbg_opcode) == 0 || dex_invalid(dex))
            break;
        if (dbg_opcode == DBG_END_SEQUENCE)
            break;
        if (itor >= dbg_size) {
            dex_mark_invalid_reason(dex, "debug_info has more items than the first pass counted");
            break;
        }
        switch (dbg_opcode) {
            case DBG_ADVANCE_PC: {
                u4 addr_diff = read_unsigned_leb128(dex);
                address += addr_diff;
                DEBUG_PRINT("\t[DBG_ADVANCE_PC]: %d\n", addr_diff);
                break;
            }
            case DBG_ADVANCE_LINE: {
                s4 line_diff = read_signed_leb128(dex);
                line += line_diff;
                DEBUG_PRINT("\t[DBG_ADVANCE_LINE]: %d\n", line_diff);
                break;
            }
            case DBG_START_LOCAL: {
                s4 reg = read_unsigned_leb128(dex);
                u4 name_idx = read_idx_p1(dex, dex->header->string_ids_size);
                u4 type_idx = read_idx_p1(dex, dex->header->type_ids_size);

                dex_dbg_item *dbg_item = &items[itor++];
                dbg_item->code = DBG_START_LOCAL;
                dbg_item->offset = address;
                dbg_item->reg_num = reg;
                dbg_item->name_idx = name_idx;
                dbg_item->type_idx = type_idx;
                dbg_item->sig_idx = NO_INDEX;
                break;
            }
            case DBG_START_LOCAL_EXTENDED: {
                s4 reg = read_unsigned_leb128(dex);
                u4 name_idx = read_idx_p1(dex, dex->header->string_ids_size);
                u4 type_idx = read_idx_p1(dex, dex->header->type_ids_size);
                u4 sig_idx = read_idx_p1(dex, dex->header->string_ids_size);

                dex_dbg_item *dbg_item = &items[itor++];
                dbg_item->code = DBG_START_LOCAL_EXTENDED;
                dbg_item->offset = address;
                dbg_item->reg_num = reg;
                dbg_item->name_idx = name_idx;
                dbg_item->type_idx = type_idx;
                dbg_item->sig_idx = sig_idx;
                break;
            }
            case DBG_END_LOCAL:
            case DBG_RESTART_LOCAL: {
                s4 reg = read_unsigned_leb128(dex);
                dex_dbg_item *dbg_item = &items[itor++];
                dbg_item->code = dbg_opcode;
                dbg_item->offset = address;
                dbg_item->reg_num = reg;
                dbg_item->name_idx = NO_INDEX;
                dbg_item->type_idx = NO_INDEX;
                dbg_item->sig_idx = NO_INDEX;
                break;
            }
            case DBG_SET_PROLOGUE_END:
            case DBG_SET_EPILOGUE_BEGIN: {
                dex_dbg_item *dbg_item = &items[itor++];
                dbg_item->code = dbg_opcode;
                dbg_item->offset = address;
                dbg_item->name_idx = NO_INDEX;
                dbg_item->type_idx = NO_INDEX;
                dbg_item->sig_idx = NO_INDEX;
                break;
            }
            case DBG_SET_FILE: {
                u4 name_idx = read_idx_p1(dex, dex->header->string_ids_size);
                dex_dbg_item *dbg_item = &items[itor++];
                dbg_item->code = DBG_SET_FILE;
                dbg_item->offset = address;
                dbg_item->name_idx = name_idx;
                dbg_item->type_idx = NO_INDEX;
                dbg_item->sig_idx = NO_INDEX;
                DEBUG_PRINT("\t[DBG_SET_FILE]: %d\n", name_idx);
                break;
            }
            default: {
                u4 adjusted_opcode = dbg_opcode - DBG_FIRST_SPECIAL;
                address += (adjusted_opcode / DBG_LINE_RANGE);
                line += (s4) (adjusted_opcode % DBG_LINE_RANGE) + DBG_LINE_BASE;
                dex_dbg_item *dbg_item = &items[itor++];
                dbg_item->code = DBG_FIRST_SPECIAL;
                dbg_item->offset = address;
                dbg_item->name_idx = NO_INDEX;
                dbg_item->type_idx = NO_INDEX;
                dbg_item->sig_idx = NO_INDEX;
                dbg_item->line = line;
                DEBUG_PRINT("\t[DBG_SPEC]: %d addr: %d line: %d\n",
                            dbg_opcode, address, line);
                break;
            }
        }
    }
}

static void parse_dex_code_item(jd_meta_dex *dex, encoded_method *em)
{
    mem_pool *pool = dex->pool;
    if (dex_invalid(dex))
        return;
    if (em->method_id >= dex->header->method_ids_size) {
        dex_mark_invalid(dex);
        return;
    }
    dex_method_id *method_id = &dex->method_ids[em->method_id];
    if (method_id->name_idx >= dex->header->string_ids_size) {
        dex_mark_invalid(dex);
        return;
    }
    string method_name = dex->strings[method_id->name_idx].data;
    if (!dex_range_ok(dex, em->code_off, 16)) {
        dex_mark_invalid_reason(dex, "code_item outside the file");
        em->code = NULL;
        return;
    }
    setup_current_offset(dex, em->code_off);
    em->code = make_obj_in(dex_code_item, pool);
    dex_code_item *code = em->code;
    jdex_read2(dex, &code->registers_size);
    jdex_read2(dex, &code->ins_size);
    jdex_read2(dex, &code->outs_size);
    jdex_read2(dex, &code->tries_size);
    jdex_read4(dex, &code->debug_info_off);
    jdex_read4(dex, &code->insns_size);

    if (code->debug_info_off != 0 && !dex_range_ok(dex, code->debug_info_off, 1)) {
        dex_mark_invalid_reason(dex, "debug_info outside the file");
        return;
    }
    if (!dex_range_ok(dex, dex->bin->cur_off, sizeof(u2) * (u8) code->insns_size)) {
        dex_mark_invalid_reason(dex, "insns outside the file");
        code->insns = NULL;
        return;
    }
    code->insns = (u2 *) (dex->bin->buffer + dex->bin->cur_off);
    setup_current_offset(dex, dex->bin->cur_off + sizeof(u2)*code->insns_size);

    parse_dex_code_try_item(dex, code);

    DEBUG_PRINT("[code_item]: %s registers_size: %d "
                "ins_size: %d outs_size: %d "
                "tries_size: %d insns_size: %d\n",
                method_name,
                code->registers_size,
                code->ins_size,
                code->outs_size,
                code->tries_size,
                code->insns_size);
    parse_dex_code_debug_item(dex, code);
}

static void parse_dex_class_data_items(jd_meta_dex *dex, dex_class_def *cdef)
{
    if (cdef->class_data_off == 0)
        return;

    setup_current_offset(dex, cdef->class_data_off);
    cdef->class_data = make_obj_in(dex_class_data_item, dex->pool);
    dex_class_data_item *cdata = cdef->class_data;

    cdata->static_fields_size      = read_unsigned_leb128(dex);
    cdata->instance_fields_size    = read_unsigned_leb128(dex);
    cdata->direct_methods_size     = read_unsigned_leb128(dex);
    cdata->virtual_methods_size    = read_unsigned_leb128(dex);
    /* 每个成员在流中至少占 2 字节，先确认计数与文件剩余字节相符。 */
    if (!dex_count_ok_at(dex, dex->bin->cur_off,
                         cdata->static_fields_size + cdata->instance_fields_size +
                         cdata->direct_methods_size + cdata->virtual_methods_size, 2)) {
        dex_mark_invalid_reason(dex, "class_data counts exceed the file");
        return;
    }

    u4 size = 0;
    mem_pool *pool = dex->pool;
    if (cdata->static_fields_size > 0) {
        size = cdata->static_fields_size;
        cdata->static_fields = make_obj_arr_in(encoded_field, size, pool);
        u4 start_idx = 0;
        for (int i = 0; i < cdata->static_fields_size; ++i) {
            encoded_field *field = &cdata->static_fields[i];
            parse_dex_encoded_field(dex, field);
            if (i == 0) {
                start_idx = field->field_idx_diff;
                field->field_id = start_idx;
            }
            else {
                field->field_id = start_idx + field->field_idx_diff;
                start_idx = field->field_id;
            }
            if (field->field_id >= dex->header->field_ids_size) {
                dex_mark_invalid_reason(dex, "class_data field index outside field_ids");
                return;
            }
        }
    }

    if (cdata->instance_fields_size > 0) {
        size = cdata->instance_fields_size;
        cdata->instance_fields = make_obj_arr_in(encoded_field, size, pool);
        u4 start_idx = 0;
        for (int i = 0; i < cdata->instance_fields_size; ++i) {
            encoded_field *field = &cdata->instance_fields[i];
            parse_dex_encoded_field(dex, field);
            if (i == 0) {
                start_idx = field->field_idx_diff;
                field->field_id = start_idx;
            }
            else {
                field->field_id = start_idx + field->field_idx_diff;
                start_idx = field->field_id;
            }
            if (field->field_id >= dex->header->field_ids_size) {
                dex_mark_invalid_reason(dex, "class_data field index outside field_ids");
                return;
            }
        }
    }

    if (cdata->direct_methods_size > 0) {
        size = cdata->direct_methods_size;
        cdata->direct_methods = make_obj_arr_in(encoded_method, size, pool);
        u4 start_idx = 0;
        for (int i = 0; i < cdata->direct_methods_size; ++i) {
            encoded_method *method = &cdata->direct_methods[i];
            parse_dex_encoded_method(dex, method);
            if (i == 0) {
                start_idx = method->method_idx_diff;
                method->method_id = start_idx;
            }
            else {
                method->method_id = start_idx + method->method_idx_diff;
                start_idx = method->method_id;
            }
            if (method->method_id >= dex->header->method_ids_size) {
                dex_mark_invalid_reason(dex, "class_data method index outside method_ids");
                return;
            }

            if (dex_encoded_method_is_lambda(dex, method)) {
                hset_u4obj(dex->lambda_method_map, method->method_id, method);
            }
        }
    }

    if (cdata->virtual_methods_size > 0) {
        size = cdata->virtual_methods_size;
        cdata->virtual_methods = make_obj_arr_in(encoded_method, size, pool);
        u4 start_idx = 0;
        for (int i = 0; i < cdata->virtual_methods_size; ++i) {
            encoded_method *method = &cdata->virtual_methods[i];
            parse_dex_encoded_method(dex, method);
            if (i == 0) {
                start_idx = method->method_idx_diff;
                method->method_id = start_idx;
            }
            else {
                method->method_id = start_idx + method->method_idx_diff;
                start_idx = method->method_id;
            }
            if (method->method_id >= dex->header->method_ids_size) {
                dex_mark_invalid_reason(dex, "class_data method index outside method_ids");
                return;
            }

            if (dex_encoded_method_is_lambda(dex, method)) {
                hset_u4obj(dex->lambda_method_map, method->method_id, method);
            }
        }
    }

    DEBUG_PRINT("[class_data_item]: static_fields_size: %d, "
           "instance_fields_size: %d, direct_methods_size: %d, "
           "virtual_methods_size: %d\n",
                cdata->static_fields_size,
                cdata->instance_fields_size,
                cdata->direct_methods_size,
                cdata->virtual_methods_size);

    for (int i = 0; i < cdata->direct_methods_size; ++i) {
        encoded_method *method = &cdata->direct_methods[i];
        if (method->code_off == 0)
            continue;
        parse_dex_code_item(dex, method);
    }

    for (int i = 0; i < cdata->virtual_methods_size; ++i) {
        encoded_method *method = &cdata->virtual_methods[i];
        if (method->code_off == 0)
            continue;
        parse_dex_code_item(dex, method);
    }
}

static void parse_dex_class_defs(jd_meta_dex *dex)
{
    dex_header *header = dex->header;
    mem_pool *pool = dex->pool;
    if (dex_invalid(dex))
        return;
    if (!dex_table_ok(dex, header->class_defs_off, header->class_defs_size, sizeof(dex_class_def))) {
        dex_mark_invalid_reason(dex, "class_defs outside the file");
        return;
    }
    setup_current_offset(dex, header->class_defs_off);

    u4 size = header->class_defs_size;
    dex->class_defs = make_obj_arr_in(dex_class_def, size, pool);
    for (int i = 0; i < header->class_defs_size; ++i) {
        dex_class_def *class_def = &dex->class_defs[i];
        jdex_read4(dex, &class_def->class_idx);
        jdex_read4(dex, &class_def->access_flags);
        jdex_read4(dex, &class_def->superclass_idx);
        jdex_read4(dex, &class_def->interfaces_off);
        jdex_read4(dex, &class_def->source_file_idx);
        jdex_read4(dex, &class_def->annotations_off);
        jdex_read4(dex, &class_def->class_data_off);
        jdex_read4(dex, &class_def->static_values_off);

        class_def->is_inner = false;
        class_def->is_anonymous = false;
        if ((class_def->access_flags & ACC_DEX_SYNTHETIC) != 0 &&
                (class_def->access_flags & ACC_DEX_FINAL) != 0) {
            hset_u4obj(dex->synthetic_classes_map, class_def->class_idx,
                       class_def);
        }
        hset_u4obj(dex->class_type_id_map, class_def->class_idx,
                   class_def);

        string cname = dex_str_of_type_id(dex, class_def->class_idx);
        hset_s2o(dex->class_name_map, cname, class_def);

        class_def->anonymous_classes = linit_object_with_pool(dex->pool);
        class_def->inner_classes = linit_object_with_pool(dex->pool);
//        printf("[class_def]: %d %s %p\n", class_def->class_idx, cname, class_def);
    }

    for (int i = 0; i < header->class_defs_size; ++i) {
        if (dex_invalid(dex))
            return;
        dex_class_def *class_def = &dex->class_defs[i];
        parse_dex_class_interfaces(dex, class_def);
        parse_dex_class_defs_anos(dex, class_def);
        parse_dex_class_data_items(dex, class_def);
        if (class_def->static_values_off != 0) {
            setup_current_offset(dex, class_def->static_values_off);
            class_def->static_values = parse_dex_encoded_array(dex);
        }

        if (dex_class_is_anonymous_class(dex, class_def))
            class_def->is_anonymous = true;
        else if (dex_class_is_inner_class(dex, class_def))
            class_def->is_inner = true;
    }

    DEBUG_PRINT("[class_defs_size]: %d\n", header->class_defs_size);
}

static jd_meta_dex* init_dex_content(mem_pool *pool, string path)
{
    FILE *file = fopen(path, "rb");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    jd_meta_dex *dex = make_obj_in(jd_meta_dex, pool);
    dex->pool = pool;
    dex->bin = make_obj_in(jd_bin, pool);
    dex->bin->buffer_size = file_size;
    dex->bin->buffer = x_alloc_in(pool, file_size);
    dex->bin->cur_off = 0;
    fread(dex->bin->buffer, 1, file_size, file);
//    dalvik->buffer_size = file_size;
//    dalvik->buffer = x_alloc_in(pool, file_size);
//    fread(dalvik->buffer, 1, file_size, file);
//    dalvik->cur_off = 0;
    fclose(file);
    return dex;
}

static void init_dex_extract_data(jd_meta_dex *dex)
{
    dex->synthetic_classes_map = hashmap_init_in(dex->pool, (hcmp_fn) u4obj_cmp, 0);
    dex->lambda_method_map = hashmap_init_in(dex->pool, (hcmp_fn) u4obj_cmp, 0);
    dex->rebuilt_lambda_bodies = hashmap_init_in(dex->pool, (hcmp_fn) u4obj_cmp, 0);
    dex->rebuilt_lambda_classes = hashmap_init_in(dex->pool, (hcmp_fn) u4obj_cmp, 0);
    dex->lambda_in_progress = hashmap_init((hcmp_fn) i2i_cmp, 0);
    pthread_mutex_init(&dex->lambda_lock, NULL);
    dex->lambda_facts = hashmap_init_in(dex->pool, (hcmp_fn) u4obj_cmp, 0);
    dex->class_type_id_map = hashmap_init_in(dex->pool, (hcmp_fn) u4obj_cmp, 0);
    dex->class_name_map = hashmap_init_in(dex->pool, (hcmp_fn) s2o_cmp, 0);
}

jd_meta_dex* parse_dex_file(string path)
{
//    init_dex_opcode_hashmap();

    mem_pool *pool = mem_create_pool();

    jd_meta_dex *dex = init_dex_content(pool, path);

    init_dex_extract_data(dex);

    /* 任一步骤发现结构非法就立即停止：后续阶段假定前面的表已经建好。 */
    parse_dex_header(dex);

    if (!dex_invalid(dex))
        parse_dex_links(dex);

    if (!dex_invalid(dex))
        parse_dex_map_list(dex);

    if (!dex_invalid(dex))
        parse_dex_string_ids(dex);

    if (!dex_invalid(dex))
        parse_dex_type_ids(dex);

    if (!dex_invalid(dex))
        parse_dex_proto_ids(dex);

    if (!dex_invalid(dex))
        parse_dex_field_ids(dex);

    if (!dex_invalid(dex))
        parse_dex_method_ids(dex);

    if (!dex_invalid(dex))
        parse_dex_class_defs(dex);

    if (!dex_invalid(dex))
        parse_dex_method_handles(dex);

    if (!dex_invalid(dex))
        parse_dex_call_sites(dex);

    if (dex->bin->overrun) {
        output_input_rejected(path, dex->bin->error);
        return NULL;
    }
    return dex;
}


jd_meta_dex* parse_dex_from_buffer(char *buffer, size_t size)
{
    mem_pool *pool = mem_create_pool();
    jd_meta_dex *meta = make_obj_in(jd_meta_dex, pool);
    meta->pool = pool;
    meta->bin = make_obj_in(jd_bin, pool);
    meta->bin->buffer_size = size;
    meta->bin->buffer = buffer;
    meta->bin->cur_off = 0;

    init_dex_extract_data(meta);

    /* 同 parse_dex_file：任一阶段发现非法即停止。 */
    parse_dex_header(meta);

    if (!dex_invalid(meta))
        parse_dex_links(meta);

    if (!dex_invalid(meta))
        parse_dex_map_list(meta);

    if (!dex_invalid(meta))
        parse_dex_string_ids(meta);

    if (!dex_invalid(meta))
        parse_dex_type_ids(meta);

    if (!dex_invalid(meta))
        parse_dex_proto_ids(meta);

    if (!dex_invalid(meta))
        parse_dex_field_ids(meta);

    if (!dex_invalid(meta))
        parse_dex_method_ids(meta);

    if (!dex_invalid(meta))
        parse_dex_class_defs(meta);

    if (!dex_invalid(meta))
        parse_dex_method_handles(meta);

    if (!dex_invalid(meta))
        parse_dex_call_sites(meta);

    if (meta->bin->overrun) {
        output_input_rejected(NULL, meta->bin->error);
        return NULL;
    }
    return meta;
}