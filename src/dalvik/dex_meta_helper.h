#ifndef GARLIC_DEX_META_HELPER_H
#define GARLIC_DEX_META_HELPER_H

#include "dalvik/dex_structure.h"
#include "dalvik/dex_ins.h"

/*
 * 表索引来自文件内容。越界时置位解析错误并返回空串：解析方据此拒绝该文件，避免用越界
 * 索引读写内存。全部按索引取值的入口都在本文件，因此边界判断只需要写在这里。
 */
static inline bool dex_meta_index_ok(jd_meta_dex *meta, u4 idx, u4 size)
{
    if (meta->header == NULL || idx >= size) {
        if (meta->bin != NULL) {
            if (meta->bin->error == NULL)
                meta->bin->error = "table index outside its range";
            meta->bin->overrun = true;
        }
        return false;
    }
    return true;
}

static inline string dex_str_of_idx(jd_meta_dex *meta, u4 idx)
{
    if (!dex_meta_index_ok(meta, idx, meta->header == NULL ? 0 : meta->header->string_ids_size))
        return "";
    return meta->strings[idx].data;
}

static inline string dex_str_of_type_id(jd_meta_dex *meta, u2 idx)
{
    if (!dex_meta_index_ok(meta, idx, meta->header == NULL ? 0 : meta->header->type_ids_size))
        return "";
    return dex_str_of_idx(meta, meta->type_ids[idx].descriptor_idx);
}

static inline string dex_str_of_superclass(jd_meta_dex *meta, dex_class_def *cf)
{
    /* NO_INDEX 是根类的合法值，不能当成类型表索引。其余越界仍拒绝该文件。 */
    if (cf->superclass_idx == NO_INDEX)
        return NULL;
    if (!dex_meta_index_ok(meta, cf->superclass_idx,
                           meta->header == NULL ? 0 : meta->header->type_ids_size))
        return "";
    return dex_str_of_type_id(meta, cf->superclass_idx);
}

static inline string dex_str_of_field_type(jd_meta_dex *meta, u2 idx)
{
    if (!dex_meta_index_ok(meta, idx, meta->header == NULL ? 0 : meta->header->field_ids_size))
        return "";
    return dex_str_of_type_id(meta, meta->field_ids[idx].type_idx);
}

static inline string dex_str_of_field_name(jd_meta_dex *meta, u2 field_idx)
{
    if (!dex_meta_index_ok(meta, field_idx, meta->header == NULL ? 0 : meta->header->field_ids_size))
        return "";
    dex_field_id field_id = meta->field_ids[field_idx];
    return dex_str_of_idx(meta, field_id.name_idx);
}

static inline string dex_str_of_field_class(jd_meta_dex *meta, u2 field_idx)
{
    if (!dex_meta_index_ok(meta, field_idx, meta->header == NULL ? 0 : meta->header->field_ids_size))
        return "";
    dex_field_id field_id = meta->field_ids[field_idx];
    return dex_str_of_type_id(meta, field_id.class_idx);
}

static inline string dex_str_of_method_id(jd_meta_dex *meta, u2 idx)
{
    if (!dex_meta_index_ok(meta, idx, meta->header == NULL ? 0 : meta->header->method_ids_size))
        return "";
    return dex_str_of_idx(meta, meta->method_ids[idx].name_idx);
}

static inline string dex_method_class_descriptor(jd_meta_dex *meta,
                                           encoded_method *em)
{
    // m's class desc
    if (!dex_meta_index_ok(meta, em->method_id,
                           meta->header == NULL ? 0 : meta->header->method_ids_size))
        return "";
    dex_method_id *method_id = &meta->method_ids[em->method_id];
    if (!dex_meta_index_ok(meta, method_id->class_idx,
                           meta->header == NULL ? 0 : meta->header->type_ids_size))
        return "";
    dex_type_id *type_id = &meta->type_ids[method_id->class_idx];
    return dex_str_of_idx(meta, type_id->descriptor_idx);
}

static inline string dex_field_desc(jd_meta_dex *meta, encoded_field *efield)
{
    // field's type descriptor
    if (!dex_meta_index_ok(meta, efield->field_id,
                           meta->header == NULL ? 0 : meta->header->field_ids_size))
        return "";
    dex_field_id *field_id = &meta->field_ids[efield->field_id];
    if (!dex_meta_index_ok(meta, field_id->type_idx,
                           meta->header == NULL ? 0 : meta->header->type_ids_size))
        return "";
    dex_type_id *type_id = &meta->type_ids[field_id->type_idx];
    return dex_str_of_idx(meta, type_id->descriptor_idx);
}

static inline string dex_field_name(jd_meta_dex *meta, encoded_field *efield)
{
    // field's name
    if (!dex_meta_index_ok(meta, efield->field_id,
                           meta->header == NULL ? 0 : meta->header->field_ids_size))
        return "";
    dex_field_id *field_id = &meta->field_ids[efield->field_id];
    return dex_str_of_idx(meta, field_id->name_idx);
}
#endif //GARLIC_DEX_META_HELPER_H
