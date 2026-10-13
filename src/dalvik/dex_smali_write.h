#ifndef GARLIC_DEX_SMALI_WRITE_H
#define GARLIC_DEX_SMALI_WRITE_H

#include "dex_structure.h"

#include <stdio.h>

void smali_string(FILE *stream, string str);

void smali_write_encoded_value(FILE *stream, jd_meta_dex *dex,
                               encoded_value *value);

void smali_write_subannotation(FILE *stream, jd_meta_dex *dex,
                               encoded_annotation *annotation);

void smali_write_class_annotations(FILE *stream, jd_meta_dex *dex,
                                   dex_class_def *cf);

void smali_write_field_annotations(FILE *stream, jd_meta_dex *dex,
                                   dex_class_def *cf, u4 field_id);

void smali_write_method_meta(FILE *stream, jd_meta_dex *dex,
                             dex_class_def *cf, encoded_method *method);

void smali_write_debug_at(FILE *stream, jd_meta_dex *dex,
                          const dex_code_item *code, u4 offset, u4 *cursor);

#endif
