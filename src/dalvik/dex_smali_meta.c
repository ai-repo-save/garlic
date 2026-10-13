#include "dex_smali_write.h"

#include "dex_meta_helper.h"

#include <ctype.h>
#include <string.h>

static const char *smali_visibility(u1 visibility)
{
    switch (visibility) {
        case 0: return "build";
        case 1: return "runtime";
        case 2: return "system";
        default: return NULL;
    }
}

static void smali_simple_name(FILE *stream, string name)
{
    int quote = name == NULL || name[0] == '\0';
    for (const unsigned char *p = (const unsigned char *) name;
         !quote && p != NULL && *p != '\0'; ++p) {
        if (!(isalnum(*p) || *p == '_' || *p == '$' || *p == '-'))
            quote = 1;
    }
    if (!quote) {
        fputs(name, stream);
        return;
    }
    fputc('`', stream);
    if (name != NULL)
        fputs(name, stream);
    fputc('`', stream);
}

void smali_write_subannotation(FILE *stream, jd_meta_dex *dex,
                               encoded_annotation *annotation)
{
    fprintf(stream, ".subannotation %s\n", dex_str_of_type_id(dex, (u2) annotation->type_idx));
    for (u4 i = 0; annotation->elements != NULL && i < annotation->size; ++i) {
        fputs("    ", stream);
        smali_simple_name(stream, dex_str_of_idx(dex, annotation->elements[i].name_idx));
        fputs(" = ", stream);
        smali_write_encoded_value(stream, dex, annotation->elements[i].value);
        fputc('\n', stream);
    }
    fputs(".end subannotation", stream);
}

static void smali_write_annotation_set(FILE *stream, jd_meta_dex *dex,
                                       annotation_set_item *set,
                                       const char *indent)
{
    if (set == NULL || set->entries == NULL)
        return;

    for (u4 i = 0; i < set->size; ++i) {
        annotation_item *item = set->entries[i].annotation_item;
        encoded_annotation *annotation;
        const char *visibility;
        if (item == NULL || item->encoded_annotation == NULL)
            continue;
        annotation = item->encoded_annotation;
        visibility = smali_visibility(item->visibility);
        if (visibility == NULL) {
            fprintf(stderr, "smali_annotation_visibility_unknown value=%u\n",
                    item->visibility);
            continue;
        }

        fprintf(stream, "%s.annotation %s %s\n", indent, visibility,
                dex_str_of_type_id(dex, (u2) annotation->type_idx));
        for (u4 j = 0; annotation->elements != NULL && j < annotation->size; ++j) {
            annotation_element *element = &annotation->elements[j];
            fprintf(stream, "%s    ", indent);
            smali_simple_name(stream, dex_str_of_idx(dex, element->name_idx));
            fputs(" = ", stream);
            smali_write_encoded_value(stream, dex, element->value);
            fputc('\n', stream);
        }
        fprintf(stream, "%s.end annotation\n", indent);
    }
}

void smali_write_class_annotations(FILE *stream, jd_meta_dex *dex,
                                   dex_class_def *cf)
{
    dex_annotations_directory_item *annotations;
    if (cf == NULL || cf->annotations == NULL)
        return;
    annotations = cf->annotations;
    if (annotations->class_annotations_off == 0)
        return;
    smali_write_annotation_set(stream, dex, annotations->class_annotation, "");
}

void smali_write_field_annotations(FILE *stream, jd_meta_dex *dex,
                                   dex_class_def *cf, u4 field_id)
{
    dex_annotations_directory_item *annotations;
    int wrote = 0;
    if (cf == NULL || cf->annotations == NULL)
        return;
    annotations = cf->annotations;
    for (u4 i = 0; i < annotations->fields_size; ++i) {
        field_annotation *field = &annotations->field_annotations[i];
        if (field->field_idx != field_id || field->annotations_off == 0)
            continue;
        smali_write_annotation_set(stream, dex, field->annotation, "    ");
        wrote = 1;
    }
    /* Without .end field, the assembler treats these as class annotations. */
    if (wrote)
        fputs(".end field\n", stream);
}

static int smali_wide_type(string descriptor)
{
    return descriptor != NULL && (descriptor[0] == 'J' || descriptor[0] == 'D');
}

static annotation_set_item *smali_parameter_annotation(dex_class_def *cf,
                                                      u4 method_id, u4 index)
{
    dex_annotations_directory_item *annotations;
    if (cf == NULL || cf->annotations == NULL)
        return NULL;
    annotations = cf->annotations;
    for (u4 i = 0; i < annotations->parameters_size; ++i) {
        parameter_annotation *parameter = &annotations->parameter_annotations[i];
        annotation_set_ref_item *item;
        if (parameter->method_idx != method_id || parameter->annotations_off == 0 ||
            parameter->annotation == NULL || index >= parameter->annotation->size)
            continue;
        item = &parameter->annotation->list[index];
        if (item->annotations_off == 0)
            return NULL;
        return item->annotation;
    }
    return NULL;
}

static void smali_write_parameters(FILE *stream, jd_meta_dex *dex,
                                   dex_class_def *cf, encoded_method *method)
{
    dex_method_id *method_id = &dex->method_ids[method->method_id];
    dex_proto_id *proto = &dex->proto_ids[method_id->proto_idx];
    dex_debug_info_item *debug = method->code == NULL ? NULL : method->code->debug_info;
    int reg = (method->access_flags & ACC_DEX_STATIC) ? 0 : 1;
    u4 count = 0;

    if (proto->parameters_off != 0 && proto->type_list != NULL)
        count = proto->type_list->size;

    for (u4 i = 0; i < count; ++i) {
        string descriptor = dex_str_of_type_id(dex, proto->type_list->list[i].type_idx);
        annotation_set_item *annotations = smali_parameter_annotation(cf, method->method_id, i);
        int named = debug != NULL && i < debug->parameters_size &&
                    debug->parameter_name[i] != NO_INDEX;
        if (named || annotations != NULL) {
            fprintf(stream, "    .param p%d", reg);
            if (named) {
                fputs(", ", stream);
                smali_string(stream, dex_str_of_idx(dex, debug->parameter_name[i]));
            }
            fputc('\n', stream);
            if (annotations != NULL) {
                smali_write_annotation_set(stream, dex, annotations, "        ");
                fputs("    .end param\n", stream);
            }
        }
        reg += smali_wide_type(descriptor) ? 2 : 1;
    }
}

void smali_write_method_meta(FILE *stream, jd_meta_dex *dex,
                             dex_class_def *cf, encoded_method *method)
{
    dex_annotations_directory_item *annotations;
    smali_write_parameters(stream, dex, cf, method);
    if (cf == NULL || cf->annotations == NULL)
        return;
    annotations = cf->annotations;
    for (u4 i = 0; i < annotations->methods_size; ++i) {
        method_annotation *item = &annotations->method_annotations[i];
        if (item->method_idx != method->method_id || item->annotations_off == 0)
            continue;
        smali_write_annotation_set(stream, dex, item->annotation, "    ");
    }
}

static void smali_write_debug_item(FILE *stream, jd_meta_dex *dex,
                                   const dex_dbg_item *item)
{
    int has_name;
    int has_type;
    int has_sig;

    switch (item->code) {
        case DBG_START_LOCAL:
        case DBG_START_LOCAL_EXTENDED:
            has_name = item->name_idx != NO_INDEX;
            has_type = item->type_idx != NO_INDEX;
            has_sig = item->sig_idx != NO_INDEX;
            fprintf(stream, "    .local v%u", item->reg_num);
            if (has_name || has_type || has_sig) {
                fputs(", ", stream);
                if (has_name)
                    smali_string(stream, dex_str_of_idx(dex, item->name_idx));
                else
                    fputs("null", stream);
                fputc(':', stream);
                if (has_type)
                    fputs(dex_str_of_type_id(dex, (u2) item->type_idx), stream);
                else
                    fputc('V', stream);
                if (has_sig) {
                    fputs(", ", stream);
                    smali_string(stream, dex_str_of_idx(dex, item->sig_idx));
                }
            }
            fputc('\n', stream);
            break;
        case DBG_END_LOCAL:
            fprintf(stream, "    .end local v%u\n", item->reg_num);
            break;
        case DBG_RESTART_LOCAL:
            fprintf(stream, "    .restart local v%u\n", item->reg_num);
            break;
        case DBG_SET_PROLOGUE_END:
            fputs("    .prologue\n", stream);
            break;
        case DBG_SET_EPILOGUE_BEGIN:
            fputs("    .epilogue\n", stream);
            break;
        case DBG_SET_FILE:
            fputs("    .source", stream);
            if (item->name_idx != NO_INDEX) {
                fputc(' ', stream);
                smali_string(stream, dex_str_of_idx(dex, item->name_idx));
            }
            fputc('\n', stream);
            break;
        case DBG_FIRST_SPECIAL:
            fprintf(stream, "    .line %d\n", item->line);
            break;
        default:
            break;
    }
}

void smali_write_debug_at(FILE *stream, jd_meta_dex *dex,
                          const dex_code_item *code, u4 offset, u4 *cursor)
{
    dex_debug_info_item *debug;
    if (code == NULL || code->debug_info == NULL || cursor == NULL)
        return;
    debug = code->debug_info;
    while (*cursor < debug->dbg_size) {
        dex_dbg_item *item = &debug->items[*cursor];
        /* A debug address may fall between instructions. Attach it to the
         * next instruction; baksmali prints it immediately before that
         * instruction either way. */
        if (item->offset > offset)
            return;
        smali_write_debug_item(stream, dex, item);
        ++*cursor;
    }
}
