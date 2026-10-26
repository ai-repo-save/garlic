#include "dalvik/dex_analysis.h"

#include "dalvik/dex_ins.h"
#include "dalvik/dex_meta_helper.h"
#include <time.h>

unsigned dex_analysis_kind(const char *desc)
{
    switch (desc[0]) {
        case 'F': return DEX_VALUE_FLOAT;
        case 'J': return DEX_VALUE_LONG;
        case 'D': return DEX_VALUE_DOUBLE;
        case 'L': case '[': return DEX_VALUE_REFERENCE;
        case 'V': return 0;
        default: return DEX_VALUE_INT;
    }
}

static bool constrain(dex_analysis *a, int value, const char *desc)
{
    if (value < 0) {
        a->failed = 1;
        return false;
    }
    dex_value_type *type = &a->types[value];
    unsigned previous = type->kinds;
    type->kinds |= dex_analysis_kind(desc);
    bool changed = previous != type->kinds;
    if (desc[0] == '[' && type->array == NULL) {
        type->array = desc;
        changed = true;
    }
    if (dex_analysis_kind(desc) == DEX_VALUE_REFERENCE && type->reference == NULL)
        type->reference = desc;
    return changed;
}

static bool input(dex_analysis *a, jd_dex_ins *ins, int reg, const char *desc)
{
    a->uses[ins->idx][reg] |= dex_analysis_kind(desc);
    return constrain(a, dex_analysis_input(a, ins->offset, reg), desc);
}

static bool output(dex_analysis *a, jd_dex_ins *ins, int reg, const char *desc)
{
    return constrain(a, dex_analysis_output(a, ins->offset, reg), desc);
}

static const char *binary_type(u1 op)
{
    if ((op >= DEX_INS_ADD_LONG && op <= DEX_INS_USHR_LONG) ||
        (op >= DEX_INS_ADD_LONG_2ADDR && op <= DEX_INS_USHR_LONG_2ADDR))
        return "J";
    if ((op >= DEX_INS_ADD_FLOAT && op <= DEX_INS_REM_FLOAT) ||
        (op >= DEX_INS_ADD_FLOAT_2ADDR && op <= DEX_INS_REM_FLOAT_2ADDR))
        return "F";
    if ((op >= DEX_INS_ADD_DOUBLE && op <= DEX_INS_REM_DOUBLE) ||
        (op >= DEX_INS_ADD_DOUBLE_2ADDR && op <= DEX_INS_REM_DOUBLE_2ADDR))
        return "D";
    return "I";
}

static int invoke_register(jd_dex_ins *ins, int word)
{
    if (ins->format == kFmt3rc || ins->format == kFmt4rcc)
        return ins->param[2] + word;
    if (word == 4)
        return (ins->param[0] >> 8) & 15;
    return (ins->param[2] >> (word * 4)) & 15;
}

static bool invoke_types(dex_analysis *a, jd_dex_ins *ins)
{
    jd_meta_dex *dex = a->dex;
    dex_method_id *method = &dex->method_ids[ins->param[1]];
    dex_proto_id *proto = &dex->proto_ids[method->proto_idx];
    int word = 0;
    bool changed = false;
    if (ins->code != DEX_INS_INVOKE_STATIC && ins->code != DEX_INS_INVOKE_STATIC_RANGE) {
        changed |= input(a, ins, invoke_register(ins, word++), dex_str_of_type_id(dex, method->class_idx));
    }
    if (proto->type_list != NULL) {
        for (u4 p = 0; p < proto->type_list->size; p++) {
            const char *desc = dex_str_of_type_id(dex, proto->type_list->list[p].type_idx);
            changed |= input(a, ins, invoke_register(ins, word), desc);
            word += desc[0] == 'J' || desc[0] == 'D' ? 2 : 1;
        }
    }
    return changed;
}

static const char *result_descriptor(dex_analysis *a, jd_dex_ins *ins)
{
    jd_dex_ins *previous = ins->prev;
    if (previous->code == DEX_INS_FILLED_NEW_ARRAY || previous->code == DEX_INS_FILLED_NEW_ARRAY_RANGE)
        return dex_str_of_type_id(a->dex, previous->param[1]);
    dex_method_id *method = &a->dex->method_ids[previous->param[1]];
    return dex_str_of_type_id(a->dex, a->dex->proto_ids[method->proto_idx].return_type_idx);
}

static bool instruction_types(dex_analysis *a, jd_dex_ins *ins, const char *ret)
{
    int op = ins->code;
    int x = ins->param[0] >> 8;
    if (ins->format == kFmt12x || ins->format == kFmt11n ||
        ins->format == kFmt22c || ins->format == kFmt22s || ins->format == kFmt22t)
        x &= 15;
    if (ins->format == kFmt32x)
        x = ins->param[1];
    bool changed = false;
    if (op >= DEX_INS_MOVE && op <= DEX_INS_MOVE_OBJECT_16) {
        if (op >= DEX_INS_MOVE_OBJECT) {
            changed |= input(a, ins, (int)dex_ins_parameter(ins, 1), "Ljava/lang/Object;");
            changed |= output(a, ins, x, "Ljava/lang/Object;");
        }
        return changed;
    }
    if (op >= DEX_INS_MOVE_RESULT && op <= DEX_INS_MOVE_RESULT_OBJECT)
        return output(a, ins, x, result_descriptor(a, ins));
    if (op == DEX_INS_MOVE_EXCEPTION)
        return output(a, ins, x, "Ljava/lang/Throwable;");
    if (op >= DEX_INS_RETURN && op <= DEX_INS_RETURN_OBJECT)
        return input(a, ins, x, ret);
    if (op >= DEX_INS_CONST_4 && op <= DEX_INS_CONST_WIDE_HIGH16)
        return false;
    if (op == DEX_INS_CONST_STRING || op == DEX_INS_CONST_STRING_JUMBO)
        return output(a, ins, x, "Ljava/lang/String;");
    if (op == DEX_INS_CONST_CLASS)
        return output(a, ins, x, "Ljava/lang/Class;");
    if (op == DEX_INS_MONITOR_ENTER || op == DEX_INS_MONITOR_EXIT)
        return input(a, ins, x, "Ljava/lang/Object;");
    if (op == DEX_INS_THROW)
        return input(a, ins, x, "Ljava/lang/Throwable;");
    if (op == DEX_INS_FILL_ARRAY_DATA)
        return input(a, ins, x, "Ljava/lang/Object;");
    if (op == DEX_INS_CHECK_CAST) {
        changed |= input(a, ins, x, "Ljava/lang/Object;");
        changed |= output(a, ins, x, dex_str_of_type_id(a->dex, ins->param[1]));
        return changed;
    }
    if (op == DEX_INS_NEW_INSTANCE)
        return output(a, ins, x, dex_str_of_type_id(a->dex, ins->param[1]));
    if (op == DEX_INS_NEW_ARRAY) {
        changed |= input(a, ins, (int)dex_ins_parameter(ins, 1), "I");
        changed |= output(a, ins, x, dex_str_of_type_id(a->dex, ins->param[1]));
        return changed;
    }
    if (op == DEX_INS_INSTANCE_OF || op == DEX_INS_ARRAY_LENGTH) {
        changed |= input(a, ins, (int)dex_ins_parameter(ins, 1), "Ljava/lang/Object;");
        changed |= output(a, ins, x, "I");
        return changed;
    }
    if (op >= DEX_INS_IGET && op <= DEX_INS_SPUT_SHORT) {
        const char *desc = dex_str_of_field_type(a->dex, ins->param[1]);
        if (op < DEX_INS_SGET)
            changed |= input(a, ins, (int)dex_ins_parameter(ins, 1), dex_str_of_field_class(a->dex, ins->param[1]));
        if ((op >= DEX_INS_IPUT && op <= DEX_INS_IPUT_SHORT) || op >= DEX_INS_SPUT)
            changed |= input(a, ins, x, desc);
        else
            changed |= output(a, ins, x, desc);
        return changed;
    }
    if ((op >= DEX_INS_INVOKE_VIRTUAL && op <= DEX_INS_INVOKE_INTERFACE) ||
        (op >= DEX_INS_INVOKE_VIRTUAL_RANGE && op <= DEX_INS_INVOKE_INTERFACE_RANGE))
        return invoke_types(a, ins);
    if (op >= DEX_INS_NEG_INT && op <= DEX_INS_INT_TO_SHORT) {
        static const char *sources[] = {
            "I", "I", "J", "J", "F", "D", "I", "I", "I", "J", "J", "J",
            "F", "F", "F", "D", "D", "D", "I", "I", "I"
        };
        static const char *destinations[] = {
            "I", "I", "J", "J", "F", "D", "J", "F", "D", "I", "F", "D",
            "I", "J", "D", "I", "J", "F", "I", "I", "I"
        };
        changed |= input(a, ins, (int)dex_ins_parameter(ins, 1), sources[op - DEX_INS_NEG_INT]);
        changed |= output(a, ins, x, destinations[op - DEX_INS_NEG_INT]);
        return changed;
    }
    if (op >= DEX_INS_ADD_INT && op <= DEX_INS_REM_DOUBLE_2ADDR) {
        const char *desc = binary_type(op);
        bool two = op >= DEX_INS_ADD_INT_2ADDR;
        bool shift = (op >= DEX_INS_SHL_LONG && op <= DEX_INS_USHR_LONG) ||
                     (op >= DEX_INS_SHL_LONG_2ADDR && op <= DEX_INS_USHR_LONG_2ADDR);
        changed |= input(a, ins, two ? x : (int)dex_ins_parameter(ins, 1), desc);
        changed |= input(a, ins, (int)dex_ins_parameter(ins, two ? 1 : 2), shift ? "I" : desc);
        changed |= output(a, ins, x, desc);
        return changed;
    }
    if (op >= DEX_INS_ADD_INT_LIT16 && op <= DEX_INS_USHR_INT_LIT8) {
        changed |= input(a, ins, (int)dex_ins_parameter(ins, 1), "I");
        changed |= output(a, ins, x, "I");
        return changed;
    }
    if (op >= DEX_INS_CMPL_FLOAT && op <= DEX_INS_CMP_LONG) {
        const char *desc = op == DEX_INS_CMP_LONG ? "J" : op <= DEX_INS_CMPG_FLOAT ? "F" : "D";
        changed |= input(a, ins, (int)dex_ins_parameter(ins, 1), desc);
        changed |= input(a, ins, (int)dex_ins_parameter(ins, 2), desc);
        changed |= output(a, ins, x, "I");
        return changed;
    }
    if (op == DEX_INS_PACKED_SWITCH || op == DEX_INS_SPARSE_SWITCH)
        return input(a, ins, x, "I");
    if (op >= DEX_INS_IF_LT && op <= DEX_INS_IF_LE) {
        changed |= input(a, ins, x, "I");
        changed |= input(a, ins, (int)dex_ins_parameter(ins, 1), "I");
        return changed;
    }
    if (op >= DEX_INS_IF_LTZ && op <= DEX_INS_IF_LEZ)
        return input(a, ins, x, "I");
    if (op >= DEX_INS_AGET && op <= DEX_INS_APUT_SHORT) {
        int arr = (int)dex_ins_parameter(ins, 1);
        changed |= input(a, ins, arr, "Ljava/lang/Object;");
        changed |= input(a, ins, (int)dex_ins_parameter(ins, 2), "I");
        int value = dex_analysis_input(a, ins->offset, arr);
        const char *array = value >= 0 ? a->types[value].array : NULL;
        if (array != NULL) {
            if (op >= DEX_INS_APUT)
                changed |= input(a, ins, x, array + 1);
            else
                changed |= output(a, ins, x, array + 1);
        }
        return changed;
    }
    if (op == DEX_INS_FILLED_NEW_ARRAY || op == DEX_INS_FILLED_NEW_ARRAY_RANGE) {
        const char *desc = dex_str_of_type_id(a->dex, ins->param[1]);
        int count = ins->format == kFmt3rc ? ins->param[0] >> 8 : ins->param[0] >> 12;
        for (int p = 0; p < count; p++)
            changed |= input(a, ins, invoke_register(ins, p), desc + 1);
        return changed;
    }
    return false;
}

static bool null_web(dex_analysis *a, int value)
{
    bool constant = false;
    for (int d = 0; d < a->ssa->definition_count; d++) {
        if (sform_register_root(a->ssa, d) != value)
            continue;
        int index = a->ssa->definitions[d].instruction;
        if (index < 0)
            return false;
        jd_dex_ins *ins = lget_obj(a->method->instructions, index);
        int op = ins->code;
        if ((op >= DEX_INS_MOVE && op <= DEX_INS_MOVE_16) ||
            (op >= DEX_INS_MOVE_OBJECT && op <= DEX_INS_MOVE_OBJECT_16))
            continue;
        if (op < DEX_INS_CONST_4 || op > DEX_INS_CONST_HIGH16)
            return false;
        u2 *words = &a->encoded->code->insns[ins->offset];
        bool zero = op == DEX_INS_CONST_4 ? (words[0] >> 12) == 0 : words[1] == 0;
        if (op == DEX_INS_CONST)
            zero &= words[2] == 0;
        if (!zero)
            return false;
        constant = true;
    }
    return constant;
}

void dex_analysis_types(dex_analysis *a)
{
    jd_register_ssa *ssa = a->ssa;
    jd_meta_dex *dex = a->dex;
    dex_method_id *method = &dex->method_ids[a->encoded->method_id];
    dex_proto_id *proto = &dex->proto_ids[method->proto_idx];
    const char *ret = dex_str_of_type_id(dex, proto->return_type_idx);
    for (int i = 0; i < ssa->instruction_count; i++) {
        jd_dex_ins *ins = lget_obj(a->method->instructions, i);
        if (!ssa->reachable[i] || ins->code < DEX_INS_MOVE || ins->code > DEX_INS_MOVE_OBJECT_16)
            continue;
        int dst = (int)dex_ins_parameter(ins, 0);
        int src = (int)dex_ins_parameter(ins, 1);
        sform_register_join(ssa, dex_analysis_input(a, ins->offset, src),
                            dex_analysis_output(a, ins->offset, dst));
    }
    int reg = a->method->max_locals - a->encoded->code->ins_size;
    if (!(a->encoded->access_flags & ACC_DEX_STATIC))
        constrain(a, sform_register_root(ssa, ssa->parameters[reg++]), dex_str_of_type_id(dex, method->class_idx));
    if (proto->type_list != NULL) {
        for (u4 p = 0; p < proto->type_list->size; p++) {
            const char *desc = dex_str_of_type_id(dex, proto->type_list->list[p].type_idx);
            constrain(a, sform_register_root(ssa, ssa->parameters[reg]), desc);
            reg += desc[0] == 'J' || desc[0] == 'D' ? 2 : 1;
        }
    }
    bool changed;
    do {
        changed = false;
        for (int i = 0; i < ssa->instruction_count; i++) {
            jd_dex_ins *ins = lget_obj(a->method->instructions, i);
            if (!ssa->reachable[i] || ins->code == DEX_INS_NOP ||
                (ins->code >= DEX_INS_GOTO && ins->code <= DEX_INS_GOTO_32) || ins->code == DEX_INS_RETURN_VOID)
                continue;
            changed |= instruction_types(a, ins, ret);
        }
    } while (changed);
    for (int i = 0; i < ssa->instruction_count; i++) {
        jd_dex_ins *ins = lget_obj(a->method->instructions, i);
        if (!ssa->reachable[i])
            continue;
        if (ins->code == DEX_INS_FILL_ARRAY_DATA) {
            int reg = (int)dex_ins_parameter(ins, 0);
            int value = dex_analysis_input(a, ins->offset, reg);
            s8 target = (s8)ins->offset + (s4)((u4)ins->param[1] | ((u4)ins->param[2] << 16));
            if (value >= 0 && a->types[value].array == NULL && null_web(a, value) &&
                target >= 0 && target + 1 < a->encoded->code->insns_size &&
                a->encoded->code->insns[target] == 0x0300) {
                u2 width = a->encoded->code->insns[target + 1];
                const char *array = width == 1 ? "[B" : width == 2 ? "[S" :
                                    width == 4 ? "[I" : width == 8 ? "[J" : NULL;
                if (array != NULL)
                    constrain(a, value, array);
            }
        }
        if (ins->code == DEX_INS_IF_EQ || ins->code == DEX_INS_IF_NE ||
            ins->code == DEX_INS_IF_EQZ || ins->code == DEX_INS_IF_NEZ) {
            int r = (int)dex_ins_parameter(ins, 0);
            int value = dex_analysis_input(a, ins->offset, r);
            bool reference = value >= 0 && (a->types[value].kinds & DEX_VALUE_REFERENCE);
            bool pair = ins->code == DEX_INS_IF_EQ || ins->code == DEX_INS_IF_NE;
            int other = pair ? (int)dex_ins_parameter(ins, 1) : -1;
            int other_value = pair ? dex_analysis_input(a, ins->offset, other) : -1;
            reference |= other_value >= 0 && (a->types[other_value].kinds & DEX_VALUE_REFERENCE);
            const char *desc = reference ? "Ljava/lang/Object;" : "I";
            input(a, ins, r, desc);
            if (pair)
                input(a, ins, other, desc);
        }
        for (size_t r = 0; bitset_next_set_bit(ins->defs, &r); r++) {
            int value = dex_analysis_output(a, ins->offset, (int)r);
            if (a->types[value].kinds == 0)
                a->types[value].kinds = ins->code >= DEX_INS_CONST_WIDE_16 && ins->code <= DEX_INS_CONST_WIDE_HIGH16 ? DEX_VALUE_LONG : DEX_VALUE_INT;
        }
    }
    if (a->failed)
        fprintf(stderr, "timestamp=%lld level=ERROR event=dex_analysis_undefined_input method_id=%u\n",
                (long long)time(NULL), a->encoded->method_id);
}
