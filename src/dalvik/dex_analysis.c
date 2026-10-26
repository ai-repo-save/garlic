#include "dalvik/dex_analysis.h"

#include "dalvik/dex_decompile.h"
#include "dalvik/dex_ins.h"
#include "dalvik/dex_method.h"
#include "parser/dex/metadata.h"

static bool instruction_can_throw(u1 op)
{
    if ((op >= DEX_INS_CONST_STRING && op <= DEX_INS_CONST_CLASS) ||
        (op >= DEX_INS_MONITOR_ENTER && op <= DEX_INS_THROW) ||
        (op >= DEX_INS_AGET && op <= DEX_INS_SPUT_SHORT) ||
        (op >= DEX_INS_INVOKE_VIRTUAL && op <= DEX_INS_INVOKE_INTERFACE) ||
        (op >= DEX_INS_INVOKE_VIRTUAL_RANGE && op <= DEX_INS_INVOKE_INTERFACE_RANGE) ||
        (op >= DEX_INS_INVOKE_POLYMORPHIC && op <= DEX_INS_CONST_METHOD_TYPE))
        return true;
    switch (op) {
        case DEX_INS_DIV_INT: case DEX_INS_REM_INT:
        case DEX_INS_DIV_LONG: case DEX_INS_REM_LONG:
        case DEX_INS_DIV_INT_2ADDR: case DEX_INS_REM_INT_2ADDR:
        case DEX_INS_DIV_LONG_2ADDR: case DEX_INS_REM_LONG_2ADDR:
        case DEX_INS_DIV_INT_LIT16: case DEX_INS_REM_INT_LIT16:
        case DEX_INS_DIV_INT_LIT8: case DEX_INS_REM_INT_LIT8:
            return true;
        default:
            return false;
    }
}

int dex_analysis_input(dex_analysis *analysis, int unit, int reg)
{
    if (unit < 0)
        return sform_register_root(analysis->ssa, analysis->ssa->parameters[reg]);
    return sform_register_input(analysis->ssa, analysis->offsets[unit], reg);
}

int dex_analysis_output(dex_analysis *analysis, int unit, int reg)
{
    if (unit < 0)
        return dex_analysis_input(analysis, unit, reg);
    return sform_register_root(analysis->ssa,
        analysis->ssa->outputs[analysis->offsets[unit]][reg]);
}

unsigned dex_analysis_use_kind(dex_analysis *analysis, int unit, int reg)
{
    int value = dex_analysis_input(analysis, unit, reg);
    if (value < 0)
        return 0;
    unsigned kinds = unit < 0 ? 0 : analysis->uses[analysis->offsets[unit]][reg];
    if (kinds == 0)
        kinds = analysis->types[value].kinds;
    return kinds & (~kinds + 1);
}

dex_analysis *dex_analyze_method(jd_meta_dex *meta, encoded_method *encoded)
{
    dex_analysis *analysis = make_obj_zero(dex_analysis);
    analysis->dex = meta;
    analysis->encoded = encoded;
    jd_dex *dex = make_obj_zero(jd_dex);
    dex->meta = meta;
    dex_init_ins_fn(dex);
    jd_method *method = make_obj_zero(jd_method);
    method->type = JD_TYPE_DALVIK;
    method->meta = dex;
    method->meta_method = encoded;
    analysis->method = method;
    dex_method_init_code(method, encoded);
    int count = method->instructions->size;
    analysis->offsets = make_obj_arr(int, encoded->code->insns_size);
    jd_register_flow *flow = make_obj_arr(jd_register_flow, count);
    for (int i = 0; i < count; i++) {
        jd_ins *ins = lget_obj(method->instructions, i);
        analysis->offsets[ins->offset] = i;
        flow[i].instruction = ins;
        flow[i].clobbers = bitset_copy(ins->defs);
        if (dex_opcode_result_width(ins->code) == 2)
            bitset_set(flow[i].clobbers, bitset_minimum(ins->defs) + 1);
        flow[i].handlers = linit_object();
        if (!instruction_can_throw(ins->code))
            continue;
        for (int e = 0; e < method->cfg_exceptions->size; e++) {
            jd_exc *exception = lget_obj(method->cfg_exceptions, e);
            if (ins->idx < exception->try_start_idx || ins->idx > exception->try_end_idx)
                continue;
            jd_ins *handler = lget_obj(method->instructions, exception->handler_start_idx);
            ladd_obj_no_dup(flow[i].handlers, handler);
        }
    }
    analysis->ssa = sform_register_analyze(flow, count, method->max_locals,
        method->max_locals - encoded->code->ins_size);
    analysis->types = make_obj_arr(dex_value_type, analysis->ssa->definition_count);
    memset(analysis->types, 0, sizeof(dex_value_type) * analysis->ssa->definition_count);
    analysis->uses = make_obj_arr(unsigned *, count);
    for (int i = 0; i < count; i++) {
        analysis->uses[i] = make_obj_arr(unsigned, method->max_locals);
        memset(analysis->uses[i], 0, sizeof(unsigned) * method->max_locals);
    }
    dex_analysis_types(analysis);
    return analysis;
}
