#include "dalvik/dex_jimple.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "dalvik/dex_analysis.h"

#include "dalvik/dex_ins_helper.h"
#include "dalvik/dex_meta_helper.h"
#include "dalvik/dex_smali.h"
#include "dalvik/dex_smali_write.h"
#include "libs/memory/mem_pool.h"

typedef struct {
    char *name;
    char *type;
} jimple_reg;

typedef struct {
    jd_meta_dex *dex;
    dex_code_item *code;
    dex_analysis *analysis;
    int unit;
    char *signature;
    FILE *stream;
    jimple_reg *regs;
    int nregs;
    char **locals;
    char **local_types;
    int nlocals;
    char **lines;
    int nlines;
    unsigned char *labels;
    int end_label;
    char *pending_invoke;
    char *pending_type;
    int failed;
} jimple_body;

static s4 read_s4(const dex_code_item *code, int unit);
static void emit_switch(jimple_body *body, int i);
static void emit_fill_array(jimple_body *body, int i);
static void emit_special_invoke(jimple_body *body, int i);
static void apply_cleanup(jimple_body *body);

static int slot_width(const char *desc)
{
    return desc != NULL && (desc[0] == 'J' || desc[0] == 'D') ? 2 : 1;
}

static char *pool_printf(const char *fmt, ...)
{
    va_list ap;
    char *out;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0)
        return "";
    out = x_alloc((size_t)n + 1);
    va_start(ap, fmt);
    vsnprintf(out, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return out;
}

static char *jimple_long_literal(s8 value)
{
    if (value == INT64_MIN)
        return "(-9223372036854775807L - 1L)";
    return pool_printf("%lldL", (long long)value);
}

static char *jimple_string(const char *text)
{
    size_t n = text == NULL ? 0 : strlen(text);
    char *out = x_alloc(n * 4 + 3);
    size_t i;
    size_t w = 0;
    out[w++] = '"';
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c == '\\' || c == '"') {
            out[w++] = '\\';
            out[w++] = (char)c;
        } else if (c == '\n') {
            out[w++] = '\\';
            out[w++] = 'n';
        } else if (c < 0x20 || c == 0x7f) {
            w += (size_t)sprintf(out + w, "\\u%04x", c);
        } else {
            out[w++] = (char)c;
        }
    }
    out[w++] = '"';
    out[w] = '\0';
    return out;
}

static char *jimple_type(const char *desc)
{
    char *out;
    size_t n;
    size_t i;
    int dims;
    const char *base;

    if (desc == NULL || desc[0] == '\0')
        return "java.lang.Object";
    dims = 0;
    while (desc[dims] == '[')
        dims++;
    base = desc + dims;
    switch (base[0]) {
        case 'V': out = "void"; break;
        case 'Z': out = "boolean"; break;
        case 'B': out = "byte"; break;
        case 'S': out = "short"; break;
        case 'C': out = "char"; break;
        case 'I': out = "int"; break;
        case 'J': out = "long"; break;
        case 'F': out = "float"; break;
        case 'D': out = "double"; break;
        case 'L':
            n = strlen(base);
            if (n >= 2 && base[n - 1] == ';')
                n -= 1;
            out = x_alloc(n);
            memcpy(out, base + 1, n - 1);
            out[n - 1] = '\0';
            for (i = 0; out[i] != '\0'; i++) {
                if (out[i] == '/')
                    out[i] = '.';
            }
            break;
        default:
            out = "java.lang.Object";
            break;
    }
    for (i = 0; i < (size_t)dims; i++)
        out = pool_printf("%s[]", out);
    return out;
}

static int is_ref_type(const char *type)
{
    return type != NULL && strcmp(type, "int") != 0 && strcmp(type, "boolean") != 0 &&
           strcmp(type, "byte") != 0 && strcmp(type, "short") != 0 &&
           strcmp(type, "char") != 0 && strcmp(type, "long") != 0 &&
           strcmp(type, "float") != 0 && strcmp(type, "double") != 0 &&
           strcmp(type, "void") != 0;
}

static char *type_prefix(const char *type)
{
    if (type == NULL)
        return "u";
    if (strcmp(type, "int") == 0 || strcmp(type, "boolean") == 0 ||
        strcmp(type, "byte") == 0 || strcmp(type, "short") == 0 ||
        strcmp(type, "char") == 0)
        return "i";
    if (strcmp(type, "long") == 0)
        return "l";
    if (strcmp(type, "float") == 0)
        return "f";
    if (strcmp(type, "double") == 0)
        return "d";
    return "r";
}

static void remember_local(jimple_body *body, char *name, char *type)
{
    int i;
    for (i = 0; i < body->nlocals; i++) {
        if (strcmp(body->locals[i], name) == 0)
            return;
    }
    body->locals = realloc(body->locals, (size_t)(body->nlocals + 1) * sizeof(char *));
    body->local_types = realloc(body->local_types, (size_t)(body->nlocals + 1) * sizeof(char *));
    body->locals[body->nlocals] = name;
    body->local_types[body->nlocals] = type;
    body->nlocals++;
}

static char *value_type(jimple_body *body, int value, unsigned kind)
{
    switch (kind) {
        case DEX_VALUE_FLOAT: return "float";
        case DEX_VALUE_LONG: return "long";
        case DEX_VALUE_DOUBLE: return "double";
        case DEX_VALUE_REFERENCE:
            return body->analysis->types[value].array != NULL
                   ? jimple_type(body->analysis->types[value].array) : "java.lang.Object";
        default: return "int";
    }
}

static char *value_local(jimple_body *body, int reg, int value, unsigned kind)
{
    if (value < 0 || kind == 0) {
        body->failed = 1;
        return "bad";
    }
    char *type = value_type(body, value, kind);
    char *name = pool_printf("%s%d_%d", type_prefix(type), reg, value);
    remember_local(body, name, type);
    return name;
}

static unsigned java_type_kind(const char *type)
{
    if (strcmp(type, "float") == 0) return DEX_VALUE_FLOAT;
    if (strcmp(type, "long") == 0) return DEX_VALUE_LONG;
    if (strcmp(type, "double") == 0) return DEX_VALUE_DOUBLE;
    return is_ref_type(type) ? DEX_VALUE_REFERENCE : DEX_VALUE_INT;
}

static char *def_reg(jimple_body *body, int reg, char *type)
{
    int value = dex_analysis_output(body->analysis, body->unit, reg);
    if (value < 0) {
        body->failed = 1;
        return "bad";
    }
    unsigned kinds = body->analysis->types[value].kinds;
    unsigned kind = java_type_kind(type);
    if (!(kinds & kind))
        kind = kinds & (~kinds + 1);
    body->regs[reg].type = value_type(body, value, kind);
    body->regs[reg].name = value_local(body, reg, value, kind);
    return body->regs[reg].name;
}

static char *use_reg(jimple_body *body, int reg)
{
    if (reg < 0 || reg >= body->nregs || body->regs[reg].name == NULL) {
        body->failed = 1;
        return "bad";
    }
    return body->regs[reg].name;
}

static void load_inputs(jimple_body *body, int unit)
{
    body->unit = unit;
    memset(body->regs, 0, sizeof(jimple_reg) * (size_t)body->nregs);
    for (int reg = 0; reg < body->nregs; reg++) {
        int value = dex_analysis_input(body->analysis, unit, reg);
        unsigned kind = dex_analysis_use_kind(body->analysis, unit, reg);
        if (value < 0 || kind == 0)
            continue;
        body->regs[reg].type = value_type(body, value, kind);
        body->regs[reg].name = value_local(body, reg, value, kind);
    }
}

static int reg_slots(jimple_body *body, int reg)
{
    const char *ty;
    if (reg < 0 || reg >= body->nregs || body->regs[reg].type == NULL)
        return 1;
    ty = body->regs[reg].type;
    return (strcmp(ty, "long") == 0 || strcmp(ty, "double") == 0) ? 2 : 1;
}

static char *append_reg_arg(jimple_body *body, char *args, int *started, int reg, int *prev)
{
    if (*prev >= 0 && reg == *prev + 1 && reg_slots(body, *prev) == 2) {
        *prev = reg;
        return args;
    }
    args = pool_printf("%s%s%s", args, *started ? ", " : "", use_reg(body, reg));
    *started = 1;
    *prev = reg;
    return args;
}

static void mark_label(jimple_body *body, int unit)
{
    if (unit < 0)
        return;
    if (unit >= (int)body->code->insns_size) {
        body->end_label = 1;
        return;
    }
    body->labels[unit] = 1;
}

static int branch_target(u1 op, const dex_code_item *code, int i)
{
    u4 raw;
    if (op == DEX_INS_GOTO)
        return i + (s4)(s1)((code->insns[i] >> 8) & 0xFF);
    if (op == DEX_INS_GOTO_16 || (op >= DEX_INS_IF_EQ && op <= DEX_INS_IF_LEZ))
        return i + (s2)code->insns[i + 1];
    raw = (u4)code->insns[i + 1] | ((u4)code->insns[i + 2] << 16);
    return i + (s4)raw;
}

static char *method_sig(jd_meta_dex *dex, u2 method_idx)
{
    dex_method_id *id = &dex->method_ids[method_idx];
    dex_proto_id *proto = &dex->proto_ids[id->proto_idx];
    char *cls = jimple_type(dex_str_of_type_id(dex, id->class_idx));
    char *ret = jimple_type(dex_str_of_type_id(dex, proto->return_type_idx));
    char *name = dex_str_of_method_id(dex, method_idx);
    char *args = x_alloc(1);
    int i;
    args[0] = '\0';
    if (proto->type_list != NULL) {
        for (i = 0; i < (int)proto->type_list->size; i++) {
            char *ty = jimple_type(dex_str_of_type_id(dex, proto->type_list->list[i].type_idx));
            args = pool_printf("%s%s%s", args, i == 0 ? "" : ",", ty);
        }
    }
    return pool_printf("<%s: %s %s(%s)>", cls, ret, name, args);
}

static char *method_return(jd_meta_dex *dex, u2 method_idx)
{
    dex_method_id *id = &dex->method_ids[method_idx];
    dex_proto_id *proto = &dex->proto_ids[id->proto_idx];
    return jimple_type(dex_str_of_type_id(dex, proto->return_type_idx));
}

static const char *invoke_kind(u1 op)
{
    switch (op) {
        case DEX_INS_INVOKE_VIRTUAL:
        case DEX_INS_INVOKE_VIRTUAL_RANGE:
            return "virtualinvoke";
        case DEX_INS_INVOKE_SUPER:
        case DEX_INS_INVOKE_SUPER_RANGE:
        case DEX_INS_INVOKE_DIRECT:
        case DEX_INS_INVOKE_DIRECT_RANGE:
            return "specialinvoke";
        case DEX_INS_INVOKE_STATIC:
        case DEX_INS_INVOKE_STATIC_RANGE:
            return "staticinvoke";
        case DEX_INS_INVOKE_INTERFACE:
        case DEX_INS_INVOKE_INTERFACE_RANGE:
            return "interfaceinvoke";
        default:
            return "virtualinvoke";
    }
}

static const char *binop(u1 op)
{
    switch (op) {
        case DEX_INS_ADD_INT:
        case DEX_INS_ADD_LONG:
        case DEX_INS_ADD_FLOAT:
        case DEX_INS_ADD_DOUBLE:
        case DEX_INS_ADD_INT_2ADDR:
        case DEX_INS_ADD_LONG_2ADDR:
        case DEX_INS_ADD_FLOAT_2ADDR:
        case DEX_INS_ADD_DOUBLE_2ADDR:
        case DEX_INS_ADD_INT_LIT16:
        case DEX_INS_ADD_INT_LIT8:
            return "+";
        case DEX_INS_SUB_INT:
        case DEX_INS_SUB_LONG:
        case DEX_INS_SUB_FLOAT:
        case DEX_INS_SUB_DOUBLE:
        case DEX_INS_SUB_INT_2ADDR:
        case DEX_INS_SUB_LONG_2ADDR:
        case DEX_INS_SUB_FLOAT_2ADDR:
        case DEX_INS_SUB_DOUBLE_2ADDR:
        case DEX_INS_RSUB_INT:
        case DEX_INS_RSUB_INT_LIT8:
            return "-";
        case DEX_INS_MUL_INT:
        case DEX_INS_MUL_LONG:
        case DEX_INS_MUL_FLOAT:
        case DEX_INS_MUL_DOUBLE:
        case DEX_INS_MUL_INT_2ADDR:
        case DEX_INS_MUL_LONG_2ADDR:
        case DEX_INS_MUL_FLOAT_2ADDR:
        case DEX_INS_MUL_DOUBLE_2ADDR:
        case DEX_INS_MUL_INT_LIT16:
        case DEX_INS_MUL_INT_LIT8:
            return "*";
        case DEX_INS_DIV_INT:
        case DEX_INS_DIV_LONG:
        case DEX_INS_DIV_FLOAT:
        case DEX_INS_DIV_DOUBLE:
        case DEX_INS_DIV_INT_2ADDR:
        case DEX_INS_DIV_LONG_2ADDR:
        case DEX_INS_DIV_FLOAT_2ADDR:
        case DEX_INS_DIV_DOUBLE_2ADDR:
        case DEX_INS_DIV_INT_LIT16:
        case DEX_INS_DIV_INT_LIT8:
            return "/";
        case DEX_INS_REM_INT:
        case DEX_INS_REM_LONG:
        case DEX_INS_REM_FLOAT:
        case DEX_INS_REM_DOUBLE:
        case DEX_INS_REM_INT_2ADDR:
        case DEX_INS_REM_LONG_2ADDR:
        case DEX_INS_REM_FLOAT_2ADDR:
        case DEX_INS_REM_DOUBLE_2ADDR:
        case DEX_INS_REM_INT_LIT16:
        case DEX_INS_REM_INT_LIT8:
            return "%";
        case DEX_INS_AND_INT:
        case DEX_INS_AND_LONG:
        case DEX_INS_AND_INT_2ADDR:
        case DEX_INS_AND_LONG_2ADDR:
        case DEX_INS_AND_INT_LIT16:
        case DEX_INS_AND_INT_LIT8:
            return "&";
        case DEX_INS_OR_INT:
        case DEX_INS_OR_LONG:
        case DEX_INS_OR_INT_2ADDR:
        case DEX_INS_OR_LONG_2ADDR:
        case DEX_INS_OR_INT_LIT16:
        case DEX_INS_OR_INT_LIT8:
            return "|";
        case DEX_INS_XOR_INT:
        case DEX_INS_XOR_LONG:
        case DEX_INS_XOR_INT_2ADDR:
        case DEX_INS_XOR_LONG_2ADDR:
        case DEX_INS_XOR_INT_LIT16:
        case DEX_INS_XOR_INT_LIT8:
            return "^";
        case DEX_INS_SHL_INT:
        case DEX_INS_SHL_LONG:
        case DEX_INS_SHL_INT_2ADDR:
        case DEX_INS_SHL_LONG_2ADDR:
        case DEX_INS_SHL_INT_LIT8:
            return "<<";
        case DEX_INS_SHR_INT:
        case DEX_INS_SHR_LONG:
        case DEX_INS_SHR_INT_2ADDR:
        case DEX_INS_SHR_LONG_2ADDR:
        case DEX_INS_SHR_INT_LIT8:
            return ">>";
        case DEX_INS_USHR_INT:
        case DEX_INS_USHR_LONG:
        case DEX_INS_USHR_INT_2ADDR:
        case DEX_INS_USHR_LONG_2ADDR:
        case DEX_INS_USHR_INT_LIT8:
            return ">>>";
        default:
            return "+";
    }
}

static char *result_type_for_binop(u1 op)
{
    if ((op >= DEX_INS_ADD_LONG && op <= DEX_INS_USHR_LONG) ||
        (op >= DEX_INS_ADD_LONG_2ADDR && op <= DEX_INS_USHR_LONG_2ADDR))
        return "long";
    if ((op >= DEX_INS_ADD_FLOAT && op <= DEX_INS_REM_FLOAT) ||
        (op >= DEX_INS_ADD_FLOAT_2ADDR && op <= DEX_INS_REM_FLOAT_2ADDR))
        return "float";
    if ((op >= DEX_INS_ADD_DOUBLE && op <= DEX_INS_REM_DOUBLE) ||
        (op >= DEX_INS_ADD_DOUBLE_2ADDR && op <= DEX_INS_REM_DOUBLE_2ADDR))
        return "double";
    return "int";
}

static void add_line(jimple_body *body, const char *line)
{
    body->lines = realloc(body->lines, (size_t)(body->nlines + 1) * sizeof(char *));
    body->lines[body->nlines++] = pool_printf("%s", line);
}

static void flush_invoke(jimple_body *body)
{
    if (body->pending_invoke == NULL)
        return;
    add_line(body, pool_printf("%s;", body->pending_invoke));
    body->pending_invoke = NULL;
    body->pending_type = NULL;
}

static void emit_stmt(jimple_body *body, const char *stmt)
{
    flush_invoke(body);
    add_line(body, pool_printf("%s;", stmt));
}

static char *floating_literal(u8 bits, unsigned kind)
{
    double number;
    if (kind == DEX_VALUE_FLOAT) {
        u4 word = (u4)bits;
        float value;
        memcpy(&value, &word, sizeof(value));
        number = value;
    } else {
        memcpy(&number, &bits, sizeof(number));
    }
    const char *suffix = kind == DEX_VALUE_FLOAT ? "F" : "";
    if (isnan(number))
        return pool_printf("#NaN%s", suffix);
    if (isinf(number))
        return pool_printf("#%sInfinity%s", signbit(number) ? "-" : "", suffix);
    char *text = pool_printf(kind == DEX_VALUE_FLOAT ? "%.9g" : "%.17g", number);
    return pool_printf("%s%s%s", text, strpbrk(text, ".eE") == NULL ? ".0" : "", suffix);
}

static void emit_constant(jimple_body *body, int reg, u8 bits)
{
    int value = dex_analysis_output(body->analysis, body->unit, reg);
    if (value < 0) {
        body->failed = 1;
        return;
    }
    unsigned kinds = body->analysis->types[value].kinds;
    for (unsigned kind = 1; kind <= DEX_VALUE_REFERENCE; kind <<= 1) {
        if (!(kinds & kind))
            continue;
        char *literal;
        if (kind == DEX_VALUE_REFERENCE) {
            if (bits != 0) {
                body->failed = 1;
                return;
            }
            literal = "null";
        } else if (kind == DEX_VALUE_FLOAT || kind == DEX_VALUE_DOUBLE)
            literal = floating_literal(bits, kind);
        else if (kind == DEX_VALUE_LONG)
            literal = jimple_long_literal((s8)bits);
        else
            literal = pool_printf("%d", (s4)bits);
        emit_stmt(body, pool_printf("%s = %s", value_local(body, reg, value, kind), literal));
    }
}

static void emit_invoke(jimple_body *body, u1 op, char *sig, char *args, char *ret)
{
    const char *kind = invoke_kind(op);
    flush_invoke(body);
    if (strcmp(ret, "void") == 0) {
        if (op == DEX_INS_INVOKE_STATIC || op == DEX_INS_INVOKE_STATIC_RANGE)
            emit_stmt(body, pool_printf("%s %s(%s)", kind, sig, args));
        else
            emit_stmt(body, pool_printf("%s %s(%s)", kind, sig, args));
        return;
    }
    body->pending_type = ret;
    body->pending_invoke = pool_printf("%s %s(%s)", kind, sig, args);
}

static int reg_a_12(u2 unit) { return (unit >> 8) & 0x0F; }
static int reg_b_12(u2 unit) { return (unit >> 12) & 0x0F; }

static void emit_one(jimple_body *body, int i)
{
    jd_meta_dex *dex = body->dex;
    dex_code_item *code = body->code;
    u2 unit = code->insns[i];
    u1 op = unit & 0xFF;
    int a = reg_a_12(unit);
    int b = reg_b_12(unit);
    char *dest;
    char *stmt;

    if (body->labels[i]) {
        flush_invoke(body);
        add_line(body, pool_printf("label_%d:", i));
    }

    if (op == DEX_INS_MOVE_RESULT || op == DEX_INS_MOVE_RESULT_WIDE ||
        op == DEX_INS_MOVE_RESULT_OBJECT) {
        dest = def_reg(body, unit >> 8, body->pending_type != NULL ? body->pending_type : "int");
        if (body->pending_invoke != NULL) {
            add_line(body, pool_printf("%s = %s;", dest, body->pending_invoke));
            body->pending_invoke = NULL;
            body->pending_type = NULL;
        }
        return;
    }

    switch (op) {
        case DEX_INS_NOP:
            break;
        case DEX_INS_MOVE:
        case DEX_INS_MOVE_FROM16:
        case DEX_INS_MOVE_16:
        case DEX_INS_MOVE_WIDE:
        case DEX_INS_MOVE_WIDE_FROM16:
        case DEX_INS_MOVE_WIDE_16:
        case DEX_INS_MOVE_OBJECT:
        case DEX_INS_MOVE_OBJECT_FROM16:
        case DEX_INS_MOVE_OBJECT_16: {
            int src;
            int dst;
            if (op == DEX_INS_MOVE || op == DEX_INS_MOVE_WIDE || op == DEX_INS_MOVE_OBJECT) {
                dst = a;
                src = b;
            } else if (op == DEX_INS_MOVE_FROM16 || op == DEX_INS_MOVE_WIDE_FROM16 ||
                       op == DEX_INS_MOVE_OBJECT_FROM16) {
                dst = unit >> 8;
                src = code->insns[i + 1];
            } else {
                dst = code->insns[i + 1];
                src = code->insns[i + 2];
            }
            int source = dex_analysis_input(body->analysis, i, src);
            int target = dex_analysis_output(body->analysis, i, dst);
            if (source < 0 || target < 0) {
                body->failed = 1;
                break;
            }
            unsigned kinds = body->analysis->types[target].kinds;
            for (unsigned kind = 1; kind <= DEX_VALUE_REFERENCE; kind <<= 1) {
                if (kinds & kind)
                    emit_stmt(body, pool_printf("%s = %s",
                        value_local(body, dst, target, kind), value_local(body, src, source, kind)));
            }
            break;
        }
        case DEX_INS_MOVE_EXCEPTION:
            dest = def_reg(body, unit >> 8, "java.lang.Throwable");
            emit_stmt(body, pool_printf("%s := @caughtexception", dest));
            break;
        case DEX_INS_RETURN_VOID:
            emit_stmt(body, "return");
            break;
        case DEX_INS_RETURN:
        case DEX_INS_RETURN_WIDE:
        case DEX_INS_RETURN_OBJECT:
            emit_stmt(body, pool_printf("return %s", use_reg(body, unit >> 8)));
            break;
        case DEX_INS_CONST_4: {
            s4 lit = (s4)(unit >> 12);
            if (lit > 7)
                lit -= 16;
            emit_constant(body, a, (u4)lit);
            break;
        }
        case DEX_INS_CONST_16:
        case DEX_INS_CONST:
        case DEX_INS_CONST_HIGH16: {
            s4 lit;
            int dst = unit >> 8;
            if (op == DEX_INS_CONST_16)
                lit = (s2)code->insns[i + 1];
            else if (op == DEX_INS_CONST_HIGH16)
                lit = (s4)((u4)code->insns[i + 1] << 16);
            else
                lit = (s4)((u4)code->insns[i + 1] | ((u4)code->insns[i + 2] << 16));
            emit_constant(body, dst, (u4)lit);
            break;
        }
        case DEX_INS_CONST_STRING:
        case DEX_INS_CONST_STRING_JUMBO: {
            u4 idx = op == DEX_INS_CONST_STRING ? code->insns[i + 1] :
                     ((u4)code->insns[i + 1] | ((u4)code->insns[i + 2] << 16));
            int dst = op == DEX_INS_CONST_STRING ? unit >> 8 : unit >> 8;
            dest = def_reg(body, dst, "java.lang.String");
            emit_stmt(body, pool_printf("%s = %s", dest, jimple_string(dex_str_of_idx(dex, idx))));
            break;
        }
        case DEX_INS_CONST_CLASS: {
            char *desc = dex_str_of_type_id(dex, code->insns[i + 1]);
            dest = def_reg(body, unit >> 8, "java.lang.Class");
            emit_stmt(body, pool_printf("%s = class %s", dest, jimple_string(desc)));
            break;
        }
        case DEX_INS_IF_EQ:
        case DEX_INS_IF_NE:
        case DEX_INS_IF_LT:
        case DEX_INS_IF_GE:
        case DEX_INS_IF_GT:
        case DEX_INS_IF_LE: {
            const char *cmp = op == DEX_INS_IF_EQ ? "==" :
                              op == DEX_INS_IF_NE ? "!=" :
                              op == DEX_INS_IF_LT ? "<" :
                              op == DEX_INS_IF_GE ? ">=" :
                              op == DEX_INS_IF_GT ? ">" : "<=";
            emit_stmt(body, pool_printf("if %s %s %s goto label_%d",
                                        use_reg(body, a), cmp, use_reg(body, b),
                                        branch_target(op, code, i)));
            break;
        }
        case DEX_INS_IF_EQZ:
        case DEX_INS_IF_NEZ:
        case DEX_INS_IF_LTZ:
        case DEX_INS_IF_GEZ:
        case DEX_INS_IF_GTZ:
        case DEX_INS_IF_LEZ: {
            const char *cmp = op == DEX_INS_IF_EQZ ? "==" :
                              op == DEX_INS_IF_NEZ ? "!=" :
                              op == DEX_INS_IF_LTZ ? "<" :
                              op == DEX_INS_IF_GEZ ? ">=" :
                              op == DEX_INS_IF_GTZ ? ">" : "<=";
            char *left = use_reg(body, unit >> 8);
            char *zero = is_ref_type(body->regs[unit >> 8].type) ? "null" : "0";
            emit_stmt(body, pool_printf("if %s %s %s goto label_%d",
                                        left, cmp, zero, branch_target(op, code, i)));
            break;
        }
        case DEX_INS_GOTO:
        case DEX_INS_GOTO_16:
        case DEX_INS_GOTO_32:
            emit_stmt(body, pool_printf("goto label_%d", branch_target(op, code, i)));
            break;
        case DEX_INS_IGET:
        case DEX_INS_IGET_WIDE:
        case DEX_INS_IGET_OBJECT:
        case DEX_INS_IGET_BOOLEAN:
        case DEX_INS_IGET_BYTE:
        case DEX_INS_IGET_CHAR:
        case DEX_INS_IGET_SHORT:
        case DEX_INS_SGET:
        case DEX_INS_SGET_WIDE:
        case DEX_INS_SGET_OBJECT:
        case DEX_INS_SGET_BOOLEAN:
        case DEX_INS_SGET_BYTE:
        case DEX_INS_SGET_CHAR:
        case DEX_INS_SGET_SHORT: {
            u2 field = code->insns[i + 1];
            char *ty = jimple_type(dex_str_of_field_type(dex, field));
            char *cls = jimple_type(dex_str_of_field_class(dex, field));
            char *name = dex_str_of_field_name(dex, field);
            int dst = (op >= DEX_INS_SGET) ? unit >> 8 : a;
            int obj = b;
            char *base = op >= DEX_INS_SGET ? NULL : use_reg(body, obj);
            dest = def_reg(body, dst, ty);
            if (op >= DEX_INS_SGET)
                stmt = pool_printf("%s = <%s: %s %s>", dest, cls, ty, name);
            else
                stmt = pool_printf("%s = %s.<%s: %s %s>", dest, base, cls, ty, name);
            emit_stmt(body, stmt);
            break;
        }
        case DEX_INS_IPUT:
        case DEX_INS_IPUT_WIDE:
        case DEX_INS_IPUT_OBJECT:
        case DEX_INS_IPUT_BOOLEAN:
        case DEX_INS_IPUT_BYTE:
        case DEX_INS_IPUT_CHAR:
        case DEX_INS_IPUT_SHORT:
        case DEX_INS_SPUT:
        case DEX_INS_SPUT_WIDE:
        case DEX_INS_SPUT_OBJECT:
        case DEX_INS_SPUT_BOOLEAN:
        case DEX_INS_SPUT_BYTE:
        case DEX_INS_SPUT_CHAR:
        case DEX_INS_SPUT_SHORT: {
            u2 field = code->insns[i + 1];
            char *ty = jimple_type(dex_str_of_field_type(dex, field));
            char *cls = jimple_type(dex_str_of_field_class(dex, field));
            char *name = dex_str_of_field_name(dex, field);
            int src = (op >= DEX_INS_SPUT) ? unit >> 8 : a;
            int obj = b;
            if (op >= DEX_INS_SPUT)
                stmt = pool_printf("<%s: %s %s> = %s", cls, ty, name, use_reg(body, src));
            else
                stmt = pool_printf("%s.<%s: %s %s> = %s", use_reg(body, obj), cls, ty, name, use_reg(body, src));
            emit_stmt(body, stmt);
            break;
        }
        case DEX_INS_INVOKE_VIRTUAL:
        case DEX_INS_INVOKE_SUPER:
        case DEX_INS_INVOKE_DIRECT:
        case DEX_INS_INVOKE_STATIC:
        case DEX_INS_INVOKE_INTERFACE:
        case DEX_INS_INVOKE_VIRTUAL_RANGE:
        case DEX_INS_INVOKE_SUPER_RANGE:
        case DEX_INS_INVOKE_DIRECT_RANGE:
        case DEX_INS_INVOKE_STATIC_RANGE:
        case DEX_INS_INVOKE_INTERFACE_RANGE: {
            u2 method = code->insns[i + 1];
            char *args = x_alloc(1);
            int count;
            int regs5[5];
            int n;
            args[0] = '\0';
            {
                int started = 0;
                int prev = -1;
                if (op >= DEX_INS_INVOKE_VIRTUAL_RANGE) {
                    count = unit >> 8;
                    for (n = 0; n < count; n++)
                        args = append_reg_arg(body, args, &started, code->insns[i + 2] + n, &prev);
                } else {
                    u2 regs = code->insns[i + 2];
                    count = unit >> 12;
                    regs5[0] = regs & 0x0F;
                    regs5[1] = (regs >> 4) & 0x0F;
                    regs5[2] = (regs >> 8) & 0x0F;
                    regs5[3] = (regs >> 12) & 0x0F;
                    regs5[4] = (unit >> 8) & 0x0F;
                    for (n = 0; n < count && n < 5; n++)
                        args = append_reg_arg(body, args, &started, regs5[n], &prev);
                }
            }
            {
                int is_static = op == DEX_INS_INVOKE_STATIC || op == DEX_INS_INVOKE_STATIC_RANGE;
                char *sig = method_sig(dex, method);
                char *ret = method_return(dex, method);
                char *expr;
                if (is_static) {
                    expr = pool_printf("staticinvoke %s(%s)", sig, args);
                } else {
                    char *base = args;
                    char *rest = strchr(args, ',');
                    if (rest != NULL) {
                        *rest = '\0';
                        rest += 2;
                    } else {
                        rest = "";
                    }
                    expr = pool_printf("%s %s.%s(%s)", invoke_kind(op), base, sig, rest);
                }
                flush_invoke(body);
                if (strcmp(ret, "void") == 0)
                    emit_stmt(body, expr);
                else {
                    body->pending_type = ret;
                    body->pending_invoke = expr;
                }
            }
            break;
        }
        case DEX_INS_ADD_INT:
        case DEX_INS_SUB_INT:
        case DEX_INS_MUL_INT:
        case DEX_INS_DIV_INT:
        case DEX_INS_REM_INT:
        case DEX_INS_AND_INT:
        case DEX_INS_OR_INT:
        case DEX_INS_XOR_INT:
        case DEX_INS_SHL_INT:
        case DEX_INS_SHR_INT:
        case DEX_INS_USHR_INT:
        case DEX_INS_ADD_LONG:
        case DEX_INS_SUB_LONG:
        case DEX_INS_MUL_LONG:
        case DEX_INS_DIV_LONG:
        case DEX_INS_REM_LONG:
        case DEX_INS_AND_LONG:
        case DEX_INS_OR_LONG:
        case DEX_INS_XOR_LONG:
        case DEX_INS_SHL_LONG:
        case DEX_INS_SHR_LONG:
        case DEX_INS_USHR_LONG:
        case DEX_INS_ADD_FLOAT:
        case DEX_INS_SUB_FLOAT:
        case DEX_INS_MUL_FLOAT:
        case DEX_INS_DIV_FLOAT:
        case DEX_INS_REM_FLOAT:
        case DEX_INS_ADD_DOUBLE:
        case DEX_INS_SUB_DOUBLE:
        case DEX_INS_MUL_DOUBLE:
        case DEX_INS_DIV_DOUBLE:
        case DEX_INS_REM_DOUBLE: {
            int dst = unit >> 8;
            int src1 = code->insns[i + 1] & 0xFF;
            int src2 = code->insns[i + 1] >> 8;
            char *ty = result_type_for_binop(op);
            char *left = use_reg(body, src1);
            char *right = use_reg(body, src2);
            dest = def_reg(body, dst, ty);
            emit_stmt(body, pool_printf("%s = %s %s %s", dest, left, binop(op), right));
            break;
        }
        case DEX_INS_ADD_INT_2ADDR:
        case DEX_INS_SUB_INT_2ADDR:
        case DEX_INS_MUL_INT_2ADDR:
        case DEX_INS_DIV_INT_2ADDR:
        case DEX_INS_REM_INT_2ADDR:
        case DEX_INS_AND_INT_2ADDR:
        case DEX_INS_OR_INT_2ADDR:
        case DEX_INS_XOR_INT_2ADDR:
        case DEX_INS_SHL_INT_2ADDR:
        case DEX_INS_SHR_INT_2ADDR:
        case DEX_INS_USHR_INT_2ADDR:
        case DEX_INS_ADD_LONG_2ADDR:
        case DEX_INS_SUB_LONG_2ADDR:
        case DEX_INS_MUL_LONG_2ADDR:
        case DEX_INS_DIV_LONG_2ADDR:
        case DEX_INS_REM_LONG_2ADDR:
        case DEX_INS_AND_LONG_2ADDR:
        case DEX_INS_OR_LONG_2ADDR:
        case DEX_INS_XOR_LONG_2ADDR:
        case DEX_INS_SHL_LONG_2ADDR:
        case DEX_INS_SHR_LONG_2ADDR:
        case DEX_INS_USHR_LONG_2ADDR:
        case DEX_INS_ADD_FLOAT_2ADDR:
        case DEX_INS_SUB_FLOAT_2ADDR:
        case DEX_INS_MUL_FLOAT_2ADDR:
        case DEX_INS_DIV_FLOAT_2ADDR:
        case DEX_INS_REM_FLOAT_2ADDR:
        case DEX_INS_ADD_DOUBLE_2ADDR:
        case DEX_INS_SUB_DOUBLE_2ADDR:
        case DEX_INS_MUL_DOUBLE_2ADDR:
        case DEX_INS_DIV_DOUBLE_2ADDR:
        case DEX_INS_REM_DOUBLE_2ADDR: {
            char *ty = result_type_for_binop(op);
            char *left = use_reg(body, a);
            char *right = use_reg(body, b);
            dest = def_reg(body, a, ty);
            emit_stmt(body, pool_printf("%s = %s %s %s", dest, left, binop(op), right));
            break;
        }
        case DEX_INS_ADD_INT_LIT8:
        case DEX_INS_RSUB_INT_LIT8:
        case DEX_INS_MUL_INT_LIT8:
        case DEX_INS_DIV_INT_LIT8:
        case DEX_INS_REM_INT_LIT8:
        case DEX_INS_AND_INT_LIT8:
        case DEX_INS_OR_INT_LIT8:
        case DEX_INS_XOR_INT_LIT8:
        case DEX_INS_SHL_INT_LIT8:
        case DEX_INS_SHR_INT_LIT8:
        case DEX_INS_USHR_INT_LIT8:
        case DEX_INS_ADD_INT_LIT16:
        case DEX_INS_RSUB_INT:
        case DEX_INS_MUL_INT_LIT16:
        case DEX_INS_DIV_INT_LIT16:
        case DEX_INS_REM_INT_LIT16:
        case DEX_INS_AND_INT_LIT16:
        case DEX_INS_OR_INT_LIT16:
        case DEX_INS_XOR_INT_LIT16: {
            int dst;
            int src;
            s4 lit;
            if (op >= DEX_INS_ADD_INT_LIT8) {
                dst = unit >> 8;
                src = code->insns[i + 1] & 0xFF;
                lit = (s1)(code->insns[i + 1] >> 8);
            } else {
                dst = a;
                src = b;
                lit = (s2)code->insns[i + 1];
            }
            char *source = use_reg(body, src);
            dest = def_reg(body, dst, "int");
            if (op == DEX_INS_RSUB_INT || op == DEX_INS_RSUB_INT_LIT8)
                emit_stmt(body, pool_printf("%s = %d - %s", dest, lit, source));
            else
                emit_stmt(body, pool_printf("%s = %s %s %d", dest, source, binop(op), lit));
            break;
        }
        case DEX_INS_NEG_INT:
        case DEX_INS_NOT_INT:
        case DEX_INS_NEG_LONG:
        case DEX_INS_NOT_LONG:
        case DEX_INS_NEG_FLOAT:
        case DEX_INS_NEG_DOUBLE: {
            int dst = a;
            int src = b;
            char *source = use_reg(body, src);
            char *ty = (op == DEX_INS_NEG_LONG || op == DEX_INS_NOT_LONG) ? "long" :
                       (op == DEX_INS_NEG_FLOAT) ? "float" :
                       (op == DEX_INS_NEG_DOUBLE) ? "double" : "int";
            dest = def_reg(body, dst, ty);
            if (op == DEX_INS_NOT_INT || op == DEX_INS_NOT_LONG)
                emit_stmt(body, pool_printf("%s = %s ^ %s", dest, source,
                                            strcmp(ty, "long") == 0 ? "-1L" : "-1"));
            else
                emit_stmt(body, pool_printf("%s = neg %s", dest, source));
            break;
        }
        case DEX_INS_INT_TO_LONG:
        case DEX_INS_INT_TO_FLOAT:
        case DEX_INS_INT_TO_DOUBLE:
        case DEX_INS_LONG_TO_INT:
        case DEX_INS_LONG_TO_FLOAT:
        case DEX_INS_LONG_TO_DOUBLE:
        case DEX_INS_FLOAT_TO_INT:
        case DEX_INS_FLOAT_TO_LONG:
        case DEX_INS_FLOAT_TO_DOUBLE:
        case DEX_INS_DOUBLE_TO_INT:
        case DEX_INS_DOUBLE_TO_LONG:
        case DEX_INS_DOUBLE_TO_FLOAT:
        case DEX_INS_INT_TO_BYTE:
        case DEX_INS_INT_TO_CHAR:
        case DEX_INS_INT_TO_SHORT: {
            int dst = a;
            int src = b;
            char *source = use_reg(body, src);
            char *ty = "int";
            if (op == DEX_INS_INT_TO_LONG || op == DEX_INS_FLOAT_TO_LONG || op == DEX_INS_DOUBLE_TO_LONG)
                ty = "long";
            else if (op == DEX_INS_INT_TO_FLOAT || op == DEX_INS_LONG_TO_FLOAT || op == DEX_INS_DOUBLE_TO_FLOAT)
                ty = "float";
            else if (op == DEX_INS_INT_TO_DOUBLE || op == DEX_INS_LONG_TO_DOUBLE || op == DEX_INS_FLOAT_TO_DOUBLE)
                ty = "double";
            else if (op == DEX_INS_INT_TO_BYTE)
                ty = "byte";
            else if (op == DEX_INS_INT_TO_CHAR)
                ty = "char";
            else if (op == DEX_INS_INT_TO_SHORT)
                ty = "short";
            dest = def_reg(body, dst, ty);
            emit_stmt(body, pool_printf("%s = (%s) %s", dest, ty, source));
            break;
        }
        case DEX_INS_NEW_INSTANCE: {
            char *ty = jimple_type(dex_str_of_type_id(dex, code->insns[i + 1]));
            dest = def_reg(body, unit >> 8, ty);
            emit_stmt(body, pool_printf("%s = new %s", dest, ty));
            break;
        }
        case DEX_INS_CHECK_CAST: {
            char *ty = jimple_type(dex_str_of_type_id(dex, code->insns[i + 1]));
            char *src = use_reg(body, unit >> 8);
            dest = def_reg(body, unit >> 8, ty);
            emit_stmt(body, pool_printf("%s = (%s) %s", dest, ty, src));
            break;
        }
        case DEX_INS_INSTANCE_OF: {
            char *ty = jimple_type(dex_str_of_type_id(dex, code->insns[i + 1]));
            char *source = use_reg(body, b);
            dest = def_reg(body, a, "boolean");
            emit_stmt(body, pool_printf("%s = %s instanceof %s", dest, source, ty));
            break;
        }
        case DEX_INS_ARRAY_LENGTH: {
            char *source = use_reg(body, b);
            dest = def_reg(body, a, "int");
            emit_stmt(body, pool_printf("%s = lengthof %s", dest, source));
            break;
        }
        case DEX_INS_THROW:
            emit_stmt(body, pool_printf("throw %s", use_reg(body, unit >> 8)));
            break;
        case DEX_INS_MONITOR_ENTER:
            emit_stmt(body, pool_printf("entermonitor %s", use_reg(body, unit >> 8)));
            break;
        case DEX_INS_MONITOR_EXIT:
            emit_stmt(body, pool_printf("exitmonitor %s", use_reg(body, unit >> 8)));
            break;
        case DEX_INS_AGET:
        case DEX_INS_AGET_WIDE:
        case DEX_INS_AGET_OBJECT:
        case DEX_INS_AGET_BOOLEAN:
        case DEX_INS_AGET_BYTE:
        case DEX_INS_AGET_CHAR:
        case DEX_INS_AGET_SHORT: {
            int dst = unit >> 8;
            int arr = code->insns[i + 1] & 0xFF;
            int idx = code->insns[i + 1] >> 8;
            char *ty = op == DEX_INS_AGET_OBJECT ? "java.lang.Object" :
                       op == DEX_INS_AGET_WIDE ? "long" : "int";
            char *array = use_reg(body, arr);
            char *index = use_reg(body, idx);
            dest = def_reg(body, dst, ty);
            emit_stmt(body, pool_printf("%s = %s[%s]", dest, array, index));
            break;
        }
        case DEX_INS_APUT:
        case DEX_INS_APUT_WIDE:
        case DEX_INS_APUT_OBJECT:
        case DEX_INS_APUT_BOOLEAN:
        case DEX_INS_APUT_BYTE:
        case DEX_INS_APUT_CHAR:
        case DEX_INS_APUT_SHORT: {
            int src = unit >> 8;
            int arr = code->insns[i + 1] & 0xFF;
            int idx = code->insns[i + 1] >> 8;
            emit_stmt(body, pool_printf("%s[%s] = %s", use_reg(body, arr), use_reg(body, idx), use_reg(body, src)));
            break;
        }
        case DEX_INS_NEW_ARRAY: {
            const char *desc = dex_str_of_type_id(dex, code->insns[i + 1]);
            char *arr = jimple_type(desc);
            char *elem = (desc != NULL && desc[0] == '[') ? jimple_type(desc + 1) : arr;
            char *size = use_reg(body, b);
            dest = def_reg(body, a, arr);
            emit_stmt(body, pool_printf("%s = newarray (%s)[%s]", dest, elem, size));
            break;
        }
        case DEX_INS_CMP_LONG:
        case DEX_INS_CMPG_FLOAT:
        case DEX_INS_CMPL_FLOAT:
        case DEX_INS_CMPG_DOUBLE:
        case DEX_INS_CMPL_DOUBLE: {
            int dst = unit >> 8;
            int s1 = code->insns[i + 1] & 0xFF;
            int s2 = code->insns[i + 1] >> 8;
            const char *which = op == DEX_INS_CMP_LONG ? "cmp" :
                                (op == DEX_INS_CMPG_FLOAT || op == DEX_INS_CMPG_DOUBLE) ? "cmpg" : "cmpl";
            char *left = use_reg(body, s1);
            char *right = use_reg(body, s2);
            dest = def_reg(body, dst, "int");
            emit_stmt(body, pool_printf("%s = %s %s %s", dest, left, which, right));
            break;
        }
        case DEX_INS_PACKED_SWITCH:
        case DEX_INS_SPARSE_SWITCH:
            emit_switch(body, i);
            break;
        case DEX_INS_FILL_ARRAY_DATA:
            emit_fill_array(body, i);
            break;
        case DEX_INS_INVOKE_POLYMORPHIC:
        case DEX_INS_INVOKE_POLYMORPHIC_RANGE:
        case DEX_INS_INVOKE_CUSTOM:
        case DEX_INS_INVOKE_CUSTOM_RANGE:
            emit_special_invoke(body, i);
            break;
        case DEX_INS_CONST_WIDE_16:
        case DEX_INS_CONST_WIDE_32:
        case DEX_INS_CONST_WIDE:
        case DEX_INS_CONST_WIDE_HIGH16: {
            int dst = unit >> 8;
            s8 wide = 0;
            if (op == DEX_INS_CONST_WIDE_16)
                wide = (s2)code->insns[i + 1];
            else if (op == DEX_INS_CONST_WIDE_HIGH16)
                wide = (s8)code->insns[i + 1] << 48;
            else if (op == DEX_INS_CONST_WIDE_32)
                wide = (s4)((u4)code->insns[i + 1] | ((u4)code->insns[i + 2] << 16));
            else {
                u8 lo = (u4)code->insns[i + 1] | ((u4)code->insns[i + 2] << 16);
                u8 hi = (u4)code->insns[i + 3] | ((u4)code->insns[i + 4] << 16);
                wide = (s8)(lo | (hi << 32));
            }
            emit_constant(body, dst, (u8)wide);
            break;
        }
        default:
            fprintf(stderr, "timestamp=%lld level=ERROR event=jimple_opcode_unmapped "
                            "op=%u at=%d method=%s\n",
                    (long long)time(NULL), op, i, body->signature);
            body->failed = 1;
            break;
    }
}

static void scan_labels(jimple_body *body)
{
    dex_code_item *code = body->code;
    int i;
    for (i = 0; i < (int)code->insns_size; ) {
        u2 raw = code->insns[i];
        u1 op = raw & 0xFF;
        int len = dex_opcode_len(op);
        if (raw == 0x0100 || raw == 0x0200 || raw == 0x0300)
            break;
        if (op == DEX_INS_GOTO || op == DEX_INS_GOTO_16 || op == DEX_INS_GOTO_32 ||
            (op >= DEX_INS_IF_EQ && op <= DEX_INS_IF_LEZ) ||
            op == DEX_INS_PACKED_SWITCH || op == DEX_INS_SPARSE_SWITCH ||
            op == DEX_INS_FILL_ARRAY_DATA)
            mark_label(body, branch_target(op, code, i));
        if (op == DEX_INS_PACKED_SWITCH || op == DEX_INS_SPARSE_SWITCH) {
            int target = branch_target(op, code, i);
            int size;
            int k;
            if (target >= 0 && target + 1 < (int)code->insns_size) {
                size = code->insns[target + 1];
                if (code->insns[target] == 0x0100) {
                    for (k = 0; k < size; k++)
                        mark_label(body, i + read_s4(code, target + 4 + k * 2));
                } else if (code->insns[target] == 0x0200) {
                    int tgts = target + 2 + size * 2;
                    for (k = 0; k < size; k++)
                        mark_label(body, i + read_s4(code, tgts + k * 2));
                }
            }
        }
        if (len <= 0)
            len = 1;
        i += len;
    }
    if (code->handlers != NULL) {
        int h;
        for (h = 0; h < (int)code->handlers->size; h++) {
            encoded_catch_handler *handler = &code->handlers->list[h];
            int k;
            int n = abs(handler->size);
            for (k = 0; k < n; k++)
                mark_label(body, (int)handler->handlers[k].addr);
            if (handler->size <= 0)
                mark_label(body, (int)handler->catch_all_addr);
        }
    }
    if (code->tries != NULL) {
        int t;
        for (t = 0; t < code->tries_size; t++) {
            mark_label(body, (int)code->tries[t].start_addr);
            mark_label(body, (int)(code->tries[t].start_addr + code->tries[t].insn_count));
        }
    }
}

static char *catch_label(jimple_body *body, u4 unit)
{
    return pool_printf((body->code->insns[unit] & 0xFF) == DEX_INS_MOVE_EXCEPTION
                       ? "label_%u" : "label_handler_%u", unit);
}

static void emit_ignored_handlers(jimple_body *body)
{
    dex_code_item *code = body->code;
    if (code->handlers == NULL)
        return;
    unsigned char *emitted = x_alloc(code->insns_size);
    memset(emitted, 0, code->insns_size);
    for (u4 h = 0; h < code->handlers->size; h++) {
        encoded_catch_handler *handler = &code->handlers->list[h];
        int count = abs(handler->size);
        for (int k = 0; k < count + (handler->size <= 0); k++) {
            u4 unit = k < count ? handler->handlers[k].addr : handler->catch_all_addr;
            if (emitted[unit] || (code->insns[unit] & 0xFF) == DEX_INS_MOVE_EXCEPTION)
                continue;
            emitted[unit] = 1;
            char *local = pool_printf("caught_%u", unit);
            remember_local(body, local, "java.lang.Throwable");
            add_line(body, pool_printf("%s:", catch_label(body, unit)));
            add_line(body, pool_printf("%s := @caughtexception;", local));
            add_line(body, pool_printf("goto label_%u;", unit));
        }
    }
}

static void emit_catches(jimple_body *body)
{
    dex_code_item *code = body->code;
    int t;
    if (code->tries == NULL || code->handlers == NULL)
        return;
    for (t = 0; t < code->tries_size; t++) {
        dex_try_item *item = &code->tries[t];
        int h;
        for (h = 0; h < (int)code->handlers->size; h++) {
            encoded_catch_handler *handler = &code->handlers->list[h];
            int k;
            int n;
            if (handler->handler_off != item->handler_off)
                continue;
            n = abs(handler->size);
            for (k = 0; k < n; k++) {
                char *ty = jimple_type(dex_str_of_type_id(body->dex, handler->handlers[k].type_idx));
                add_line(body, pool_printf(
                        "catch %s from label_%u to label_%u with %s;",
                        ty, item->start_addr,
                        item->start_addr + item->insn_count,
                        catch_label(body, handler->handlers[k].addr)));
                mark_label(body, (int)item->start_addr);
                mark_label(body, (int)(item->start_addr + item->insn_count));
            }
            if (handler->size <= 0) {
                add_line(body, pool_printf(
                        "catch java.lang.Throwable from label_%u to label_%u with %s;",
                        item->start_addr, item->start_addr + item->insn_count,
                        catch_label(body, handler->catch_all_addr)));
            }
        }
    }
}

static s4 read_s4(const dex_code_item *code, int unit)
{
    return (s4)((u4)code->insns[unit] | ((u4)code->insns[unit + 1] << 16));
}

static void emit_switch(jimple_body *body, int i)
{
    dex_code_item *code = body->code;
    int target = branch_target(code->insns[i] & 0xFF, code, i);
    int reg = code->insns[i] >> 8;
    u2 ident;
    int size;
    int k;
    char *text;

    if (target < 0 || target + 1 >= (int)code->insns_size)
        return;
    ident = code->insns[target];
    size = code->insns[target + 1];
    text = pool_printf("lookupswitch(%s)\n        {", use_reg(body, reg));
    if (ident == 0x0100) {
        s4 first = read_s4(code, target + 2);
        for (k = 0; k < size; k++) {
            s4 rel = read_s4(code, target + 4 + k * 2);
            int dest = i + rel;
            mark_label(body, dest);
            text = pool_printf("%s\n            case %d: goto label_%d;", text, first + k, dest);
        }
    } else if (ident == 0x0200) {
        int keys = target + 2;
        int tgts = keys + size * 2;
        for (k = 0; k < size; k++) {
            s4 key = read_s4(code, keys + k * 2);
            s4 rel = read_s4(code, tgts + k * 2);
            int dest = i + rel;
            mark_label(body, dest);
            text = pool_printf("%s\n            case %d: goto label_%d;", text, key, dest);
        }
    }
    text = pool_printf("%s\n            default: goto label_%d;\n        }", text, i + dex_opcode_len(code->insns[i] & 0xFF));
    mark_label(body, i + dex_opcode_len(code->insns[i] & 0xFF));
    emit_stmt(body, text);
}

static void emit_fill_array(jimple_body *body, int i)
{
    dex_code_item *code = body->code;
    int target = branch_target(DEX_INS_FILL_ARRAY_DATA, code, i);
    int reg = code->insns[i] >> 8;
    u2 width;
    u4 size;
    u4 k;

    if (target < 0 || target + 4 >= (int)code->insns_size)
        return;
    if (code->insns[target] != 0x0300)
        return;
    width = code->insns[target + 1];
    size = (u4)code->insns[target + 2] | ((u4)code->insns[target + 3] << 16);
    if (width != 1 && width != 2 && width != 4 && width != 8) {
        fprintf(stderr, "jimple_array_payload_width width=%u\n", width);
        body->failed = 1;
        return;
    }
    {
        int data = target + 4;
        for (k = 0; k < size; k++) {
            s8 value = 0;
            int at = data + (int)((k * width) / 2);
            int units = width / 2;
            if (units < 1)
                units = 1;
            if (at < 0 || at + units > (int)code->insns_size)
                break;
            if (width == 1)
                value = (k & 1) ? (code->insns[at] >> 8) : (code->insns[at] & 0xFF);
            else if (width == 2)
                value = (s2)code->insns[at];
            else if (width == 4)
                value = read_s4(code, at);
            else
                value = (s8)((u4)code->insns[at] | ((u8)code->insns[at + 1] << 16) |
                             ((u8)code->insns[at + 2] << 32) | ((u8)code->insns[at + 3] << 48));
            emit_stmt(body, pool_printf("%s[%u] = %s", use_reg(body, reg), k,
                                        width == 8 ? jimple_long_literal(value)
                                                   : pool_printf("%lld", (long long)value)));
        }
    }
}

static u4 encoded_index(encoded_value *value)
{
    u4 n = 0;
    size_t i;
    if (value == NULL || value->value == NULL)
        return 0;
    for (i = 0; i < value->value_length && i < 4; i++)
        n |= ((u4)value->value[i]) << (8 * i);
    return n;
}

static void emit_special_invoke(jimple_body *body, int i)
{
    jd_meta_dex *dex = body->dex;
    dex_code_item *code = body->code;
    u2 unit = code->insns[i];
    u1 op = unit & 0xFF;
    u2 ref = code->insns[i + 1];
    char *args = x_alloc(1);
    int count;
    int n;
    int regs5[5];

    args[0] = '\0';
    {
        int started = 0;
        int prev = -1;
        if (op == DEX_INS_INVOKE_CUSTOM_RANGE || op == DEX_INS_INVOKE_POLYMORPHIC_RANGE) {
            count = unit >> 8;
            for (n = 0; n < count; n++)
                args = append_reg_arg(body, args, &started, code->insns[i + 2] + n, &prev);
        } else {
            u2 regs = code->insns[i + 2];
            count = unit >> 12;
            regs5[0] = regs & 0x0F;
            regs5[1] = (regs >> 4) & 0x0F;
            regs5[2] = (regs >> 8) & 0x0F;
            regs5[3] = (regs >> 12) & 0x0F;
            regs5[4] = (unit >> 8) & 0x0F;
            for (n = 0; n < count && n < 5; n++)
                args = append_reg_arg(body, args, &started, regs5[n], &prev);
        }
    }

    if (op == DEX_INS_INVOKE_POLYMORPHIC || op == DEX_INS_INVOKE_POLYMORPHIC_RANGE) {
        char *sig = method_sig(dex, ref);
        char *ret = method_return(dex, ref);
        char *base = args;
        char *rest = strchr(args, ',');
        char *expr;
        if (rest != NULL) {
            *rest = '\0';
            rest += 2;
        } else {
            rest = "";
        }
        expr = pool_printf("virtualinvoke %s.%s(%s)", base, sig, rest);
        flush_invoke(body);
        if (strcmp(ret, "void") == 0)
            emit_stmt(body, expr);
        else {
            body->pending_type = ret;
            body->pending_invoke = expr;
        }
        return;
    }

    if (ref < dex->call_sites_size) {
        encoded_array *site = &dex->call_sites[ref];
        char *name = "callsite";
        char *boot = "<java.lang.invoke.MethodHandle: java.lang.invoke.CallSite invoke()>";
        char *proto = "<java.lang.Object ()>";
        if (site->size >= 2 && site->values[1].value_type == kDexAnnotationString)
            name = dex_str_of_idx(dex, encoded_index(&site->values[1]));
        if (site->size >= 1 && site->values[0].value_type == kDexAnnotationMethodHandle) {
            u4 handle = encoded_index(&site->values[0]);
            if (handle < dex->method_handles_size)
                boot = method_sig(dex, dex->method_handles[handle].field_or_method_idx);
        }
        if (site->size >= 3 && site->values[2].value_type == kDexAnnotationMethodType) {
            u4 proto_idx = encoded_index(&site->values[2]);
            if (proto_idx < dex->header->proto_ids_size) {
                dex_proto_id *p = &dex->proto_ids[proto_idx];
                char *ret = jimple_type(dex_str_of_type_id(dex, p->return_type_idx));
                char *params = x_alloc(1);
                int pi;
                params[0] = '\0';
                if (p->type_list != NULL) {
                    for (pi = 0; pi < (int)p->type_list->size; pi++) {
                        params = pool_printf("%s%s%s", params, pi == 0 ? "" : ",",
                                              jimple_type(dex_str_of_type_id(dex, p->type_list->list[pi].type_idx)));
                    }
                }
                proto = pool_printf("<%s (%s)>", ret, params);
                body->pending_type = ret;
            }
        }
        flush_invoke(body);
        body->pending_invoke = pool_printf("dynamicinvoke \"%s\" %s(%s) %s()", name, proto, args, boot);
        if (body->pending_type == NULL)
            body->pending_type = "java.lang.Object";
        return;
    }
    fprintf(stderr, "jimple_call_site_missing index=%u\n", ref);
    body->failed = 1;
}

static int line_is_label(const char *line)
{
    return strncmp(line, "label_", 6) == 0;
}

static const char *label_target_stmt(jimple_body *body, const char *label)
{
    int i;
    for (i = 0; i < body->nlines; i++) {
        if (strcmp(body->lines[i], label) != 0)
            continue;
        while (i + 1 < body->nlines && line_is_label(body->lines[i + 1]))
            i++;
        if (i + 1 < body->nlines)
            return body->lines[i + 1];
    }
    return NULL;
}

static void apply_cleanup(jimple_body *body)
{
    int i;
    int changed = 1;
    while (changed) {
        changed = 0;
        for (i = 0; i < body->nlines; i++) {
            char *line = body->lines[i];
            char *goto_at = strstr(line, "goto label_");
            const char *target;
            if (goto_at == NULL)
                continue;
            target = label_target_stmt(body, goto_at + 5);
            if (target == NULL)
                continue;
            if (strncmp(target, "goto label_", 11) == 0) {
                body->lines[i] = pool_printf("%.*s%s", (int)(goto_at - line), line, target);
                changed = 1;
            } else if (strncmp(line, "goto label_", 11) == 0 && strncmp(target, "return", 6) == 0) {
                body->lines[i] = pool_printf("%s", target);
                changed = 1;
            }
        }
    }
    for (i = 0; i < body->nlocals; i++) {
        int j;
        if (!is_ref_type(body->local_types[i]))
            continue;
        for (j = 0; j < body->nlines; j++) {
            char *expect = pool_printf("%s = 0;", body->locals[i]);
            if (strcmp(body->lines[j], expect) == 0)
                body->lines[j] = pool_printf("%s = null;", body->locals[i]);
        }
    }
}

static void write_annotation_set_comment(FILE *stream, jd_meta_dex *dex,
                                         annotation_set_item *set, const char *indent)
{
    u4 i;
    if (set == NULL || set->entries == NULL)
        return;
    for (i = 0; i < set->size; i++) {
        annotation_item *item = set->entries[i].annotation_item;
        encoded_annotation *annotation;
        u4 j;
        if (item == NULL || item->encoded_annotation == NULL)
            continue;
        annotation = item->encoded_annotation;
        fprintf(stream, "%s/* @%s", indent,
                jimple_type(dex_str_of_type_id(dex, (u2)annotation->type_idx)));
        if (annotation->size > 0)
            fputc('(', stream);
        for (j = 0; annotation->elements != NULL && j < annotation->size; j++) {
            char *buf = NULL;
            size_t len = 0;
            FILE *mem = open_memstream(&buf, &len);
            if (j != 0)
                fputs(", ", stream);
            fputs(dex_str_of_idx(dex, annotation->elements[j].name_idx), stream);
            fputs(" = ", stream);
            if (mem != NULL) {
                smali_write_encoded_value(mem, dex, annotation->elements[j].value);
                fclose(mem);
                if (buf != NULL) {
                    fputs(buf, stream);
                    free(buf);
                }
            }
        }
        if (annotation->size > 0)
            fputc(')', stream);
        fputs(" */\n", stream);
    }
}

static int emit_method(jd_meta_dex *dex, dex_class_def *cf, encoded_method *method, FILE *stream)
{
    dex_code_item *code = method->code;
    dex_method_id *id = &dex->method_ids[method->method_id];
    dex_proto_id *proto = &dex->proto_ids[id->proto_idx];
    char *ret = jimple_type(dex_str_of_type_id(dex, proto->return_type_idx));
    char *name = dex_str_of_method_id(dex, method->method_id);
    char *cls = jimple_type(dex_str_of_type_id(dex, cf->class_idx));
    int instance = (method->access_flags & ACC_DEX_STATIC) == 0;
    int param_count = proto->type_list == NULL ? 0 : (int)proto->type_list->size;
    int i;
    jimple_body body;
    char *args = x_alloc(1);

    args[0] = '\0';
    if (cf->annotations != NULL) {
        u4 ai;
        for (ai = 0; ai < cf->annotations->methods_size; ai++) {
            if (cf->annotations->method_annotations[ai].method_idx == method->method_id)
                write_annotation_set_comment(stream, dex,
                                             cf->annotations->method_annotations[ai].annotation,
                                             "    ");
        }
    }
    fprintf(stream, "\n    ");
    if (method->access_flags & ACC_DEX_PUBLIC)
        fputs("public ", stream);
    if (method->access_flags & ACC_DEX_PRIVATE)
        fputs("private ", stream);
    if (method->access_flags & ACC_DEX_PROTECTED)
        fputs("protected ", stream);
    if (method->access_flags & ACC_DEX_STATIC)
        fputs("static ", stream);
    if (method->access_flags & ACC_DEX_FINAL)
        fputs("final ", stream);
    if (method->access_flags & ACC_DEX_NATIVE)
        fputs("native ", stream);
    if (method->access_flags & ACC_DEX_ABSTRACT)
        fputs("abstract ", stream);
    if (method->access_flags & (ACC_DEX_SYNCHRONIZED | ACC_DEX_DECLARED_SYNCHRONIZED))
        fputs("synchronized ", stream);
    fprintf(stream, "%s %s(", ret, name);
    for (i = 0; i < param_count; i++) {
        if (i != 0)
            fputc(',', stream);
        fputs(jimple_type(dex_str_of_type_id(dex, proto->type_list->list[i].type_idx)), stream);
    }
    fputs(")", stream);
    if (code == NULL || (method->access_flags & (ACC_DEX_NATIVE | ACC_DEX_ABSTRACT)) != 0) {
        fputs(";\n", stream);
        return 0;
    }
    fputs("\n    {\n", stream);

    memset(&body, 0, sizeof(body));
    body.dex = dex;
    body.code = code;
    body.analysis = dex_analyze_method(dex, method);
    if (body.analysis->failed)
        return 2;
    body.unit = -1;
    body.failed = body.analysis->failed;
    body.signature = method_sig(dex, method->method_id);
    body.stream = stream;
    body.nregs = code->registers_size;
    body.regs = make_obj_arr(jimple_reg, body.nregs);
    memset(body.regs, 0, sizeof(jimple_reg) * (size_t)body.nregs);
    body.labels = x_alloc(code->insns_size);
    memset(body.labels, 0, code->insns_size);
    scan_labels(&body);

    {
        int reg = code->registers_size - code->ins_size;
        int p;
        if (instance) {
            char *local = def_reg(&body, reg, cls);
            add_line(&body, pool_printf("%s := @this: %s;", local, cls));
            reg++;
        }
        for (p = 0; p < param_count; p++) {
            char *ty = jimple_type(dex_str_of_type_id(dex, proto->type_list->list[p].type_idx));
            char *local = def_reg(&body, reg, ty);
            add_line(&body, pool_printf("%s := @parameter%d: %s;", local, p, ty));
            reg += (strcmp(ty, "long") == 0 || strcmp(ty, "double") == 0) ? 2 : 1;
        }
    }

    for (i = 0; i < (int)code->insns_size; ) {
        u2 raw = code->insns[i];
        u1 op = raw & 0xFF;
        int len = dex_opcode_len(op);
        if (raw == 0x0100 || raw == 0x0200 || raw == 0x0300)
            break;
        int index = body.analysis->offsets[i];
        if (body.analysis->ssa->reachable[index]) {
            load_inputs(&body, i);
            emit_one(&body, i);
        } else if (body.labels[i]) {
            add_line(&body, pool_printf("label_%d:", i));
            add_line(&body, pool_printf("goto label_%d;", i));
        }
        if (len <= 0)
            len = 1;
        i += len;
    }
    flush_invoke(&body);
    {
        int label_at;
        for (label_at = i; label_at < (int)code->insns_size; label_at++) {
            if (body.labels[label_at]) {
                add_line(&body, pool_printf("label_%d:", label_at));
                add_line(&body, pool_printf("goto label_%d;", label_at));
            }
        }
    }
    if (body.end_label) {
        add_line(&body, pool_printf("label_%u:", code->insns_size));
        add_line(&body, pool_printf("goto label_%u;", code->insns_size));
    }
    emit_ignored_handlers(&body);
    emit_catches(&body);
    apply_cleanup(&body);
    {
        int li;
        int lj;
        for (li = 0; li < body.nlocals; li++) {
            int earlier = 0;
            int printed = 0;
            for (lj = 0; lj < li; lj++) {
                if (strcmp(body.local_types[lj], body.local_types[li]) == 0)
                    earlier = 1;
            }
            if (earlier)
                continue;
            fprintf(stream, "        %s ", body.local_types[li]);
            for (lj = li; lj < body.nlocals; lj++) {
                if (strcmp(body.local_types[lj], body.local_types[li]) != 0)
                    continue;
                fprintf(stream, "%s%s", printed ? ", " : "", body.locals[lj]);
                printed = 1;
            }
            fputs(";\n", stream);
        }
        fputc('\n', stream);
        for (li = 0; li < body.nlines; li++)
            fprintf(stream, "        %s\n", body.lines[li]);
    }
    fputs("    }\n", stream);
    free(body.locals);
    free(body.local_types);
    free(body.lines);
    return body.failed ? 2 : 0;
}

int dex_class_def_to_jimple(jd_meta_dex *dex, dex_class_def *cf, FILE *stream)
{
    char *cls = jimple_type(dex_str_of_type_id(dex, cf->class_idx));
    char *super_name = NULL;
    string super_desc = dex_str_of_superclass(dex, cf);
    dex_class_data_item *data = cf->class_data;
    int i;

    if (super_desc != NULL && super_desc[0] != '\0')
        super_name = jimple_type(super_desc);
    fputs("public ", stream);
    if (cf->access_flags & ACC_DEX_INTERFACE)
        fprintf(stream, "interface %s", cls);
    else
        fprintf(stream, "class %s", cls);
    if (super_name != NULL)
        fprintf(stream, " extends %s", super_name);
    fputs("\n{\n", stream);
    if (cf->annotations != NULL)
        write_annotation_set_comment(stream, dex, cf->annotations->class_annotation, "    ");
    if (data != NULL) {
        for (i = 0; i < (int)data->static_fields_size; i++) {
            encoded_field *field = &data->static_fields[i];
            if (cf->annotations != NULL) {
                u4 ai;
                for (ai = 0; ai < cf->annotations->fields_size; ai++) {
                    if (cf->annotations->field_annotations[ai].field_idx == field->field_id)
                        write_annotation_set_comment(stream, dex,
                                                     cf->annotations->field_annotations[ai].annotation,
                                                     "    ");
                }
            }
            fprintf(stream, "    static %s %s;\n",
                    jimple_type(dex_field_desc(dex, field)),
                    dex_field_name(dex, field));
        }
        for (i = 0; i < (int)data->instance_fields_size; i++) {
            encoded_field *field = &data->instance_fields[i];
            if (cf->annotations != NULL) {
                u4 ai;
                for (ai = 0; ai < cf->annotations->fields_size; ai++) {
                    if (cf->annotations->field_annotations[ai].field_idx == field->field_id)
                        write_annotation_set_comment(stream, dex,
                                                     cf->annotations->field_annotations[ai].annotation,
                                                     "    ");
                }
            }
            fprintf(stream, "    %s %s;\n",
                    jimple_type(dex_field_desc(dex, field)),
                    dex_field_name(dex, field));
        }
        for (i = 0; i < (int)data->direct_methods_size; i++) {
            if (emit_method(dex, cf, &data->direct_methods[i], stream) != 0)
                return 2;
        }
        for (i = 0; i < (int)data->virtual_methods_size; i++) {
            if (emit_method(dex, cf, &data->virtual_methods[i], stream) != 0)
                return 2;
        }
    }
    fputs("}\n", stream);
    return 0;
}

int dex_jimple_write_class_from_path(const char *path,
                                     const char *class_name,
                                     FILE *stream)
{
    return dex_write_class_from_path(path, class_name, stream, dex_class_def_to_jimple);
}
