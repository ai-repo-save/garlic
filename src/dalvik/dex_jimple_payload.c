#include "dalvik/dex_jimple_body.h"
#include "dalvik/dex_jimple_literals.h"
#include "dalvik/dex_ins_helper.h"
#include "parser/dex/metadata.h"
#include "common/str_tools.h"

#include <limits.h>
#include <time.h>

static s4 signed_word(const dex_code_item *code, int unit)
{
    return (s4)((u4)code->insns[unit] | ((u4)code->insns[unit + 1] << 16));
}

static void payload_failure(jimple_body *body, int unit, const char *reason)
{
    fprintf(stderr, "timestamp=%lld level=ERROR event=jimple_payload_invalid "
                    "reason=%s at=%d method=%s\n",
            (long long)time(NULL), reason, unit, body->signature);
    body->failed = 1;
}

static int payload_target(jimple_body *body, int unit, u2 identifier)
{
    s8 target = (s8)unit + signed_word(body->code, unit + 1);
    if (target < 0 || target >= body->code->insns_size ||
        body->code->insns[target] != identifier ||
        dex_instruction_width(body->code, (u4)target) == 0) {
        payload_failure(body, unit, "invalid_payload_target");
        return -1;
    }
    return (int)target;
}

void dex_jimple_emit_switch(jimple_body *body, int unit)
{
    dex_code_item *code = body->code;
    bool packed = (code->insns[unit] & 0xFF) == DEX_INS_PACKED_SWITCH;
    int target = payload_target(body, unit, packed ? 0x0100 : 0x0200);
    if (target < 0)
        return;
    int size = code->insns[target + 1];
    int fallback = unit + dex_instruction_width(code, (u4)unit);
    dex_jimple_mark_label(body, fallback);
    if (size == 0) {
        dex_jimple_emit_stmt(body, str_create("goto label_%d", fallback));
        return;
    }
    char *text = str_create("lookupswitch(%s)\n        {",
                           dex_jimple_use_reg(body, code->insns[unit] >> 8));
    int targets = packed ? target + 4 : target + 2 + size * 2;
    for (int n = 0; n < size; n++) {
        s8 destination = (s8)unit + signed_word(code, targets + n * 2);
        if (destination < 0 || destination >= code->insns_size) {
            payload_failure(body, unit, "invalid_switch_destination");
            return;
        }
        s4 key = packed ? (s4)((u4)signed_word(code, target + 2) + (u4)n)
                        : signed_word(code, target + 2 + n * 2);
        dex_jimple_mark_label(body, (int)destination);
        text = str_create("%s\n            case %d: goto label_%d;", text, key, (int)destination);
    }
    text = str_create("%s\n            default: goto label_%d;\n        }", text, fallback);
    dex_jimple_emit_stmt(body, text);
}

static char *array_literal(jimple_body *body, int unit, u4 index, u8 bits,
                           const char *element)
{
    dex_jimple_literal literal;
    switch (element[0]) {
        case 'F': literal = dex_jimple_floating_literal(bits, 32); break;
        case 'D': literal = dex_jimple_floating_literal(bits, 64); break;
        case 'J': literal = dex_jimple_long_literal((s8)bits); break;
        case 'B': literal = (dex_jimple_literal){str_create("%d", (s1)bits), true}; break;
        case 'S': literal = (dex_jimple_literal){str_create("%d", (s2)bits), true}; break;
        case 'C': literal = (dex_jimple_literal){str_create("%u", (u2)bits), true}; break;
        default: literal = (dex_jimple_literal){str_create("%d", (s4)bits), true}; break;
    }
    if (literal.immediate)
        return literal.text;
    char *local = str_create("payload_value_%d_%u", unit, index);
    dex_jimple_remember_local(body, local, dex_jimple_type(element));
    dex_jimple_emit_stmt(body, str_create("%s = %s", local, literal.text));
    return local;
}

static bool array_bounds(jimple_body *body, int unit, int reg, u4 count)
{
    char *length = str_create("payload_length_%d", unit);
    dex_jimple_remember_local(body, length, "int");
    dex_jimple_emit_stmt(body, str_create("%s = lengthof %s", length, dex_jimple_use_reg(body, reg)));
    if (count <= INT_MAX)
        dex_jimple_emit_stmt(body, str_create("if %s >= %u goto label_payload_%d", length, count, unit));
    char *exception = str_create("payload_exception_%d", unit);
    dex_jimple_remember_local(body, exception, "java.lang.ArrayIndexOutOfBoundsException");
    dex_jimple_emit_stmt(body, str_create("%s = new java.lang.ArrayIndexOutOfBoundsException", exception));
    dex_jimple_emit_stmt(body, str_create("specialinvoke %s.<java.lang.ArrayIndexOutOfBoundsException: void <init>()>()", exception));
    dex_jimple_emit_stmt(body, str_create("throw %s", exception));
    if (count > INT_MAX)
        return false;
    dex_jimple_emit_label(body, str_create("label_payload_%d", unit));
    dex_jimple_emit_stmt(body, "nop");
    return true;
}

void dex_jimple_emit_fill_array(jimple_body *body, int unit)
{
    dex_code_item *code = body->code;
    int target = payload_target(body, unit, 0x0300);
    if (target < 0)
        return;
    u2 width = code->insns[target + 1];
    if (width != 1 && width != 2 && width != 4 && width != 8) {
        payload_failure(body, unit, "invalid_array_element_width");
        return;
    }
    u4 count = (u4)code->insns[target + 2] | ((u4)code->insns[target + 3] << 16);
    int reg = code->insns[unit] >> 8;
    int value = dex_analysis_input(body->analysis, unit, reg);
    const char *array = value < 0 ? NULL : body->analysis->types[value].array;
    if (array == NULL) {
        payload_failure(body, unit, "missing_array_type");
        return;
    }
    const char *element = array + 1;
    int expected = element[0] == 'B' || element[0] == 'Z' ? 1 :
                   element[0] == 'S' || element[0] == 'C' ? 2 :
                   element[0] == 'I' || element[0] == 'F' ? 4 :
                   element[0] == 'J' || element[0] == 'D' ? 8 : 0;
    if (expected != width) {
        payload_failure(body, unit, "array_width_type_mismatch");
        return;
    }
    if (!array_bounds(body, unit, reg, count))
        return;
    int data = target + 4;
    for (u4 n = 0; n < count; n++) {
        u8 bits = 0;
        u8 byte = (u8)n * width;
        for (u2 b = 0; b < width; b++) {
            u8 at = byte + b;
            u2 word = code->insns[data + at / 2];
            bits |= (u8)((word >> ((at & 1) * 8)) & 0xFF) << (b * 8);
        }
        char *literal = array_literal(body, unit, n, bits, element);
        dex_jimple_emit_stmt(body, str_create("%s[%u] = %s", dex_jimple_use_reg(body, reg), n, literal));
    }
}
