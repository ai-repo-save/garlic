#include "parser/dex/metadata.h"

#include <limits.h>
#include <time.h>

int dex_instruction_width(const dex_code_item *code, u4 unit)
{
    u4 remaining = code->insns_size - unit;
    u2 raw = code->insns[unit];
    u8 width;
    if (raw == 0x0100) {
        if (remaining < 4)
            return 0;
        width = 4 + (u8)code->insns[unit + 1] * 2;
    } else if (raw == 0x0200) {
        if (remaining < 2)
            return 0;
        width = 2 + (u8)code->insns[unit + 1] * 4;
    } else if (raw == 0x0300) {
        if (remaining < 4)
            return 0;
        u4 count = (u4)code->insns[unit + 2] | ((u4)code->insns[unit + 3] << 16);
        width = 4 + ((u8)count * code->insns[unit + 1] + 1) / 2;
    } else {
        width = dex_opcode_len(raw & 0xFF);
    }
    return width == 0 || width > remaining || width > INT_MAX ? 0 : (int)width;
}

int dex_validate_instructions(const dex_code_item *code, u4 method_id)
{
    for (u4 unit = 0; unit < code->insns_size;) {
        int width = dex_instruction_width(code, unit);
        if (width == 0) {
            fprintf(stderr, "timestamp=%lld level=ERROR event=dex_instruction_invalid "
                            "op=%u at=%u method_id=%u\n",
                    (long long)time(NULL), code->insns[unit] & 0xFF, unit, method_id);
            return 2;
        }
        unit += (u4)width;
    }
    return 0;
}
