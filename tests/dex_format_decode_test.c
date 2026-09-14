/* Operand layout checks against google/smali dexlib2 DexBackedInstruction*. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "dalvik/dex_opcode_fields.h"

static void fail(const char *msg)
{
    fprintf(stderr, "FAIL %s\n", msg);
    exit(1);
}

int main(void)
{
    /* DexBackedInstruction23x: bytes [op, A, B, C] */
    {
        u2 u0 = 0x4f | (12u << 8);
        u2 u1 = 4u | (25u << 8);
        if (dex_field_aa(u0) != 12)
            fail("23x A");
        if (dex_field_23x_bb(u1) != 4)
            fail("23x B");
        if (dex_field_23x_cc(u1) != 25)
            fail("23x C");
    }

    /* DexBackedInstruction22c/12x/22t: byte1 low nibble A, high nibble B */
    {
        u2 u0 = 0x21 | (1u << 8) | (2u << 12); /* instance-of */
        if (dex_field_a_nibble(u0) != 1)
            fail("22c A");
        if (dex_field_b_nibble(u0) != 2)
            fail("22c B");
    }

    /* DexBackedInstruction11n: low nibble A, high signed nibble literal */
    {
        u2 u0 = 0x12 | (3u << 8) | (0xfu << 12); /* const/4 v3, #-1 */
        if (dex_field_a_nibble(u0) != 3)
            fail("11n A");
        if (dex_field_high_signed_nibble(u0) != (s1)-1)
            fail("11n N");
    }

    /* DexBackedInstruction22b: [op, A, B, literal] */
    {
        u1 lit = (u1)(s1)-5;
        u2 u1 = (u2)(7u | ((u2)lit << 8));
        if ((u1 & 0xFF) != 7)
            fail("22b B");
        if ((s1)(u1 >> 8) != (s1)-5)
            fail("22b literal");
    }

    printf("ok\n");
    return 0;
}
