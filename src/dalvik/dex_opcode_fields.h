#ifndef GARLIC_DEX_OPCODE_FIELDS_H
#define GARLIC_DEX_OPCODE_FIELDS_H

#include "dalvik/dex_structure.h"

/* First code unit is little-endian: low byte opcode, high byte AA or B|A. */
static inline u1 dex_field_aa(u2 u0)
{
    return (u1)(u0 >> 8);
}

static inline u1 dex_field_a_nibble(u2 u0)
{
    return (u1)((u0 >> 8) & 0x0F);
}

static inline u1 dex_field_b_nibble(u2 u0)
{
    return (u1)(u0 >> 12);
}

/* 23x second unit is CC|BB: low byte vBB, high byte vCC. */
static inline u1 dex_field_23x_bb(u2 unit)
{
    return (u1)(unit & 0xFF);
}

static inline u1 dex_field_23x_cc(u2 unit)
{
    return (u1)(unit >> 8);
}

#endif
