#ifndef GARLIC_DEX_JIMPLE_LITERALS_H
#define GARLIC_DEX_JIMPLE_LITERALS_H

#include "common/types.h"

typedef struct {
    char *text;
    bool immediate;
} dex_jimple_literal;

/* Inputs are parser-owned, NUL-terminated DEX MUTF-8, not standard UTF-8.
 * Returned text belongs to the current scratch pool. */
char *dex_jimple_string(const char *mutf8);

dex_jimple_literal dex_jimple_long_literal(s8 value);

/* width is 32 or 64; bits contains the unmodified IEEE 754 representation.
 * A non-immediate RHS must be assigned to a local before immediate-only use. */
dex_jimple_literal dex_jimple_floating_literal(u8 bits, unsigned width);

#endif
