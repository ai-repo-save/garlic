#include "dalvik/dex_jimple_literals.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "common/str_tools.h"
#include "libs/memory/mem_pool.h"

char *dex_jimple_string(const char *mutf8)
{
    const unsigned char *p = (const unsigned char *)mutf8;
    char *out = x_alloc(strlen(mutf8) * 6 + 3);
    char *w = out;

    *w++ = '"';
    while (*p != '\0') {
        unsigned unit;
        if (*p < 0x80) {
            unit = *p++;
        } else if (*p < 0xe0) {
            unit = ((unsigned)(p[0] & 0x1f) << 6) | (p[1] & 0x3f);
            p += 2;
        } else {
            unit = ((unsigned)(p[0] & 0x0f) << 12) |
                   ((unsigned)(p[1] & 0x3f) << 6) | (p[2] & 0x3f);
            p += 3;
        }

        if (unit == '\\' || unit == '"') {
            *w++ = '\\';
            *w++ = (char)unit;
        } else if (unit >= 0x20 && unit <= 0x7e) {
            *w++ = (char)unit;
        } else {
            w += sprintf(w, "\\u%04x", unit);
        }
    }
    *w++ = '"';
    *w = '\0';
    return out;
}

dex_jimple_literal dex_jimple_long_literal(s8 value)
{
    /* Soot's Walker.outAIntegerConstant includes the sign in Long.parseLong. */
    return (dex_jimple_literal){str_create("%" PRId64 "L", value), true};
}

static dex_jimple_literal nan_literal(u8 bits, unsigned width)
{
    if (width == 32) {
        u4 word = (u4)bits;
        s4 value;
        if (word == UINT32_C(0x7fc00000))
            return (dex_jimple_literal){str_create("#NaNF"), true};
        memcpy(&value, &word, sizeof(value));
        return (dex_jimple_literal){
            str_create("staticinvoke <java.lang.Float: float intBitsToFloat(int)>(%" PRId32 ")", value),
            false
        };
    }

    if (bits == UINT64_C(0x7ff8000000000000))
        return (dex_jimple_literal){str_create("#NaN"), true};
    s8 value;
    memcpy(&value, &bits, sizeof(value));
    dex_jimple_literal raw = dex_jimple_long_literal(value);
    return (dex_jimple_literal){
        str_create("staticinvoke <java.lang.Double: double longBitsToDouble(long)>(%s)", raw.text),
        false
    };
}

static char *finite_literal(double value, unsigned width)
{
    char *decimal = str_create(width == 32 ? "%.9g" : "%.17g", value);
    const char *suffix = width == 32 ? "F" : "";
    if (strchr(decimal, '.') != NULL)
        return str_create("%s%s", decimal, suffix);

    /* jimple.scc requires digits on both sides of the point, even with an exponent. */
    char *exponent = strpbrk(decimal, "eE");
    if (exponent != NULL)
        return str_create("%.*s.0%s%s", (int)(exponent - decimal), decimal, exponent, suffix);
    return str_create("%s.0%s", decimal, suffix);
}

dex_jimple_literal dex_jimple_floating_literal(u8 bits, unsigned width)
{
    assert(width == 32 || width == 64);

    double value;
    bool negative;
    bool infinite;
    if (width == 32) {
        u4 word = (u4)bits;
        u4 magnitude = word & UINT32_C(0x7fffffff);
        if (magnitude > UINT32_C(0x7f800000))
            return nan_literal(bits, width);
        negative = (word >> 31) != 0;
        infinite = magnitude == UINT32_C(0x7f800000);
        float number;
        memcpy(&number, &word, sizeof(number));
        value = number;
    } else {
        u8 magnitude = bits & UINT64_C(0x7fffffffffffffff);
        if (magnitude > UINT64_C(0x7ff0000000000000))
            return nan_literal(bits, width);
        negative = (bits >> 63) != 0;
        infinite = magnitude == UINT64_C(0x7ff0000000000000);
        memcpy(&value, &bits, sizeof(value));
    }

    if (infinite)
        return (dex_jimple_literal){
            str_create("#%sInfinity%s", negative ? "-" : "", width == 32 ? "F" : ""),
            true
        };
    return (dex_jimple_literal){finite_literal(value, width), true};
}
