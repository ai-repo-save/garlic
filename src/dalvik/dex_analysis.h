#ifndef GARLIC_DEX_ANALYSIS_H
#define GARLIC_DEX_ANALYSIS_H

#include "dalvik/dex_structure.h"
#include "decompiler/ssa_registers.h"

enum {
    DEX_VALUE_INT = 1,
    DEX_VALUE_FLOAT = 2,
    DEX_VALUE_LONG = 4,
    DEX_VALUE_DOUBLE = 8,
    DEX_VALUE_REFERENCE = 16
};

typedef struct {
    unsigned kinds;
    const char *reference;
    const char *array;
} dex_value_type;

typedef struct {
    jd_meta_dex *dex;
    encoded_method *encoded;
    jd_method *method;
    jd_register_ssa *ssa;
    dex_value_type *types;
    unsigned **uses;
    int *offsets;
    int failed;
} dex_analysis;

dex_analysis *dex_analyze_method(jd_meta_dex *dex, encoded_method *method);
int dex_analysis_input(dex_analysis *analysis, int unit, int reg);
int dex_analysis_output(dex_analysis *analysis, int unit, int reg);
unsigned dex_analysis_use_kind(dex_analysis *analysis, int unit, int reg);
unsigned dex_analysis_kind(const char *descriptor);
void dex_analysis_types(dex_analysis *analysis);

#endif
