#ifndef GARLIC_SSA_REGISTERS_H
#define GARLIC_SSA_REGISTERS_H

#include "decompiler/structure.h"

typedef struct {
    jd_ins *instruction;
    bitset_t *clobbers;
    list_object *handlers;
} jd_register_flow;

typedef struct {
    int instruction;
    int reg;
    int parent;
} jd_register_definition;

typedef struct {
    int instruction_count;
    int register_count;
    int definition_count;
    jd_register_definition *definitions;
    int **outputs;
    int *parameters;
    bitset_t **inputs;
    unsigned char *reachable;
} jd_register_ssa;

/* Exceptional successors observe the state before an instruction completes. */
jd_register_ssa *sform_register_analyze(jd_register_flow *flow, int count,
                                        int registers, int first_parameter);
int sform_register_root(jd_register_ssa *ssa, int definition);
void sform_register_join(jd_register_ssa *ssa, int left, int right);
int sform_register_input(jd_register_ssa *ssa, int instruction, int reg);

#endif
