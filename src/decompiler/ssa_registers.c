#include "decompiler/ssa_registers.h"

int sform_register_root(jd_register_ssa *ssa, int definition)
{
    if (definition < 0)
        return -1;
    int root = definition;
    while (ssa->definitions[root].parent != root)
        root = ssa->definitions[root].parent;
    while (definition != root) {
        int next = ssa->definitions[definition].parent;
        ssa->definitions[definition].parent = root;
        definition = next;
    }
    return root;
}

void sform_register_join(jd_register_ssa *ssa, int left, int right)
{
    left = sform_register_root(ssa, left);
    right = sform_register_root(ssa, right);
    if (left < 0 || right < 0 || left == right)
        return;
    if (left > right) {
        int swap = left;
        left = right;
        right = swap;
    }
    ssa->definitions[right].parent = left;
}

int sform_register_input(jd_register_ssa *ssa, int instruction, int reg)
{
    bitset_t *input = ssa->inputs[instruction];
    for (size_t d = 0; bitset_next_set_bit(input, &d); d++) {
        if (ssa->definitions[d].reg == reg)
            return sform_register_root(ssa, (int)d);
    }
    return -1;
}

static int add_definition(jd_register_ssa *ssa, int instruction, int reg)
{
    int id = ssa->definition_count++;
    ssa->definitions[id] = (jd_register_definition){instruction, reg, id};
    return id;
}

static bool propagate(jd_register_ssa *ssa, int target, bitset_t *state)
{
    bool changed = !ssa->reachable[target];
    ssa->reachable[target] = 1;
    bitset_t *input = ssa->inputs[target];
    for (size_t word = 0; word < state->arraysize; word++) {
        uint64_t previous = input->array[word];
        input->array[word] |= state->array[word];
        changed |= previous != input->array[word];
    }
    return changed;
}

jd_register_ssa *sform_register_analyze(jd_register_flow *flow, int count,
                                        int registers, int first_parameter)
{
    jd_register_ssa *ssa = make_obj_zero(jd_register_ssa);
    ssa->instruction_count = count;
    ssa->register_count = registers;
    int capacity = registers;
    for (int i = 0; i < count; i++)
        capacity += (int)bitset_count(flow[i].instruction->defs);
    ssa->definitions = make_obj_arr(jd_register_definition, capacity);
    ssa->parameters = make_obj_arr(int, registers);
    ssa->outputs = make_obj_arr(int *, count);
    ssa->inputs = make_obj_arr(bitset_t *, count);
    ssa->reachable = make_obj_arr(unsigned char, count);
    memset(ssa->reachable, 0, (size_t)count);
    for (int r = 0; r < registers; r++)
        ssa->parameters[r] = r >= first_parameter ? add_definition(ssa, -1, r) : -1;
    for (int i = 0; i < count; i++) {
        ssa->outputs[i] = make_obj_arr(int, registers);
        for (int r = 0; r < registers; r++)
            ssa->outputs[i][r] = -1;
        jd_ins *ins = flow[i].instruction;
        for (size_t r = 0; bitset_next_set_bit(ins->defs, &r); r++)
            ssa->outputs[i][r] = add_definition(ssa, i, (int)r);
        ssa->inputs[i] = bitset_create_with_capacity((size_t)capacity);
    }
    if (count == 0)
        return ssa;
    for (int r = first_parameter; r < registers; r++)
        bitset_set(ssa->inputs[0], ssa->parameters[r]);
    ssa->reachable[0] = 1;
    bitset_t *output = bitset_create_with_capacity((size_t)capacity);
    bool changed;
    do {
        changed = false;
        for (int i = 0; i < count; i++) {
            if (!ssa->reachable[i])
                continue;
            jd_ins *ins = flow[i].instruction;
            bitset_clear(output);
            bitset_inplace_union(output, ssa->inputs[i]);
            for (size_t d = 0; bitset_next_set_bit(output, &d); d++) {
                if (bitset_get(ins->defs, ssa->definitions[d].reg))
                    bitset_set_to_value(output, d, false);
            }
            for (size_t r = 0; bitset_next_set_bit(ins->defs, &r); r++)
                bitset_set(output, ssa->outputs[i][r]);
            for (int t = 0; t < ins->targets->size; t++) {
                jd_ins *target = lget_obj(ins->targets, t);
                changed |= propagate(ssa, target->idx, output);
            }
            for (int t = 0; t < flow[i].handlers->size; t++) {
                jd_ins *handler = lget_obj(flow[i].handlers, t);
                changed |= propagate(ssa, handler->idx, ssa->inputs[i]);
            }
        }
    } while (changed);
    for (int i = 0; i < count; i++) {
        if (!ssa->reachable[i])
            continue;
        jd_ins *ins = flow[i].instruction;
        for (size_t r = 0; bitset_next_set_bit(ins->uses, &r); r++) {
            int first = -1;
            for (size_t d = 0; bitset_next_set_bit(ssa->inputs[i], &d); d++) {
                if (ssa->definitions[d].reg != r)
                    continue;
                if (first < 0)
                    first = (int)d;
                else
                    sform_register_join(ssa, first, (int)d);
            }
        }
    }
    return ssa;
}
