#ifndef GARLIC_METADATA_H
#define GARLIC_METADATA_H

#include "dex.h"

jd_meta_dex* parse_dex_file(string path);

jd_meta_dex* parse_dex_from_buffer(char *buffer, size_t size);

string dex_opcode_name(u1 code);

int dex_opcode_len(u1 code);

int dex_opcode_result_width(u1 code);

int dex_instruction_width(const dex_code_item *code, u4 unit);

int dex_validate_instructions(const dex_code_item *code, u4 method_id);

int read_unsigned_leb128(jd_meta_dex *dex);

int read_signed_leb128(jd_meta_dex *dex);

dex_instruction_format dex_opcode_fmt(u1 code);

#endif //GARLIC_METADATA_H
