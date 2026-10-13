#ifndef GARLIC_OUTPUT_ERROR_H
#define GARLIC_OUTPUT_ERROR_H

#include <stdio.h>

#include "common/types.h"

void output_close(FILE *stream, string path);

void output_open_failed(string path);

bool output_had_errors(void);

bool output_report(void);

/* 输入结构非法而被拒绝：与写入失败分开报告，使退出码非零且原因明确。 */
void output_input_rejected(string path, const char *reason);

#endif //GARLIC_OUTPUT_ERROR_H
