#ifndef GARLIC_DEX_SMALI_H
#define GARLIC_DEX_SMALI_H
#include <stdio.h>
#include "dex_structure.h"

void dex_to_smali(string path);

void dex_class_def_to_smali(jd_meta_dex *dex, dex_class_def *cf, FILE *stream);

/* Write one class as smali. class_name accepts ms.bd.o.h2 or Lms/bd/o/h2;.
 * Returns 0 if written, 1 if the class is missing, 2 on I/O or parse error. */
int dex_smali_write_class_from_path(const char *path,
                                    const char *class_name,
                                    FILE *stream);

#endif //GARLIC_DEX_SMALI_H
