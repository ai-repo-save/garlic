#ifndef GARLIC_DEX_JIMPLE_H
#define GARLIC_DEX_JIMPLE_H

#include <stdio.h>
#include "parser/dex/dex.h"

/* Write one class as Jimple. class_name accepts cmp.Sample or Lcmp/Sample;.
 * Returns 0 if written, 1 if the class is missing, 2 on I/O or parse error. */
int dex_jimple_write_class_from_path(const char *path,
                                     const char *class_name,
                                     FILE *stream);

int dex_class_def_to_jimple(jd_meta_dex *dex, dex_class_def *cf, FILE *stream);

#endif
