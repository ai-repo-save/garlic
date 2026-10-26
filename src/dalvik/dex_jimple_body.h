#ifndef GARLIC_DEX_JIMPLE_BODY_H
#define GARLIC_DEX_JIMPLE_BODY_H

#include "dalvik/dex_analysis.h"
#include <stdio.h>

typedef struct {
    char *name;
    char *type;
} jimple_reg;

typedef struct {
    jd_meta_dex *dex;
    dex_code_item *code;
    dex_analysis *analysis;
    int unit;
    char *signature;
    FILE *stream;
    jimple_reg *regs;
    int nregs;
    char **locals;
    char **local_types;
    int nlocals;
    char **lines;
    int nlines;
    unsigned char *labels;
    int end_label;
    char *pending_invoke;
    char *pending_value;
    char *pending_type;
    int failed;
} jimple_body;

char *dex_jimple_type(const char *descriptor);
void dex_jimple_remember_local(jimple_body *body, char *name, char *type);
char *dex_jimple_use_reg(jimple_body *body, int reg);
void dex_jimple_mark_label(jimple_body *body, int unit);
void dex_jimple_emit_stmt(jimple_body *body, const char *statement);
void dex_jimple_emit_label(jimple_body *body, const char *name);
void dex_jimple_emit_switch(jimple_body *body, int unit);
void dex_jimple_emit_fill_array(jimple_body *body, int unit);

#endif
