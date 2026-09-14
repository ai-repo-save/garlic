#include "dalvik/output_syntax.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tree_sitter/api.h>

const TSLanguage *tree_sitter_java(void);

static char* read_whole_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    long sz;
    char *buf;

    if (f == NULL)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    buf = malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    buf[sz] = '\0';
    if (out_len)
        *out_len = (size_t)sz;
    return buf;
}

static int java_has_parse_error(const char *src, uint32_t len)
{
    TSParser *parser;
    TSTree *tree;
    TSNode root;
    int err;

    parser = ts_parser_new();
    if (parser == NULL)
        return 0;
    if (!ts_parser_set_language(parser, tree_sitter_java())) {
        ts_parser_delete(parser);
        return 0;
    }
    tree = ts_parser_parse_string(parser, NULL, src, len);
    if (tree == NULL) {
        ts_parser_delete(parser);
        return 0;
    }
    root = ts_tree_root_node(tree);
    err = ts_node_has_error(root);
    ts_tree_delete(tree);
    ts_parser_delete(parser);
    return err;
}

static int prepend_header(const char *path, const char *reason)
{
    size_t len = 0;
    char *src = read_whole_file(path, &len);
    FILE *f;
    const char *marker = "Garlic syntax: INVALID";

    if (src == NULL)
        return -1;
    if (strstr(src, marker) != NULL) {
        free(src);
        return 0;
    }
    f = fopen(path, "wb");
    if (f == NULL) {
        free(src);
        return -1;
    }
    fprintf(f,
            "/*\n"
            " * %s\n"
            " * checker: tree-sitter-java\n"
            " * reason: %s\n"
            " */\n",
            marker, reason);
    fwrite(src, 1, len, f);
    fclose(f);
    free(src);
    return 0;
}

void jd_output_mark_syntax(const char *path, int is_smali)
{
    size_t len = 0;
    char *src;

    if (path == NULL || is_smali)
        return;
    src = read_whole_file(path, &len);
    if (src == NULL)
        return;
    if (java_has_parse_error(src, (uint32_t)len))
        prepend_header(path, "tree-sitter-java reported a parse error");
    free(src);
}
