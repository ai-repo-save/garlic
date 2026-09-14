#include "dalvik/output_syntax.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static const char* probe_java(const char *src)
{
    int braces = 0;
    int parens = 0;
    const char *p = src;

    if (strstr(src, "if_true_block") != NULL)
        return "CFG node name leaked: if_true_block";
    if (strstr(src, "if_false_block") != NULL)
        return "CFG node name leaked: if_false_block";
    if (strstr(src, "public static  {") != NULL ||
        strstr(src, "static  {") != NULL)
        return "clinit written without a method name";
    if (strstr(src, "[][]{}") != NULL)
        return "new-array printed as empty 2-D initializer";
    if (strstr(src, " class;") != NULL || strstr(src, "\tclass;") != NULL)
        return "keyword class used as an identifier";
    if (strstr(src, "import ") != NULL && strchr(src, '$') != NULL)
        return "inner-class import used $\ instead of .";

    while (*p) {
        if (p[0] == '/' && p[1] == '/') {
            while (*p && *p != '\n')
                p++;
            continue;
        }
        if (p[0] == '/' && p[1] == '*') {
            p += 2;
            while (*p && !(p[0] == '*' && p[1] == '/'))
                p++;
            if (*p)
                p += 2;
            continue;
        }
        if (*p == '"' || *p == '\'') {
            char q = *p++;
            while (*p && *p != q) {
                if (*p == '\\' && p[1])
                    p++;
                p++;
            }
            if (*p)
                p++;
            continue;
        }
        if (*p == '{')
            braces++;
        else if (*p == '}')
            braces--;
        else if (*p == '(')
            parens++;
        else if (*p == ')')
            parens--;
        if (braces < 0)
            return "unmatched }";
        if (parens < 0)
            return "unmatched )";
        p++;
    }
    if (braces != 0)
        return "unbalanced braces";
    if (parens != 0)
        return "unbalanced parentheses";
    return NULL;
}

static const char* probe_smali(const char *src)
{
    const char *p = src;

    while (*p) {
        const char *line = p;
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);

        if (n > 10 && strncmp(line, "\tnew-array ", 11) == 0) {
            const char *type = line + n;
            while (type > line && type[-1] != ' ' && type[-1] != ',')
                type--;
            if (type[0] >= '0' && type[0] <= '9')
                return "new-array type printed as numeric id";
        }
        if (strstr(line, "aput-char ") != NULL ||
            strstr(line, "aget-char ") != NULL) {
            const char *comma = strrchr(line, ',');
            if (comma) {
                comma++;
                while (*comma == ' ')
                    comma++;
                if (*comma >= '0' && *comma <= '9')
                    return "23x third operand printed as immediate";
            }
        }
        p = nl ? nl + 1 : p + n;
        if (!nl)
            break;
    }
    return NULL;
}

static int prepend_header(const char *path, const char *kind, const char *reason)
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
            " * checker: garlic-syntax-probe\n"
            " * reason: %s\n"
            " */\n",
            marker, reason);
    fwrite(src, 1, len, f);
    fclose(f);
    free(src);
    (void)kind;
    return 0;
}

void jd_output_mark_syntax(const char *path, int is_smali)
{
    size_t len = 0;
    char *src;
    const char *reason;

    if (path == NULL)
        return;
    src = read_whole_file(path, &len);
    if (src == NULL)
        return;
    reason = is_smali ? probe_smali(src) : probe_java(src);
    free(src);
    if (reason != NULL)
        prepend_header(path, is_smali ? "smali" : "java", reason);
}
