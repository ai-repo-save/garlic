#include "decompiler/transformer/transformer.h"
#include <string.h>

static string array_element_name(string class_name)
{
    size_t n;
    string out;

    if (class_name == NULL)
        return "Object";
    n = strlen(class_name);
    if (n >= 2 && class_name[n - 2] == '[' && class_name[n - 1] == ']') {
        out = x_alloc(n - 1);
        memcpy(out, class_name, n - 2);
        out[n - 2] = '\0';
        return out;
    }
    return class_name;
}

string exp_new_array_to_s(jd_exp *expression)
{
    jd_exp_new_array *new_array = expression->data;
    string count = exp_to_s(&new_array->list->args[0]);
    string element = array_element_name(new_array->class_name);
    size_t len = snprintf(NULL, 0, "new %s[%s]", element, count) + 1;
    string result;

    if (new_array->list->len > 1)
        len += 3;
    result = x_alloc(len);
    memset(result, 0, len);
    sprintf(result, "new %s[%s]", element, count);

    if (new_array->list->len > 1) {
        strcat(result, "{");
        size_t old_len = len;
        for (int i = 1; i < new_array->list->len; ++i) {
            jd_exp *exp = &new_array->list->args[i];
            string value = exp_to_s(exp);
            len = len + strlen(value) + 2;
            result = x_realloc(result, old_len, len);
            old_len = len;
            strcat(result, value);
            if (i != new_array->list->len - 1)
                strcat(result, ", ");
        }
        strcat(result, "}");
    }

    result[len] = '\0';
    return result;
}

void exp_new_array_to_stream(FILE *stream, jd_node *node, jd_exp *expression)
{
    jd_exp_new_array *new_array = expression->data;
    string element = array_element_name(new_array->class_name);

    fprintf(stream, "new %s[", element);
    if (new_array->list->len > 0)
        expression_to_stream(stream, node, &new_array->list->args[0]);
    fprintf(stream, "]");

    if (new_array->list->len > 1) {
        fprintf(stream, "{");
        for (int i = 1; i < new_array->list->len; ++i) {
            jd_exp *exp = &new_array->list->args[i];
            expression_to_stream(stream, node, exp);
            if (i != new_array->list->len - 1)
                fprintf(stream, ", ");
        }
        fprintf(stream, "}");
    }
}
