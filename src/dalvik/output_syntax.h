#ifndef GARLIC_OUTPUT_SYNTAX_H
#define GARLIC_OUTPUT_SYNTAX_H

/* If the file is not valid Java/smali syntax, prepend a comment header. */
void jd_output_mark_syntax(const char *path, int is_smali);
void jd_output_mark_java(const char *source_dir, const char *package_name,
                         const char *class_name);

#endif
