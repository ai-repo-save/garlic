#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/str_tools.h"
#include "dalvik/dex_meta_helper.h"
#include "dalvik/dex_smali.h"
#include "libs/memory/mem_pool.h"
#include "parser/dex/metadata.h"
#include "zip.h"

static int descriptor_from_query(char *out, size_t cap, const char *query)
{
    size_t len;
    size_t i;
    int wrap;

    if (query == NULL || query[0] == '\0' || cap < 4)
        return -1;

    len = strlen(query);
    wrap = !(query[0] == 'L' && query[len - 1] == ';');
    if (wrap)
        len += 2;
    if (len + 1 > cap)
        return -1;

    if (wrap) {
        out[0] = 'L';
        memcpy(out + 1, query, strlen(query));
        out[len - 1] = ';';
        out[len] = '\0';
    } else {
        memcpy(out, query, len + 1);
    }

    for (i = 0; out[i] != '\0'; i++) {
        if (out[i] == '.')
            out[i] = '/';
    }
    return 0;
}

/* The lookup consumes this DEX; no metadata is needed after rendering. */
static int write_matching_class(jd_meta_dex *meta, const char *descriptor, FILE *stream)
{
    int i;
    int rc = 1;

    if (meta == NULL || meta->header == NULL)
        return 2;

    for (i = 0; i < meta->header->class_defs_size; ++i) {
        dex_class_def *cf = &meta->class_defs[i];
        string desc = dex_str_of_type_id(meta, cf->class_idx);
        if (desc != NULL && STR_EQL(desc, descriptor)) {
            dex_class_def_to_smali(meta, cf, stream);
            rc = 0;
            break;
        }
    }
    pthread_mutex_destroy(&meta->lambda_lock);
    mem_pool_free(meta->pool);
    return rc;
}

static int write_from_dex_path(const char *path, const char *descriptor, FILE *stream)
{
    jd_meta_dex *meta = parse_dex_file((string)path);
    if (meta == NULL)
        return 2;
    return write_matching_class(meta, descriptor, stream);
}

static int write_from_zip(struct zip_t *zip, const char *descriptor, FILE *stream)
{
    int total;
    int i;
    int found = 1;

    if (zip == NULL)
        return 2;

    total = zip_entries_total(zip);
    for (i = 0; i < total; ++i) {
        string path_in_zip;
        size_t buf_size;
        char *buf;
        int rc;

        zip_entry_openbyindex(zip, i);
        path_in_zip = (string)zip_entry_name(zip);
        if (path_in_zip == NULL) {
            zip_entry_close(zip);
            continue;
        }

        if (strchr(path_in_zip, '/') != NULL && !str_end_with(path_in_zip, ".apk")) {
            zip_entry_close(zip);
            continue;
        }

        if (str_end_with(path_in_zip, ".apk")) {
            buf_size = zip_entry_size(zip);
            buf = malloc(buf_size);
            if (buf) {
                struct zip_t *nested;
                zip_entry_noallocread(zip, (void *)buf, buf_size);
                nested = zip_stream_open(buf, buf_size, 0, 'r');
                if (nested) {
                    rc = write_from_zip(nested, descriptor, stream);
                    zip_stream_close(nested);
                    if (rc == 0)
                        found = 0;
                }
                free(buf);
            }
            zip_entry_close(zip);
            if (found == 0)
                return 0;
            continue;
        }

        if (!str_end_with(path_in_zip, ".dex")) {
            zip_entry_close(zip);
            continue;
        }

        buf_size = zip_entry_size(zip);
        buf = malloc(buf_size);
        if (buf == NULL) {
            zip_entry_close(zip);
            return 2;
        }
        zip_entry_noallocread(zip, (void *)buf, buf_size);
        zip_entry_close(zip);

        /* Parser and renderer scratch allocations also belong to this entry. */
        mem_pool *outer = mem_scratch_enter();
        rc = write_matching_class(parse_dex_from_buffer(buf, buf_size),
                                  descriptor, stream);
        mem_scratch_leave(outer);
        free(buf);
        if (rc == 0)
            return 0;
        if (rc == 2)
            return 2;
    }
    return found;
}

int dex_smali_write_class_from_path(const char *path,
                                    const char *class_name,
                                    FILE *stream)
{
    char descriptor[1024];
    int rc;

    if (path == NULL || stream == NULL)
        return 2;
    if (descriptor_from_query(descriptor, sizeof(descriptor), class_name) != 0)
        return 2;

    mem_init_pool();

    if (str_is_apk_path(path)) {
        struct zip_t *zip = zip_open(path, 0, 'r');
        if (zip == NULL) {
            mem_free_pool();
            return 2;
        }
        rc = write_from_zip(zip, descriptor, stream);
        zip_close(zip);
        mem_free_pool();
        return rc;
    }

    rc = write_from_dex_path(path, descriptor, stream);
    mem_free_pool();
    return rc;
}
