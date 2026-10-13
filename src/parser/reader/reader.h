#ifndef GARLIC_READER_H
#define GARLIC_READER_H

#include <string.h>
#include "common/types.h"

typedef struct jd_bin {
    char           *buffer;
    size_t         buffer_size;
    size_t         cur_off;
    bool           overrun; /* 读取越过缓冲区末尾：结构非法，解析方应尽早停止 */
    const char    *error;   /* 首个非法结构的说明，用于向用户报告原因 */
} jd_bin;

static inline size_t jd_bin_read(jd_bin *bin, void *ptr, size_t size)
{
    if (bin->cur_off > bin->buffer_size || size > bin->buffer_size - bin->cur_off) {
        bin->overrun = true;
        return 0;
    }
    memcpy(ptr, &bin->buffer[bin->cur_off], size);
    bin->cur_off += size;
    return size;
}

static inline size_t jd_bin_read1(jd_bin *bin, void* ptr)
{
    return jd_bin_read(bin, ptr, sizeof(u1));
}

static inline size_t jd_bin_read2(jd_bin *bin, void* ptr)
{
    return jd_bin_read(bin, ptr, sizeof(u2));
}

static inline size_t jd_bin_read4(jd_bin *bin, void* ptr)
{
    return jd_bin_read(bin, ptr, sizeof(u4));
}

#endif //GARLIC_READER_H
