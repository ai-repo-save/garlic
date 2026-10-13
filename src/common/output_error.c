#include <errno.h>
#include <pthread.h>
#include <string.h>

#include "output_error.h"
#include "common/str_tools.h"

static pthread_mutex_t error_lock = PTHREAD_MUTEX_INITIALIZER;
static long failed = 0;
static int last_errno = 0;
static string first_path = NULL;
static string rejected_path = NULL;
static long rejected_count = 0;
static const char *rejected_reason = NULL;

static mem_pool *names = NULL;

static void remember(string path)
{
    if (failed != 0)
        return;

    last_errno = errno;
    if (path == NULL)
        return;

    if (names == NULL)
        names = mem_create_pool();
    first_path = str_create_in(names, "%s", path);
}

static void record(string path)
{
    pthread_mutex_lock(&error_lock);
    remember(path);
    failed++;
    pthread_mutex_unlock(&error_lock);
}

void output_open_failed(string path)
{
    record(path);
}

void output_close(FILE *stream, string path)
{
    if (stream == NULL)
        return;

    int flush_failed = fflush(stream) != 0;
    int close_failed = fclose(stream) != 0;
    if (!flush_failed && !close_failed)
        return;

    record(path);
}

void output_input_rejected(string path, const char *reason)
{
    pthread_mutex_lock(&error_lock);
    rejected_count++;
    if (rejected_reason == NULL && reason != NULL)
        rejected_reason = reason;
    if (path == NULL) {
        pthread_mutex_unlock(&error_lock);
        return;
    }

    if (rejected_path == NULL) {
        mem_pool *pool = mem_create_pool();
        rejected_path = str_create_in(pool, "%s", path);
    }
    pthread_mutex_unlock(&error_lock);
}

bool output_had_errors(void)
{
    return failed > 0 || rejected_path != NULL;
}

bool output_report(void)
{
    if (rejected_path != NULL)
        fprintf(stderr, "[garlic] %s: invalid dex structure (%s), the file was rejected\n",
                rejected_path, rejected_reason != NULL ? rejected_reason : "unspecified");

    if (failed == 0)
        return rejected_count > 0;

    fprintf(stderr,
            "[garlic] error: %ld file(s) could not be written (%s); the "
            "output is incomplete\n",
            failed,
            last_errno != 0 ? strerror(last_errno) : "unknown error");
    if (first_path != NULL)
        fprintf(stderr, "[garlic] the first was %s\n", first_path);
    return true;
}
