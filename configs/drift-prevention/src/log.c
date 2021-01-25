#include <stdio.h>          // FILE, fopen, vfprintf
#include <stdarg.h>         // va_list, va_start, va_end
#include <sys/file.h>       // flock
#include <unistd.h>         // stderr
#include <errno.h>          // errno
#include <string.h>         // strerror
#include <stdlib.h>         // malloc
#include <time.h>           // time_t, ctime

#include "log.h"

FILE* g_log_dest = NULL;

int init_log() {
    g_log_dest = fopen("/var/log/drift-prevention.log", "a+");
    if (g_log_dest == NULL) {
        g_log_dest = stderr;
        return 1;
    }
    return 0;
}

int teardown_log() {
    if (g_log_dest != NULL) {
        if (!fclose(g_log_dest)) {
            return 1;
        }
    }
    return 0;
}

int write_log(int level, const char *fmt, ...) {
    if (g_log_dest == NULL) {
        return 1;
    }

    va_list args;

    va_start(args, fmt);
    int bufsize = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    char* buf_inner = malloc(bufsize + 1);

    va_start(args, fmt);
    vsprintf(buf_inner, fmt, args);
    va_end(args);

    char level_str[8] = "INFO";
    if (level == WARN) {
        strcpy(level_str, "WARN");
    } else if (level == ERROR) {
        strcpy(level_str, "ERROR");
    }

    time_t time_now = time(NULL);
    char time_buf[32];
    // 2021-01-19T12:22:46+0100
    strftime(time_buf, 32, "%Y-%m-%dT%H:%M:%S%z", localtime(&time_now));

    // lock writes to the same file from multiple processes
    int fd = fileno(g_log_dest);
    if (flock(fd, LOCK_EX) == -1) {
        free(buf_inner);
        return 1;
    }

    if (fprintf(g_log_dest, "%s %s: %s", time_buf, level_str, buf_inner) < 0) {
        fprintf(stderr, "Failed to write log: %s\n", strerror(errno));
    }

    // unlock file
    if (flock(fd, LOCK_UN) == -1) {
        free(buf_inner);
        return 1;
    }

    free(buf_inner);
    return 0;
}

// Uncomment int main() to test
// int main() {
//     if (init_log() != 0) {
//         write_log(WARN, "Failed to fully initialize log: %s\n", strerror(errno));
//     }

//     int my_age = 13;
//     char msg[] = "Hello, world";

//     write_log(INFO, "Info message: %d\n", my_age);
//     write_log(WARN, "Warn multiline message: %s\nsecond line\n", strerror(errno));
//     write_log(ERROR, "Error message: %s\n", msg);

//     if (teardown_log() != 0) {
//         write_log(WARN, "Failed to properly teardown log: %s\n", strerror(errno));
//     }
// }