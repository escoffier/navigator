#ifndef LOG_H_
#define LOG_H_

#include <stddef.h>

enum log_level {
    INFO,
    WARN,
    ERROR
};

extern int drift_prevent_init_log();

extern int drift_prevent_teardown_log();

extern int drift_prevent_write_log(int level, const char *fmt, ...);

#endif // LOG_H_
