#ifndef LOG_H_
#define LOG_H_

#include <stddef.h>

enum log_level {
    INFO,
    WARN,
    ERROR
};

extern int init_log();

extern int teardown_log();

extern int write_log(int level, const char *fmt, ...);

#endif // LOG_H_
