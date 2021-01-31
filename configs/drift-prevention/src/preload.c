#define _GNU_SOURCE

#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h> 
#include <sys/un.h>
#include <stdarg.h>

#include "log.h"

#include "hash_search.c"
#include "config.c"
#include "crc32.c"
#include "remote_alert.c"

/*
* In order to avoid overwrite function calls in other executable files
* please try to add "static" before the function name
*
* use "nm -D " query what function has been overwrite
*
* Currently, the functions being overwrite are
* T drift_prevent_init_log
* T drift_prevent_teardown_log
* T drift_prevent_write_log
* T execl
* T execle
* T execlp
* T execv
* T execve
* T execvp
* 
*/

extern char **environ;

typedef struct {
    char real_path[PATH_MAX];
    char *drift_prevent;
    char *drift_detect;
} pre_info;

static const key_t SHM_WHITELIST_SIZE_NAME = 512;
static const key_t SHM_WHITELIST_NAME = 1024; 

typedef struct {
    char filename[PATH_MAX];
    uint32_t checksum;
} shm_whitelist_entry;

static Whitelist g_whitelist_config;
static hash_tbl_t *g_whitelist_hash;

static void init() __attribute__((constructor));

static void finish() __attribute__((destructor));

static void finish() {
    whitelist_free(&g_whitelist_config);
    hashtbl_node_free(g_whitelist_hash);
}

/*
 * As .so library is loaded for each exec, we need to initialize the whitelist as fast as possible
 * to minimize additional latency. Here we assumed, that in the first load we create a shared memory,
 * which later on is accessed by consecutive loads of the shared object by the 
 * SHM_WHITELIST_SIZE_NAME and SHM_WHITELIST_NAME.
 * 
 * One drawback of this solution is that we never free shared memory in this case.
 */
static void init() {
    void* shm_ref;
    int shm_file_size_fd; 
    int* shm_file_size_ptr;
    int shm_whitelist_fd; 
    shm_whitelist_entry *shm_whitelist_ptr;
    shm_file_size_fd = shmget(SHM_WHITELIST_SIZE_NAME, sizeof(size_t), S_IRUSR); 
    if (shm_file_size_fd < 0) {
        whitelist_init(&g_whitelist_config, 32);
        read_config(&g_whitelist_config);
        shm_file_size_fd = shmget(SHM_WHITELIST_SIZE_NAME, sizeof(size_t), IPC_CREAT | S_IRUSR | S_IWUSR); 
        if (shm_file_size_fd < 0) {
            drift_prevent_write_log(ERROR, "Could not create shared memory for whitelist size: %s\n", strerror(errno));
            goto use_data_from_file;
        }
        ftruncate(shm_file_size_fd, sizeof(size_t));
        size_t *shmaddr = (size_t *) shmat (shm_file_size_fd, 0, 0);
        memcpy(shmaddr, &g_whitelist_config.used, sizeof (size_t));
        int shm_whitelist_size = sizeof(shm_whitelist_entry) * g_whitelist_config.used;
        shm_whitelist_fd = shmget(SHM_WHITELIST_NAME, shm_whitelist_size, IPC_CREAT | S_IRUSR | S_IWUSR); 
        shm_whitelist_entry *file_shmaddr = (shm_whitelist_entry *) shmat (shm_whitelist_fd, 0, 0);
        g_whitelist_hash = hashtbl_init(&whitelist_hash_config);
        if (!g_whitelist_hash) {
            drift_prevent_write_log(ERROR, "Could not allocate memory for whitelist: %s\n", strerror(errno));
            goto use_data_from_file;
        }
        for (int i = 0; i < g_whitelist_config.used; i++) {
            shm_whitelist_entry file = { .checksum = g_whitelist_config.checksums[i]};
            strncpy(file.filename, g_whitelist_config.filenames[i], PATH_MAX * sizeof(char));
            memcpy(file_shmaddr, &file, sizeof(shm_whitelist_entry));
            entry *node = hashtbl_node_insert(file_shmaddr[0].filename, g_whitelist_hash);
            if(!node) {
                drift_prevent_write_log(ERROR, "node is null %s\n", strerror(errno));
                file_shmaddr += 1;
                continue;
            }
            node->checksum = file_shmaddr[0].checksum;
            file_shmaddr += 1;
        }
        goto finish;
    } else {
        size_t *shm_whitelist_size = (size_t *) shmat (shm_file_size_fd, 0, 0);
        g_whitelist_hash = hashtbl_init(&whitelist_hash_config);
        if (!g_whitelist_hash) {
            drift_prevent_write_log(ERROR, "Could not allocate memory for whitelist: %s\n", strerror(errno));
            goto read_data_from_file;
        }
        shm_whitelist_fd = shmget(SHM_WHITELIST_NAME, *shm_whitelist_size, S_IRUSR); 
        shm_whitelist_entry *file_shmaddr = (shm_whitelist_entry *) shmat (shm_whitelist_fd, 0, 0);
        for (int i = 0; i < *shm_whitelist_size; i++) {
            entry *node = hashtbl_node_insert(file_shmaddr[0].filename, g_whitelist_hash);
            if(!node) {
                drift_prevent_write_log(ERROR, "node is null %s\n", strerror(errno));
                file_shmaddr += 1;
                continue;
            }
            node->checksum = file_shmaddr[0].checksum;
            file_shmaddr += 1;
        }
        goto finish;
    }
read_data_from_file:
    whitelist_init(&g_whitelist_config, 32);
    read_config(&g_whitelist_config);
use_data_from_file:
    g_whitelist_hash = hashtbl_init(&whitelist_hash_config);
    for (int i = 0; i < g_whitelist_config.used; i++) {
        shm_whitelist_entry file = { .checksum = g_whitelist_config.checksums[i]};
        entry *node = hashtbl_node_insert(g_whitelist_config.filenames, g_whitelist_hash);
        if(!node) {
            drift_prevent_write_log(ERROR, "node is null %s\n", strerror(errno));
            continue;
        }
        node->checksum = file.checksum;
    }
finish:
    return;
}

static void * hash_search(hash_tbl_t * table, void *key) {
    if(!table||!key) {
        return NULL;
    }
    entry *node = (entry *) hashtbl_node_get(key, table);
    if(!node) {
        return NULL;
    }
    return node;
}

// CRC fields will be ignored if reason is not checksum related.
static int send_alert(const char* filepath, const char* syscall, const char* reason, const char* action, const uint32_t crc32_expected, const uint32_t crc32_actual) {
    char* podname = getenv("MY_POD_NAME");

    char *host = getenv("TENSORSEC_CONSOLE_ADDR");
    if (host == NULL) {
        drift_prevent_write_log(ERROR, "Env var TENSORSEC_CONSOLE_ADDR not found: %s\n", strerror(errno));
        return 1;
    }

    char *port = getenv("TENSORSEC_CONSOLE_PORT");
    if (port == NULL) {
        drift_prevent_write_log(ERROR, "Env var TENSORSEC_CONSOLE_PORT not found: %s\n", strerror(errno));
        return 1;
    }

    const int port_int = atoi(port);
    if (port_int == 0) {
        drift_prevent_write_log(ERROR, "Atoi converted port number to 0, check env var TENSORSEC_CONSOLE_PORT: %s\n", strerror(errno));
        return 1;
    }

    struct alert_t alert;
    strcpy(alert.filepath, filepath);
    strcpy(alert.podname, podname);
    strcpy(alert.syscall, syscall);
    strcpy(alert.reason, reason);
    strcpy(alert.action, action);
    alert.crc32_expected = crc32_expected;
    alert.crc32_actual = crc32_actual;

    int rc = raise_remote_alert(host, port_int, &alert);
    if (rc > 0) {
        drift_prevent_write_log(ERROR, "Failed to raise remote alert with reason %s and action %s: %s\n", reason, action, strerror(errno));
        return 1;
    }
    return 0;
}

static void strings_release(char **in) {
    int save_errno = errno;
    for (char **it = in; it && *it; ++it) {
        free(*it);
    }
    free(in);
    errno = save_errno;
}

static char **strings_build(const char *arg, va_list *args)
{
    char **result = 0;
    size_t size = 0;
    for (const char *it = arg; it; it = va_arg(*args, const char *)) {
        result = realloc(result, (size + 2) * sizeof(const char *));
        if (!result) {
            return NULL;
        }
        char *copy = strdup(it);
        if (!copy) {
            goto undo;
        }
        result[size++] = copy;
        result[size] = 0;
    }
    return result;

undo:
    /* Return an empty array.  */
    strings_release(result);
    return NULL;
}

static char *init_pre_data(const char* path, pre_info* pre_data)
{
    pre_data->real_path[0] = '\0';
    pre_data->drift_prevent = NULL;
    pre_data->drift_detect = NULL;

    char *ret = realpath(path, pre_data->real_path);
    pre_data->drift_prevent = getenv("DRIFT_PREVENT");
    pre_data->drift_detect = getenv("DRIFT_DETECT");
    return ret;
}

static long file_opt(const char* path, char **buffer) {
    FILE *fp;
    long l_size;

    fp = fopen(path, "rb");
    if (!fp) {
        drift_prevent_write_log(ERROR, "Open failed: %s\n", strerror(errno));
        return -1;
    }
    fseek(fp, 0L, SEEK_END);
    l_size = ftell(fp);
    rewind(fp);
    *buffer = calloc(1, l_size+1);
    if (!*buffer) {
        drift_prevent_write_log(ERROR, "Memory allocation for file content failed: %s\n", strerror(errno));
        goto cleanup_file;
    }
    if (1 != fread(*buffer, l_size, 1, fp)) {
        drift_prevent_write_log(ERROR, "File content read failed: %s\n", strerror(errno));
        goto cleanup_content;
    }
    return l_size;
cleanup_content:
    free(*buffer);
cleanup_file:
    if (fclose(fp) != 0) {
        drift_prevent_write_log(ERROR, "could not close file: %s\n", strerror(errno));
    }
    return -1;
}

// TODO: https://stackoverflow.com/questions/10312787/setting-the-ld-preload-environment-variable-for-commands-run-without-typing-the

#define VA_STR(...) __VA_ARGS__

#define CHECKPROCESS(exec_str, exec_name, file_path, input_str, ret_str)                \
typedef ssize_t (*exec_name##_func_t)(input_str);                                       \
static exec_name##_func_t old_##exec_name = NULL;                                       \
int exec_name(input_str)                                                                \
{                                                                                       \
    if (drift_prevent_init_log() != 0) {                                                \
        drift_prevent_write_log(WARN, "Failed to fully initialize log: %s\n",           \
                          strerror(errno));                                             \
    }                                                                                   \
                                                                                        \
    pre_info pre_data = {"", NULL, NULL};                                               \
    char *content = NULL;                                                               \
    char *action = NULL;                                                                \
    char *reason = NULL;                                                                \
    uint32_t expected_crc32 = 0;                                                        \
    uint32_t calculated_crc32 = 0;                                                      \
    if (!init_pre_data(file_path, &pre_data)) {                                         \
        drift_prevent_write_log(ERROR, "Failed to get real path: %s\n",                 \
                                strerror(errno));                                       \
        goto cleanup;                                                                   \
    }                                                                                   \
                                                                                        \
    entry *node = (entry *)hash_search(g_whitelist_hash, pre_data.real_path);           \
    if (!node) {                                                                        \
        reason = malloc(strlen(REASON_NOT_IN_WHITELIST)+1);                             \
        strcpy(reason, REASON_NOT_IN_WHITELIST);                                        \
        if (NULL != pre_data.drift_detect) {                                            \
            action = malloc(strlen(ACTION_NOTIFIED)+1);                                 \
            strcpy(action, ACTION_NOTIFIED);                                            \
            goto send_alert;                                                            \
        }                                                                               \
        else if (NULL != pre_data.drift_prevent) {                                      \
            action = malloc(strlen(ACTION_BLOCKED)+1);                                  \
            strcpy(action, ACTION_BLOCKED);                                             \
            goto send_alert;                                                            \
        }                                                                               \
    } else {                                                                            \
        long l_size = file_opt(pre_data.real_path, &content);                           \
        if (l_size < 0) {                                                               \
            goto cleanup;                                                               \
        }                                                                               \
        expected_crc32 = node->checksum;                                                \
        calculated_crc32 = rc_crc32(0, content, l_size);                                \
        if (calculated_crc32 != expected_crc32) {                                       \
            reason = malloc(strlen(REASON_CHECKSUM_MISMATCH)+1);                        \
            strcpy(reason, REASON_CHECKSUM_MISMATCH);                                   \
            if (NULL != pre_data.drift_detect) {                                        \
                action = malloc(strlen(ACTION_NOTIFIED)+1);                             \
                strcpy(action, ACTION_NOTIFIED);                                        \
                goto send_alert;                                                        \
            }                                                                           \
            else if (NULL != pre_data.drift_prevent) {                                  \
                action = malloc(strlen(ACTION_BLOCKED)+1);                              \
                strcpy(action, ACTION_BLOCKED);                                         \
                goto send_alert;                                                        \
            }                                                                           \
        }                                                                               \
    }                                                                                   \
    goto cleanup;                                                                       \
send_alert:                                                                             \
    if (send_alert(                                                                     \
        pre_data.real_path, exec_str, reason,                                           \
        action, calculated_crc32, expected_crc32                                        \
    ) > 0) {                                                                            \
        drift_prevent_write_log(ERROR, "Could not send alert: %s\n", strerror(errno));  \
    }                                                                                   \
    if (NULL != pre_data.drift_prevent) {                                               \
        free(content);                                                                  \
        if (drift_prevent_teardown_log() != 0) {                                        \
            drift_prevent_write_log(WARN, "Failed to properly teardown log: %s\n",      \
                                    strerror(errno));                                   \
        }                                                                               \
        errno = EACCES;                                                                 \
        return errno;                                                                   \
    }                                                                                   \
cleanup:                                                                                \
    free(content);                                                                      \
    free(reason);                                                                       \
    free(action);                                                                       \
    if (drift_prevent_teardown_log() != 0) {                                            \
        drift_prevent_write_log(WARN, "Failed to properly teardown log: %s\n",          \
                                strerror(errno));                                       \
    }                                                                                   \
old_ret:                                                                                \
    old_##exec_name = dlsym(RTLD_NEXT, exec_str);                                       \
    return old_##exec_name(ret_str);                                                    \
}

/*because can't pass VA_ARGS， the functions of execl* all use execve() */
#define CHECKPROCESS_VA(exec_str, exec_name, file_path, input_str, ret_str)     \
typedef ssize_t (*exec_name##_func_t)(input_str);                               \
static exec_name##_func_t old_##exec_name = NULL;                               \
int exec_name(input_str)                                                        \
{                                                                               \
    va_list args;                                                               \
    va_start(args, arg);                                                        \
                                                                                \
    char **argv = strings_build(arg, &args);                                    \
    if(!argv || !*argv){                                                        \
        fputs("A NULL argv was passed through an exec system call.", stderr);   \
        exit(EXIT_FAILURE);                                                     \
    }                                                                           \
    char *const *envp = va_arg(args, char *const *);                            \
    int ret = envp ?execve(ret_str):execve(file_path, argv, environ);           \
    va_end(args);                                                               \
    strings_release(argv);                                                      \
    return ret;                                                                 \
}

CHECKPROCESS("execv", execv, path, VA_STR(const char *path, char *const argv[]), VA_STR(path, argv))
CHECKPROCESS("execvp", execvp, file, VA_STR(const char *file, char *const argv[]), VA_STR(file, argv))
CHECKPROCESS("execve", execve, filename, VA_STR(const char *filename, char *const argv[],char *const envp[]), VA_STR(filename, argv, envp))

CHECKPROCESS_VA("execl", execl, path, VA_STR(const char *path, const char *arg, ...), VA_STR(path, argv, environ))
CHECKPROCESS_VA("execlp", execlp, file, VA_STR(const char *file, const char *arg, ...), VA_STR(file, argv, environ))
CHECKPROCESS_VA("execle", execle, path, VA_STR(const char *path, const char *arg, .../*, (char *)0, char *const envp[] */), VA_STR(path, argv, envp))