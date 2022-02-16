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

#ifdef _TRIE
#include "trie_search.c"
#endif

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

enum function_stat
{
    DRIFT_DETECT = 1,
    DRIFT_PREVENT = 1 << 1,
    DRIFT_ON = DRIFT_DETECT | DRIFT_PREVENT,
    COMMAND_DETECT = 1 << 2,
    COMMAND_PREVENT = 1 << 3,
    COMMAND_ON = COMMAND_DETECT | COMMAND_PREVENT,
};

typedef struct
{
    char real_path[PATH_MAX];
    // unsigned int func_switch;
} pre_info;

static const key_t SHM_WHITELIST_SIZE_NAME = 512;
static const key_t SHM_WHITELIST_NAME = 1024;

static const key_t SHM_COMMAND_WHITELIST_SIZE = 1234;
static const key_t SHM_COMMAND_WHITELIST = 2345;

typedef struct
{
    char filename[PATH_MAX];
    uint32_t checksum;
} shm_whitelist_entry;

typedef struct
{
    char filename_commands[2 * PATH_MAX]; //TODO: ARG_MAX=131072,should use a pointer
    char cwd[PATH_MAX];
} shm_command_whitelist_entry;

static Whitelist g_whitelist_config;
static CommandWhitelist g_command_whitelist_config;

static hash_tbl_t *g_command_whitelist_hash; // TODO: this hashtable should have only filename_args entries and we look only for existence, not value stored (we do it this way, as one binary can have multiple args lists)

#ifdef _HASH
static hash_tbl_t *g_whitelist_hash;
#elif defined(_TRIE)
static struct trie_node *g_whitelist_trie_root;
#else
static shm_whitelist_entry *g_whitelist;
static size_t g_whitelist_size;

#endif

static unsigned int func_switch = 0;

static unsigned int config_err_flag = 0;

#ifdef _DEBUG

#else

static void init() __attribute__((constructor));

static void finish() __attribute__((destructor));

#endif

static void finish()
{
    whitelist_free(&g_whitelist_config);
    command_whitelist_free(&g_command_whitelist_config);
    hashtbl_node_free(g_command_whitelist_hash);


#ifdef _HASH
    hashtbl_node_free(g_whitelist_hash);
#elif defined(_TRIE)
    trie_delete(g_whitelist_trie_root);
#else
    free(g_whitelist);
#endif
}

static void init_command_whitelist()
{
    void *shm_ref;
    int shm_file_size_fd;
    int *shm_file_size_ptr;
    int shm_command_whitelist_fd;
    shm_command_whitelist_entry *shm_command_whitelist_ptr;
    shm_file_size_fd = shmget(SHM_COMMAND_WHITELIST_SIZE, sizeof(size_t), S_IRUSR);
#ifdef READ_FROM_DISK
    goto read_data_from_file;
#endif // TODO: Check for file changes
    if (shm_file_size_fd < 0)
    {
        command_whitelist_init(&g_command_whitelist_config, 32);
        if(read_command_config(&g_command_whitelist_config)){
            config_err_flag = 1;
            goto finish;
        }
        shm_file_size_fd = shmget(SHM_COMMAND_WHITELIST_SIZE, sizeof(size_t), IPC_CREAT | S_IRUSR | S_IWUSR);
        if (shm_file_size_fd < 0)
        {
            drift_prevent_write_log(ERROR, "Could not create shared memory for whitelist size: %s\n", strerror(errno));
            errno = 0;
            goto use_data_from_file;
        }
        ftruncate(shm_file_size_fd, sizeof(size_t));
        size_t *shmaddr = (size_t *)shmat(shm_file_size_fd, 0, 0);
        memcpy(shmaddr, &g_command_whitelist_config.used, sizeof(size_t));
        int shm_command_whitelist_size = sizeof(shm_command_whitelist_entry) * g_command_whitelist_config.used;
        shm_command_whitelist_fd = shmget(SHM_COMMAND_WHITELIST, shm_command_whitelist_size, IPC_CREAT | S_IRUSR | S_IWUSR);
        shm_command_whitelist_entry *file_shmaddr = (shm_command_whitelist_entry *)shmat(shm_command_whitelist_fd, 0, 0);
        g_command_whitelist_hash = hashtbl_init(&command_whitelist_hash_config);
        if (!g_command_whitelist_hash)
        {
            drift_prevent_write_log(ERROR, "Could not allocate memory for whitelist: %s\n", strerror(errno));
            goto use_data_from_file;
        }
        for (int i = 0; i < g_command_whitelist_config.used; i++)
        {
            shm_command_whitelist_entry file;
            strncpy(file.filename_commands, g_command_whitelist_config.filename_commands[i], 2 * PATH_MAX * sizeof(char));
            strncpy(file.cwd, g_command_whitelist_config.cwd[i], sizeof(file.cwd));
            memcpy(file_shmaddr, &file, sizeof(shm_command_whitelist_entry));
            command_whitelist_entry *node = hashtbl_node_insert(file_shmaddr[0].filename_commands, file_shmaddr[0].cwd, g_command_whitelist_hash);
            if (!node)
            {
                drift_prevent_write_log(ERROR, "node is null %s\n", strerror(errno));
                errno = 0;
                file_shmaddr += 1;
                continue;
            }
            strncpy(node->cwd, file_shmaddr[0].cwd, sizeof(node->cwd));
            file_shmaddr += 1;
        }
        goto finish;
    }
    else
    {
        size_t *shm_command_whitelist_size = (size_t *)shmat(shm_file_size_fd, 0, 0);
        g_command_whitelist_hash = hashtbl_init(&command_whitelist_hash_config);
        if (!g_command_whitelist_hash)
        {
            drift_prevent_write_log(ERROR, "Could not allocate memory for whitelist: %s\n", strerror(errno));
            errno = 0;
            goto read_data_from_file;
        }
        shm_command_whitelist_fd = shmget(SHM_COMMAND_WHITELIST, *shm_command_whitelist_size, S_IRUSR);
        shm_command_whitelist_entry *file_shmaddr = (shm_command_whitelist_entry *)shmat(shm_command_whitelist_fd, 0, 0);
        for (int i = 0; i < *shm_command_whitelist_size; i++)
        {
            command_whitelist_entry *node = hashtbl_node_insert(file_shmaddr[0].filename_commands, file_shmaddr[0].cwd, g_command_whitelist_hash);
            if (!node)
            {
                drift_prevent_write_log(ERROR, "node is null %s\n", strerror(errno));
                errno = 0;
                file_shmaddr += 1;
                continue;
            }
            strncpy(node->cwd, file_shmaddr[0].cwd, sizeof(node->cwd));
            file_shmaddr += 1;
        }
        goto finish;
    }
read_data_from_file:
    command_whitelist_init(&g_command_whitelist_config, 32);
    if(read_command_config(&g_command_whitelist_config)){
        config_err_flag = 1;
        goto finish;
    }
use_data_from_file:
    g_command_whitelist_hash = hashtbl_init(&command_whitelist_hash_config);
    for (int i = 0; i < g_command_whitelist_config.used; i++)
    {
        command_whitelist_entry *node = hashtbl_node_insert(g_command_whitelist_config.filename_commands[i], g_command_whitelist_config.cwd[i], g_command_whitelist_hash);
        if (!node)
        {
            drift_prevent_write_log(ERROR, "node is null %s\n", strerror(errno));
            errno = 0;
            continue;
        }
        strncpy(node->cwd, g_command_whitelist_config.cwd[i], sizeof(node->cwd));
    }
finish:
    return;
}

#ifndef _TRIE
static void init_whitelist()
{
    void *shm_ref;
    int shm_file_size_fd;
    int *shm_file_size_ptr;
    int shm_whitelist_fd;
    shm_whitelist_entry *shm_whitelist_ptr;
    shm_file_size_fd = shmget(SHM_WHITELIST_SIZE_NAME, sizeof(size_t), S_IRUSR);
#ifdef READ_FROM_DISK
    goto read_data_from_file;
#endif
    if (shm_file_size_fd < 0)
    {
        whitelist_init(&g_whitelist_config, 32);
        if(read_config(&g_whitelist_config)){
            config_err_flag = 1;
            goto finish;
        }
        shm_file_size_fd = shmget(SHM_WHITELIST_SIZE_NAME, sizeof(size_t), IPC_CREAT | S_IRUSR | S_IWUSR);
        if (shm_file_size_fd < 0)
        {
            drift_prevent_write_log(ERROR, "Could not create shared memory for whitelist size: %s\n", strerror(errno));
            errno = 0;
            goto use_data_from_file;
        }
        ftruncate(shm_file_size_fd, sizeof(size_t));
        size_t *shmaddr = (size_t *)shmat(shm_file_size_fd, 0, 0);
        memcpy(shmaddr, &g_whitelist_config.used, sizeof(size_t));
        int shm_whitelist_size = sizeof(shm_whitelist_entry) * g_whitelist_config.used;
        shm_whitelist_fd = shmget(SHM_WHITELIST_NAME, shm_whitelist_size, IPC_CREAT | S_IRUSR | S_IWUSR);
        shm_whitelist_entry *file_shmaddr = (shm_whitelist_entry *)shmat(shm_whitelist_fd, 0, 0);
        #ifndef _HASH
        g_whitelist = malloc(shm_whitelist_size * sizeof(shm_whitelist_entry));
        g_whitelist_size = g_whitelist_config.used;
        if (!g_whitelist) {
            drift_prevent_write_log(ERROR, "Could not allocate memory for whitelist: %s\n", strerror(errno));
            goto use_data_from_file;
        }

        #else
        g_whitelist_hash = hashtbl_init(&whitelist_hash_config);
        if (!g_whitelist_hash)
        {
            drift_prevent_write_log(ERROR, "Could not allocate memory for whitelist: %s\n", strerror(errno));
            errno = 0;
            goto use_data_from_file;
        }
        #endif

        for (int i = 0; i < g_whitelist_config.used; i++)
        {
            #ifndef _HASH
            shm_whitelist_entry file = {.checksum = g_whitelist_config.checksums[i]};
            strncpy(file.filename, g_whitelist_config.filenames[i], PATH_MAX * sizeof(char));
            memcpy(file_shmaddr, &file, sizeof(shm_whitelist_entry));
            strncpy(g_whitelist[i].filename, file_shmaddr[0].filename, PATH_MAX * sizeof(char));
            g_whitelist[i].checksum = file_shmaddr[0].checksum;
            #else
            entry *node = hashtbl_node_insert(file_shmaddr[0].filename, &(file_shmaddr[0].checksum), g_whitelist_hash);
            if (!node)
            {
                drift_prevent_write_log(ERROR, "node is null %s\n", strerror(errno));
                errno = 0;
                file_shmaddr += 1;
                continue;
            }
            node->checksum = file_shmaddr[0].checksum;
            #endif

            file_shmaddr += 1;
        }
        goto finish;
    }
    else
    {
        size_t *shm_whitelist_size = (size_t *)shmat(shm_file_size_fd, 0, 0);
        g_whitelist_size = *shm_whitelist_size;
        g_whitelist_config.used = g_whitelist_size;
        #ifdef _HASH
        g_whitelist_hash = hashtbl_init(&whitelist_hash_config);
        if (!g_whitelist_hash)
        {
            drift_prevent_write_log(ERROR, "Could not allocate memory for whitelist: %s\n", strerror(errno));
            errno = 0;
            goto read_data_from_file;
        }
        #else
        g_whitelist = malloc(*shm_whitelist_size * sizeof(shm_whitelist_entry));
        if (!g_whitelist) {
            drift_prevent_write_log(ERROR, "Could not allocate memory for whitelist: %s\n", strerror(errno));
            goto read_data_from_file;
        }
        #endif

        shm_whitelist_fd = shmget(SHM_WHITELIST_NAME, *shm_whitelist_size, S_IRUSR);
        shm_whitelist_entry *file_shmaddr = (shm_whitelist_entry *)shmat(shm_whitelist_fd, 0, 0);
        for (int i = 0; i < *shm_whitelist_size; i++)
        {
            #ifdef _HASH
            entry *node = hashtbl_node_insert(file_shmaddr[0].filename, &(file_shmaddr[0].checksum), g_whitelist_hash);
            if (!node)
            {
                drift_prevent_write_log(ERROR, "node is null %s\n", strerror(errno));
                errno = 0;
                file_shmaddr += 1;
                continue;
            }
            node->checksum = file_shmaddr[0].checksum;
            #else

            strncpy(g_whitelist[i].filename, file_shmaddr[0].filename, PATH_MAX * sizeof(char));
            g_whitelist[i].checksum = file_shmaddr[0].checksum;
            #endif
            file_shmaddr += 1;
        }
        goto finish;
    }
read_data_from_file:
    whitelist_init(&g_whitelist_config, 32);
    if(read_config(&g_whitelist_config)){
        config_err_flag = 1;
        goto finish;
    }
use_data_from_file:
    #ifdef _HASH
    g_whitelist_hash = hashtbl_init(&whitelist_hash_config);
    for (int i = 0; i < g_whitelist_config.used; i++)
    {
        shm_whitelist_entry file = {.checksum = g_whitelist_config.checksums[i]};
        entry *node = hashtbl_node_insert(g_whitelist_config.filenames[i], &(file.checksum), g_whitelist_hash);
        if (!node)
        {
            drift_prevent_write_log(ERROR, "node is null %s\n", strerror(errno));
            errno = 0;
            continue;
        }
        node->checksum = file.checksum;
    }
    #else

    g_whitelist = malloc(g_whitelist_config.used * sizeof(shm_whitelist_entry));
    for (int i = 0; i < g_whitelist_config.used; i++) {
        shm_whitelist_entry file = { .checksum = g_whitelist_config.checksums[i]};
        strncpy(g_whitelist[i].filename, g_whitelist_config.filenames[i], PATH_MAX * sizeof(char));
        g_whitelist[i].checksum = file.checksum;
    }
    #endif

finish:
    return;
}
#endif

/*
 * As .so library is loaded for each exec, we need to initialize the whitelist as fast as possible
 * to minimize additional latency. Here we assumed, that in the first load we create a shared memory,
 * which later on is accessed by consecutive loads of the shared object by the
 * SHM_WHITELIST_SIZE_NAME and SHM_WHITELIST_NAME.
 *
 * One drawback of this solution is that we never free shared memory in this case.
 */
static void init()
{
    if (getenv("DRIFT_DETECT"))
    {
        func_switch |= DRIFT_DETECT;
    }

    if (getenv("DRIFT_PREVENT"))
    {
        func_switch |= DRIFT_PREVENT;
    }

    if (getenv("COMMAND_DRIFT_PREVENT"))
    {
        func_switch |= COMMAND_PREVENT;
    }

    if (getenv("COMMAND_DRIFT_DETECT"))
    {
        func_switch |= COMMAND_DETECT;
    }

    if (func_switch & DRIFT_ON)
    {
        #ifndef _TRIE
        init_whitelist();
        #else
        trie_init(g_whitelist_trie_root);
        #endif
    }

    if (func_switch & COMMAND_ON)
    {
        init_command_whitelist();
    }
}

static void *hash_search(hash_tbl_t *table, void *key, void *value)
{
    if (!table || !key)
    {
        return NULL;
    }
    void *node = hashtbl_node_get(key, value, table);
    if (!node)
    {
        return NULL;
    }
    return node;
}

#if !defined(_HASH) && !defined(_TRIE)
static int binary_search(shm_whitelist_entry *list_of_files, int size, const char *target) {
    int bottom= 0;
    int mid;
    int top = size - 1;
    while(bottom <= top){
        mid = (bottom + top)/2;
        if (strcmp(list_of_files[mid].filename, target) == 0 && strlen(list_of_files[mid].filename) == strlen(target)){
            return mid;
        } else if (strcmp(list_of_files[mid].filename, target) > 0){
            top    = mid - 1;
        } else if (strcmp(list_of_files[mid].filename, target) < 0){
            bottom = mid + 1;
        }
    }
    return -1;
}
#endif


// CRC fields will be ignored if reason is not checksum related.
static int send_alert(const char *filepath, const char *syscall, const char *reason, const char *action, const uint32_t crc32_expected, const uint32_t crc32_actual)
{
    char *podname = getenv("MY_POD_NAME");

    char *poduid = getenv("MY_POD_UID");

    char *podnamespace = getenv("MY_POD_NAMESPACE");

    // char *host = getenv("_EVENTCENTER_NEW_ADDR");
    char *host = getenv("EVENTCENTER_NEW_ADDR");
    if (host == NULL)
    {
        drift_prevent_write_log(ERROR, "Env var EVENTCENTER_ADDR not found: %s\n", strerror(errno));
        errno = 0;
        return 1;
    }

    // char *port = getenv("TENSORSEC_EVENTCENTER_NEW_PORT");
    char *port = getenv("EVENTCENTER_NEW_PORT");
    if (port == NULL)
    {
        drift_prevent_write_log(ERROR, "Env var EVENTCENTER_NEW_PORT not found: %s\n", strerror(errno));
        errno = 0;
        return 1;
    }

    const int port_int = atoi(port);
    if (port_int == 0)
    {
        drift_prevent_write_log(ERROR, "Atoi converted port number to 0, check env var CONSOLE_PORT: %s\n", strerror(errno));
        errno = 0;
        return 1;
    }

    char unknown_str[] = "unknown";
    if (!podname)
    {
        drift_prevent_write_log(ERROR, "Env var MY_POD_NAME not found: %s\n", strerror(errno));
        errno = 0;
        podname = unknown_str;
    }

    if (!poduid)
    {
        drift_prevent_write_log(ERROR, "Env var MY_POD_UID not found: %s\n", strerror(errno));
        errno = 0;
        poduid = unknown_str;
    }

    if (!podnamespace)
    {
        drift_prevent_write_log(ERROR, "Env var MY_POD_NAMESPACE not found: %s\n", strerror(errno));
        errno = 0;
        podnamespace = unknown_str;
    }

    struct alert_t alert;
    strcpy(alert.filepath, filepath);
    strcpy(alert.podname, podname);
    strcpy(alert.poduid, poduid);
    strcpy(alert.podnamespace, podnamespace);
    strcpy(alert.syscall, syscall);
    strcpy(alert.reason, reason);
    strcpy(alert.action, action);
    alert.crc32_expected = crc32_expected;
    alert.crc32_actual = crc32_actual;

    int rc = raise_remote_alert(host, port_int, &alert);
    if (rc > 0)
    {
        drift_prevent_write_log(ERROR, "Failed to raise remote alert with reason %s and action %s: %s %s\n", reason, action, filepath, strerror(errno));
        errno = 0;
        return 1;
    }
    return 0;
}

static void strings_release(char **in)
{
    int save_errno = errno;
    for (char **it = in; it && *it; ++it)
    {
        free(*it);
    }
    free(in);
    errno = save_errno;
}

static char **strings_build(const char *arg, va_list *args)
{
    char **result = 0;
    size_t size = 0;
    for (const char *it = arg; it; it = va_arg(*args, const char *))
    {
        result = realloc(result, (size + 2) * sizeof(const char *));
        if (!result)
        {
            return NULL;
        }
        char *copy = strdup(it);
        if (!copy)
        {
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

#define WHICH_DELIMITER ":"

char * which_path(const char *name, const char *_path, char *result) {
  char *path = strdup(_path);
  if (NULL == path) return NULL;
  char *tok = strtok(path, WHICH_DELIMITER);

  while (tok) {
    // path
    int len = strlen(tok) + 2 + strlen(name);
    char *file = malloc(len);
    if (!file) {
      free(path);
      return NULL;
    }
    sprintf(file, "%s/%s", tok, name);

    // executable
    if (0 == access(file, X_OK)) {
      free(path);
      memcpy(result, file, len);
      return file;
    }

    // next token
    tok = strtok(NULL, WHICH_DELIMITER);
    free(file);
  }

  free(path);

  return NULL;
}

char * which(const char *name, void *dest) {
  return which_path(name, getenv("PATH"), dest);
}

static char *init_pre_data(const char *path, pre_info *pre_data)
{
    pre_data->real_path[0] = '\0';
    char *ret = realpath(path, pre_data->real_path);
    if(!ret){
        ret = which(path, pre_data->real_path);
    }
    return ret;
}

static long file_opt(const char *path, char **buffer)
{
    FILE *fp;
    long l_size;

    fp = fopen(path, "rb");
    if (!fp)
    {
        drift_prevent_write_log(ERROR, "Open failed: %s\n", strerror(errno));
        errno = 0;
        return -1;
    }
    fseek(fp, 0L, SEEK_END);
    l_size = ftell(fp);
    rewind(fp);
    *buffer = calloc(1, l_size + 1);
    if (!*buffer)
    {
        drift_prevent_write_log(ERROR, "Memory allocation for file content failed: %s\n", strerror(errno));
        errno = 0;
        goto cleanup_file;
    }
    if (1 != fread(*buffer, l_size, 1, fp))
    {
        drift_prevent_write_log(ERROR, "File content read failed: %s\n", strerror(errno));
        errno = 0;
        goto cleanup_content;
    }
    return l_size;
cleanup_content:
    free(*buffer);
cleanup_file:
    if (fclose(fp) != 0)
    {
        drift_prevent_write_log(ERROR, "could not close file: %s\n", strerror(errno));
        errno = 0;
    }
    return -1;
}

static int splice_cmdline(char *const argv[], char *args)
{

    int i = 0;
    for (i = 0; argv[i] != NULL; i++)
    {
        if (i == 0)
        {
            continue;
        }
        strcat(args, " ");
        strcat(args, argv[i]);
    }

    return 0;
}

// TODO: https://stackoverflow.com/questions/10312787/setting-the-ld-preload-environment-variable-for-commands-run-without-typing-the

// typedef entry  *(*result_ret_func)(const char *target);

// result_ret_func result_ret_func_ptr;

// #ifdef _HASH
// static entry *ret_hash_result(const char *target)
// {
//     return (entry *)hash_search(g_whitelist_hash, (void  *)target, 0);
// }
// result_ret_func_ptr = ret_hash_result;
// #elif defined(_TRIE)
// static entry *ret_trie_result(const char *target)
// {
//     trie_search(g_whitelist_trie_root, target);
// }
// result_ret_func_ptr = ret_trie_result;
// #else

// #endif




#define VA_STR(...) __VA_ARGS__

#ifdef _HASH

#define CHECKPROCESS(exec_str, exec_name, file_path, input_str, ret_str)                 \
    typedef ssize_t (*exec_name##_func_t)(input_str);                                    \
    static exec_name##_func_t old_##exec_name = NULL;                                    \
    int exec_name(input_str)                                                             \
    {                                                                                    \
        if(config_err_flag)                                                              \
        {                                                                                \
            drift_prevent_write_log(ERROR, "read config file fail, skip detect %u\n",    \
                        func_switch);                                                    \
           goto old_ret;                                                                 \
        }                                                                                \
        if (drift_prevent_init_log() != 0)                                               \
        {                                                                                \
            drift_prevent_write_log(WARN, "Failed to fully initialize log: %s\n",        \
                                    strerror(errno));                                    \
        }                                                                                \
                                                                                         \
        pre_info pre_data = {""};                                                        \
        char *content = NULL;                                                            \
        char *action = NULL;                                                             \
        char *reason = NULL;                                                             \
        uint32_t expected_crc32 = 0;                                                     \
        uint32_t calculated_crc32 = 0;                                                   \
        if (!func_switch)                                                                \
        {                                                                                \
            goto cleanup;                                                                \
        }                                                                                \
        if (!init_pre_data(file_path, &pre_data))                                        \
        {                                                                                \
            drift_prevent_write_log(ERROR, "Failed to get real path: %s\n",              \
                                    strerror(errno));                                    \
            errno = 0;                                                                   \
            goto cleanup;                                                                \
        }                                                                                \
        char args[2 * PATH_MAX + 1] = {'\0'};                                            \
        char pwd[PATH_MAX] = {'\0'};                                                     \
        strncpy(args, pre_data.real_path, strlen(pre_data.real_path));                   \
        splice_cmdline(argv, args);                                                      \
        int block_flag = 0;                                                              \
        if (func_switch & DRIFT_ON)                                                      \
        {                                                                                \
            entry *node = (entry *)hash_search(g_whitelist_hash, pre_data.real_path, 0); \
            if (!node)                                                                   \
            {                                                                            \
                reason = malloc(strlen(REASON_NOT_IN_WHITELIST) + 1);                    \
                strcpy(reason, REASON_NOT_IN_WHITELIST);                                 \
                if (func_switch & DRIFT_DETECT)                                          \
                {                                                                        \
                    action = malloc(strlen(ACTION_NOTIFIED) + 1);                        \
                    strcpy(action, ACTION_NOTIFIED);                                     \
                    send_alert(pre_data.real_path, exec_str, reason,                     \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
                else if (func_switch & DRIFT_PREVENT)                                    \
                {                                                                        \
                    block_flag = 1;                                                      \
                    action = malloc(strlen(ACTION_BLOCKED) + 1);                         \
                    strcpy(action, ACTION_BLOCKED);                                      \
                    send_alert(pre_data.real_path, exec_str, reason,                     \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
            }                                                                            \
            else                                                                         \
            {                                                                            \
                long l_size = file_opt(pre_data.real_path, &content);                    \
                if (l_size < 0)                                                          \
                {                                                                        \
                    goto cleanup;                                                        \
                }                                                                        \
                expected_crc32 = node->checksum;                                         \
                calculated_crc32 = rc_crc32(0, content, l_size);                         \
                if (calculated_crc32 != expected_crc32)                                  \
                {                                                                        \
                    reason = malloc(strlen(REASON_CHECKSUM_MISMATCH) + 1);               \
                    strcpy(reason, REASON_CHECKSUM_MISMATCH);                            \
                    if (func_switch & DRIFT_DETECT)                                      \
                    {                                                                    \
                        action = malloc(strlen(ACTION_NOTIFIED) + 1);                    \
                        strcpy(action, ACTION_NOTIFIED);                                 \
                        send_alert(pre_data.real_path, exec_str, reason,                 \
                                   action, calculated_crc32, expected_crc32);            \
                    }                                                                    \
                    else if (func_switch & DRIFT_PREVENT)                                \
                    {                                                                    \
                        block_flag = 1;                                                  \
                        action = malloc(strlen(ACTION_BLOCKED) + 1);                     \
                        strcpy(action, ACTION_BLOCKED);                                  \
                        send_alert(pre_data.real_path, exec_str, reason,                 \
                                   action, calculated_crc32, expected_crc32);            \
                    }                                                                    \
                }                                                                        \
            }                                                                            \
        }                                                                                \
                                                                                         \
        if (func_switch & COMMAND_ON)                                                    \
        {                                                                                \
            getcwd(pwd, sizeof(pwd));                                                    \
            if (strlen(pwd) > 0 && pwd[strlen(pwd) - 1] != '/')                          \
            {                                                                            \
                pwd[strlen(pwd)] = '/';                                                  \
            }                                                                            \
            command_whitelist_entry *command_node = (command_whitelist_entry *)          \
                hash_search(g_command_whitelist_hash,                                    \
                            args, pwd);                                                  \
            if (command_node)                                                            \
            {                                                                            \
                if (!strcmp(pwd, command_node->cwd))                                     \
                {                                                                        \
                    goto cleanup;                                                        \
                }                                                                        \
                reason = malloc(strlen(REASON_COMMAND_CWD_NOT_ALLOW) + 1);               \
                strcpy(reason, REASON_COMMAND_CWD_NOT_ALLOW);                            \
                if (func_switch & COMMAND_DETECT)                                        \
                {                                                                        \
                    action = malloc(strlen(ACTION_NOTIFIED) + 1);                        \
                    strcpy(action, ACTION_NOTIFIED);                                     \
                    send_alert(args, exec_str, reason,                                   \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
                else if (func_switch & COMMAND_PREVENT)                                  \
                {                                                                        \
                    block_flag = 1;                                                      \
                    action = malloc(strlen(ACTION_BLOCKED) + 1);                         \
                    strcpy(action, ACTION_BLOCKED);                                      \
                    send_alert(args, exec_str, reason,                                   \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
            }                                                                            \
            else                                                                         \
            {                                                                            \
                reason = malloc(strlen(REASON_COMMAND_NOT_INT_WHITELIST) + 1);           \
                strcpy(reason, REASON_COMMAND_NOT_INT_WHITELIST);                        \
                if (func_switch & COMMAND_DETECT)                                        \
                {                                                                        \
                    action = malloc(strlen(ACTION_NOTIFIED) + 1);                        \
                    strcpy(action, ACTION_NOTIFIED);                                     \
                    send_alert(args, exec_str, reason,                                   \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
                else if (func_switch & COMMAND_PREVENT)                                  \
                {                                                                        \
                    block_flag = 1;                                                      \
                    action = malloc(strlen(ACTION_BLOCKED) + 1);                         \
                    strcpy(action, ACTION_BLOCKED);                                      \
                    send_alert(args, exec_str, reason,                                   \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
            }                                                                            \
        }                                                                                \
    cleanup:                                                                             \
        free(content);                                                                   \
        free(reason);                                                                    \
        free(action);                                                                    \
        if (drift_prevent_teardown_log() != 0)                                           \
        {                                                                                \
            drift_prevent_write_log(WARN, "Failed to properly teardown log: %s\n",       \
                                    strerror(errno));                                    \
            errno = 0;                                                                   \
        }                                                                                \
        if (block_flag)                                                                  \
        {                                                                                \
            errno = EACCES;                                                              \
            return errno;                                                                \
        }                                                                                \
    old_ret:                                                                             \
        old_##exec_name = dlsym(RTLD_NEXT, exec_str);                                    \
        return old_##exec_name(ret_str);                                                 \
    }

#elif defined(_TRIE)

#define CHECKPROCESS(exec_str, exec_name, file_path, input_str, ret_str)                 \
    typedef ssize_t (*exec_name##_func_t)(input_str);                                    \
    static exec_name##_func_t old_##exec_name = NULL;                                    \
    int exec_name(input_str)                                                             \
    {                                                                                    \
        if(config_err_flag)                                                              \
        {                                                                                \
            drift_prevent_write_log(ERROR, "read config file fail, skip detect %u\n",    \
                        func_switch);                                                    \
           goto old_ret;                                                                 \
        }                                                                                \
        if (drift_prevent_init_log() != 0)                                               \
        {                                                                                \
            drift_prevent_write_log(WARN, "Failed to fully initialize log: %s\n",        \
                                    strerror(errno));                                    \
        }                                                                                \
                                                                                         \
        pre_info pre_data = {""};                                                        \
        char *content = NULL;                                                            \
        char *action = NULL;                                                             \
        char *reason = NULL;                                                             \
        uint32_t expected_crc32 = 0;                                                     \
        uint32_t calculated_crc32 = 0;                                                   \
        if (!func_switch)                                                                \
        {                                                                                \
            goto cleanup;                                                                \
        }                                                                                \
        if (!init_pre_data(file_path, &pre_data))                                        \
        {                                                                                \
            drift_prevent_write_log(ERROR, "Failed to get real path: %s\n",              \
                                    strerror(errno));                                    \
            errno = 0;                                                                   \
            goto cleanup;                                                                \
        }                                                                                \
        char args[2 * PATH_MAX + 1] = {'\0'};                                            \
        char pwd[PATH_MAX] = {'\0'};                                                     \
        strncpy(args, pre_data.real_path, strlen(pre_data.real_path));                   \
        splice_cmdline(argv, args);                                                      \
        int block_flag = 0;                                                              \
        if (func_switch & DRIFT_ON)                                                      \
        {                                                                                \
            struct trie_node *node = trie_search(g_whitelist_trie_root,                  \
                                                pre_data.real_path);                     \
            if (!node)                                                                   \
            {                                                                            \
                reason = malloc(strlen(REASON_NOT_IN_WHITELIST) + 1);                    \
                strcpy(reason, REASON_NOT_IN_WHITELIST);                                 \
                if (func_switch & DRIFT_DETECT)                                          \
                {                                                                        \
                    action = malloc(strlen(ACTION_NOTIFIED) + 1);                        \
                    strcpy(action, ACTION_NOTIFIED);                                     \
                    send_alert(pre_data.real_path, exec_str, reason,                     \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
                else if (func_switch & DRIFT_PREVENT)                                    \
                {                                                                        \
                    block_flag = 1;                                                      \
                    action = malloc(strlen(ACTION_BLOCKED) + 1);                         \
                    strcpy(action, ACTION_BLOCKED);                                      \
                    send_alert(pre_data.real_path, exec_str, reason,                     \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
            }                                                                            \
            else                                                                         \
            {                                                                            \
                long l_size = file_opt(pre_data.real_path, &content);                    \
                if (l_size < 0)                                                          \
                {                                                                        \
                    goto cleanup;                                                        \
                }                                                                        \
                expected_crc32 = node->checksum;                                         \
                calculated_crc32 = rc_crc32(0, content, l_size);                         \
                if (calculated_crc32 != expected_crc32)                                  \
                {                                                                        \
                    reason = malloc(strlen(REASON_CHECKSUM_MISMATCH) + 1);               \
                    strcpy(reason, REASON_CHECKSUM_MISMATCH);                            \
                    if (func_switch & DRIFT_DETECT)                                      \
                    {                                                                    \
                        action = malloc(strlen(ACTION_NOTIFIED) + 1);                    \
                        strcpy(action, ACTION_NOTIFIED);                                 \
                        send_alert(pre_data.real_path, exec_str, reason,                 \
                                   action, calculated_crc32, expected_crc32);            \
                    }                                                                    \
                    else if (func_switch & DRIFT_PREVENT)                                \
                    {                                                                    \
                        block_flag = 1;                                                  \
                        action = malloc(strlen(ACTION_BLOCKED) + 1);                     \
                        strcpy(action, ACTION_BLOCKED);                                  \
                        send_alert(pre_data.real_path, exec_str, reason,                 \
                                   action, calculated_crc32, expected_crc32);            \
                    }                                                                    \
                }                                                                        \
            }                                                                            \
        }                                                                                \
                                                                                         \
        if (func_switch & COMMAND_ON)                                                    \
        {                                                                                \
            getcwd(pwd, sizeof(pwd));                                                    \
            if (strlen(pwd) > 0 && pwd[strlen(pwd) - 1] != '/')                          \
            {                                                                            \
                pwd[strlen(pwd)] = '/';                                                  \
            }                                                                            \
            command_whitelist_entry *command_node = (command_whitelist_entry *)          \
                hash_search(g_command_whitelist_hash,                                    \
                            args, pwd);                                                  \
            if (command_node)                                                            \
            {                                                                            \
                if (!strcmp(pwd, command_node->cwd))                                     \
                {                                                                        \
                    goto cleanup;                                                        \
                }                                                                        \
                reason = malloc(strlen(REASON_COMMAND_CWD_NOT_ALLOW) + 1);               \
                strcpy(reason, REASON_COMMAND_CWD_NOT_ALLOW);                            \
                if (func_switch & COMMAND_DETECT)                                        \
                {                                                                        \
                    action = malloc(strlen(ACTION_NOTIFIED) + 1);                        \
                    strcpy(action, ACTION_NOTIFIED);                                     \
                    send_alert(args, exec_str, reason,                                   \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
                else if (func_switch & COMMAND_PREVENT)                                  \
                {                                                                        \
                    block_flag = 1;                                                      \
                    action = malloc(strlen(ACTION_BLOCKED) + 1);                         \
                    strcpy(action, ACTION_BLOCKED);                                      \
                    send_alert(args, exec_str, reason,                                   \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
            }                                                                            \
            else                                                                         \
            {                                                                            \
                reason = malloc(strlen(REASON_COMMAND_NOT_INT_WHITELIST) + 1);           \
                strcpy(reason, REASON_COMMAND_NOT_INT_WHITELIST);                        \
                if (func_switch & COMMAND_DETECT)                                        \
                {                                                                        \
                    action = malloc(strlen(ACTION_NOTIFIED) + 1);                        \
                    strcpy(action, ACTION_NOTIFIED);                                     \
                    send_alert(args, exec_str, reason,                                   \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
                else if (func_switch & COMMAND_PREVENT)                                  \
                {                                                                        \
                    block_flag = 1;                                                      \
                    action = malloc(strlen(ACTION_BLOCKED) + 1);                         \
                    strcpy(action, ACTION_BLOCKED);                                      \
                    send_alert(args, exec_str, reason,                                   \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
            }                                                                            \
        }                                                                                \
    cleanup:                                                                             \
        free(content);                                                                   \
        free(reason);                                                                    \
        free(action);                                                                    \
        if (drift_prevent_teardown_log() != 0)                                           \
        {                                                                                \
            drift_prevent_write_log(WARN, "Failed to properly teardown log: %s\n",       \
                                    strerror(errno));                                    \
            errno = 0;                                                                   \
        }                                                                                \
        if (block_flag)                                                                  \
        {                                                                                \
            errno = EACCES;                                                              \
            return errno;                                                                \
        }                                                                                \
    old_ret:                                                                             \
        old_##exec_name = dlsym(RTLD_NEXT, exec_str);                                    \
        return old_##exec_name(ret_str);                                                 \
    }

#else

#define CHECKPROCESS(exec_str, exec_name, file_path, input_str, ret_str)                 \
    typedef ssize_t (*exec_name##_func_t)(input_str);                                    \
    static exec_name##_func_t old_##exec_name = NULL;                                    \
    int exec_name(input_str)                                                             \
    {                                                                                    \
        if(config_err_flag)                                                              \
        {                                                                                \
            drift_prevent_write_log(ERROR, "read config file fail, skip detect %u\n",    \
                        func_switch);                                                    \
           goto old_ret;                                                                 \
        }                                                                                \
        if (drift_prevent_init_log() != 0)                                               \
        {                                                                                \
            drift_prevent_write_log(WARN, "Failed to fully initialize log: %s\n",        \
                                    strerror(errno));                                    \
        }                                                                                \
                                                                                         \
        pre_info pre_data = {""};                                                        \
        char *content = NULL;                                                            \
        char *action = NULL;                                                             \
        char *reason = NULL;                                                             \
        uint32_t expected_crc32 = 0;                                                     \
        uint32_t calculated_crc32 = 0;                                                   \
        if (!func_switch)                                                                \
        {                                                                                \
            goto cleanup;                                                                \
        }                                                                                \
        if (!init_pre_data(file_path, &pre_data))                                        \
        {                                                                                \
            drift_prevent_write_log(ERROR, "Failed to get real path: %s\n",              \
                                    strerror(errno));                                    \
            errno = 0;                                                                   \
        }                                                                                \
        char args[2 * PATH_MAX + 1] = {'\0'};                                            \
        char pwd[PATH_MAX] = {'\0'};                                                     \
        strncpy(args, pre_data.real_path, strlen(pre_data.real_path));                   \
        splice_cmdline(argv, args);                                                      \
        int block_flag = 0;                                                              \
        if (func_switch & DRIFT_ON)                                                      \
        {                                                                                \
            int index = binary_search(g_whitelist, g_whitelist_size, pre_data.real_path);\
            if (index < 0)                                                               \
            {                                                                            \
                reason = malloc(strlen(REASON_NOT_IN_WHITELIST) + 1);                    \
                strcpy(reason, REASON_NOT_IN_WHITELIST);                                 \
                if (func_switch & DRIFT_DETECT)                                          \
                {                                                                        \
                    action = malloc(strlen(ACTION_NOTIFIED) + 1);                        \
                    strcpy(action, ACTION_NOTIFIED);                                     \
                    send_alert(pre_data.real_path, exec_str, reason,                     \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
                else if (func_switch & DRIFT_PREVENT)                                    \
                {                                                                        \
                    block_flag = 1;                                                      \
                    action = malloc(strlen(ACTION_BLOCKED) + 1);                         \
                    strcpy(action, ACTION_BLOCKED);                                      \
                    send_alert(pre_data.real_path, exec_str, reason,                     \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
            }                                                                            \
            else                                                                         \
            {                                                                            \
                long l_size = file_opt(pre_data.real_path, &content);                    \
                if (l_size < 0)                                                          \
                {                                                                        \
                    goto cleanup;                                                        \
                }                                                                        \
                expected_crc32 = g_whitelist[index].checksum;                            \
                calculated_crc32 = rc_crc32(0, content, l_size);                         \
                if (calculated_crc32 != expected_crc32)                                  \
                {                                                                        \
                    reason = malloc(strlen(REASON_CHECKSUM_MISMATCH) + 1);               \
                    strcpy(reason, REASON_CHECKSUM_MISMATCH);                            \
                    if (func_switch & DRIFT_DETECT)                                      \
                    {                                                                    \
                        action = malloc(strlen(ACTION_NOTIFIED) + 1);                    \
                        strcpy(action, ACTION_NOTIFIED);                                 \
                        send_alert(pre_data.real_path, exec_str, reason,                 \
                                   action, calculated_crc32, expected_crc32);            \
                    }                                                                    \
                    else if (func_switch & DRIFT_PREVENT)                                \
                    {                                                                    \
                        block_flag = 1;                                                  \
                        action = malloc(strlen(ACTION_BLOCKED) + 1);                     \
                        strcpy(action, ACTION_BLOCKED);                                  \
                        send_alert(pre_data.real_path, exec_str, reason,                 \
                                   action, calculated_crc32, expected_crc32);            \
                    }                                                                    \
                }                                                                        \
            }                                                                            \
        }                                                                                \
                                                                                         \
        if (func_switch & COMMAND_ON)                                                    \
        {                                                                                \
            getcwd(pwd, sizeof(pwd));                                                    \
            if (strlen(pwd) > 0 && pwd[strlen(pwd) - 1] != '/')                          \
            {                                                                            \
                pwd[strlen(pwd)] = '/';                                                  \
            }                                                                            \
            command_whitelist_entry *command_node = (command_whitelist_entry *)          \
                hash_search(g_command_whitelist_hash,                                    \
                            args, pwd);                                                  \
            if (command_node)                                                            \
            {                                                                            \
                if (!strcmp(pwd, command_node->cwd))                                     \
                {                                                                        \
                    goto cleanup;                                                        \
                }                                                                        \
                reason = malloc(strlen(REASON_COMMAND_CWD_NOT_ALLOW) + 1);               \
                strcpy(reason, REASON_COMMAND_CWD_NOT_ALLOW);                            \
                if (func_switch & COMMAND_DETECT)                                        \
                {                                                                        \
                    action = malloc(strlen(ACTION_NOTIFIED) + 1);                        \
                    strcpy(action, ACTION_NOTIFIED);                                     \
                    send_alert(args, exec_str, reason,                                   \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
                else if (func_switch & COMMAND_PREVENT)                                  \
                {                                                                        \
                    block_flag = 1;                                                      \
                    action = malloc(strlen(ACTION_BLOCKED) + 1);                         \
                    strcpy(action, ACTION_BLOCKED);                                      \
                    send_alert(args, exec_str, reason,                                   \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
            }                                                                            \
            else                                                                         \
            {                                                                            \
                reason = malloc(strlen(REASON_COMMAND_NOT_INT_WHITELIST) + 1);           \
                strcpy(reason, REASON_COMMAND_NOT_INT_WHITELIST);                        \
                if (func_switch & COMMAND_DETECT)                                        \
                {                                                                        \
                    action = malloc(strlen(ACTION_NOTIFIED) + 1);                        \
                    strcpy(action, ACTION_NOTIFIED);                                     \
                    send_alert(args, exec_str, reason,                                   \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
                else if (func_switch & COMMAND_PREVENT)                                  \
                {                                                                        \
                    block_flag = 1;                                                      \
                    action = malloc(strlen(ACTION_BLOCKED) + 1);                         \
                    strcpy(action, ACTION_BLOCKED);                                      \
                    send_alert(args, exec_str, reason,                                   \
                               action, calculated_crc32, expected_crc32);                \
                }                                                                        \
            }                                                                            \
        }                                                                                \
    cleanup:                                                                             \
        free(content);                                                                   \
        free(reason);                                                                    \
        free(action);                                                                    \
        if (drift_prevent_teardown_log() != 0)                                           \
        {                                                                                \
            drift_prevent_write_log(WARN, "Failed to properly teardown log: %s\n",       \
                                    strerror(errno));                                    \
            errno = 0;                                                                   \
        }                                                                                \
        if (block_flag)                                                                  \
        {                                                                                \
            errno = EACCES;                                                              \
            return errno;                                                                \
        }                                                                                \
    old_ret:                                                                             \
        old_##exec_name = dlsym(RTLD_NEXT, exec_str);                                    \
        return old_##exec_name(ret_str);                                                 \
    }

#endif

/*because can't pass VA_ARGS， the functions of execl* all use execve() */
#define CHECKPROCESS_VA(exec_str, exec_name, file_path, input_str, ret_str)       \
    typedef ssize_t (*exec_name##_func_t)(input_str);                             \
    static exec_name##_func_t old_##exec_name = NULL;                             \
    int exec_name(input_str)                                                      \
    {                                                                             \
        va_list args;                                                             \
        va_start(args, arg);                                                      \
                                                                                  \
        char **argv = strings_build(arg, &args);                                  \
        if (!argv || !*argv)                                                      \
        {                                                                         \
            fputs("A NULL argv was passed through an exec system call.", stderr); \
            exit(EXIT_FAILURE);                                                   \
        }                                                                         \
        char *const *envp = va_arg(args, char *const *);                          \
        int ret = envp ? execve(ret_str) : execve(file_path, argv, environ);      \
        va_end(args);                                                             \
        strings_release(argv);                                                    \
        return ret;                                                               \
    }


CHECKPROCESS("execv", execv, path, VA_STR(const char *path, char *const argv[]), VA_STR(pre_data.real_path, argv))
CHECKPROCESS("execvp", execvp, file, VA_STR(const char *file, char *const argv[]), VA_STR(pre_data.real_path, argv))
CHECKPROCESS("execve", execve, filename, VA_STR(const char *filename, char *const argv[], char *const envp[]), VA_STR(pre_data.real_path, argv, envp))

CHECKPROCESS_VA("execl", execl, path, VA_STR(const char *path, const char *arg, ...), VA_STR(path, argv, environ))
CHECKPROCESS_VA("execlp", execlp, file, VA_STR(const char *file, const char *arg, ...), VA_STR(file, argv, environ))
CHECKPROCESS_VA("execle", execle, path, VA_STR(const char *path, const char *arg, ... /*, (char *)0, char *const envp[] */), VA_STR(path, argv, envp))

#ifdef _DEBUG

int main(int argc, char *argv[], char *envp[])
{
    init_whitelist();
    printf("%d\n", sizeof(entry));
    printf("total size : %lu\n", used_size);
    printf("%llu\n", config_used_size);
    printf("%lld\n", PATH_MAX * sizeof(char)*g_whitelist_config.used + g_whitelist_config.size);

    char cmd_args[1000] = {'\0'};
    char filepath[1000] = {'\0'};
    char *arg = NULL;
    printf("Please input the command you want to check: ");

    while(~scanf("%s", filepath)){
        #ifdef _HASH
        entry *node = (entry *)hash_search(g_whitelist_hash, filepath, "0");

        if (node)
        {
            printf("%x\n", node->checksum);
        }
        else
        {
            printf("not found %lu %s\n", strlen(filepath), filepath);
        }
        #endif
    }

    command_whitelist_entry *cmdline_node = (command_whitelist_entry *)hash_search(g_command_whitelist_hash, cmd_args, "/c");
    if (cmdline_node)
    {
        printf("%s\n", cmdline_node->filename_args);
        printf("%s\n", cmdline_node->cwd);
    }
    else
    {
        printf("not find %lu %s\n", strlen(cmd_args), cmd_args);
    }

    finish();
    return 0;
}

#endif