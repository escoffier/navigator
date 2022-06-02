#define _GNU_SOURCE

#include <stdio.h> // stderr
#include <errno.h> // errno
#include <dlfcn.h> // dlsym
#include <string.h> // strdup
#include <stdlib.h> // EXIT_FAILURE
#include <stdarg.h> //va_args
#include <stdint.h> //uint32_t

#include <stddef.h>// offsetof
#include <sys/socket.h> // socket
#include <sys/un.h>// sockaddr_un
#include <unistd.h> // write read close
#include <time.h> // time
#include <linux/limits.h> // PATH_MAX

#include "crc32.c"  // crc32
#include "container_info.c" // get_container_id
#include "log.h"

#define PASSKEY "pass\n"

const char *server_path = "/.tensor/judge.sock";
const int64_t hash_byte_size = 1024;


// static void init() __attribute__((constructor));
// static void finish() __attribute__((destructor));

// static void init()
// {
//     drift_prevent_init_log();
// }

// static void finish() {
//     drift_prevent_teardown_log();
// }

static int send_info_via_socket(const char *msg, ...) {
    drift_prevent_write_log(INFO, "%s-%d msg: %s", __func__, __LINE__, msg);
    int connfd, n;
    struct sockaddr_un server_un;
    char buffer[256];

    connfd = socket(AF_UNIX, SOCK_STREAM, 0);
    bzero((char *)&server_un, sizeof(server_un));
    server_un.sun_family = AF_UNIX;
    strcpy(server_un.sun_path, server_path);
    int size = strlen(server_un.sun_path) + offsetof(struct sockaddr_un, sun_path);

    if(connect(connfd, (struct sockaddr *) &server_un, size) < 0) {
        drift_prevent_write_log(ERROR, "%s-%d errno: %s\n", __func__, __LINE__, strerror(errno));
        return 0;
    }
    n = write(connfd, msg, strlen(msg));
    if (n < 0) {
        close(connfd);
        drift_prevent_write_log(ERROR, "%s-%d errno: %s\n", __func__, __LINE__, strerror(errno));
        return 0;
    }
    //need catch signal or ignore, refer to https://unix.stackexchange.com/questions/509375/what-is-interrupted-system-call
    memset(buffer, 0, sizeof(buffer));
    while((n = read(connfd, buffer, sizeof(buffer))) < 0 && errno ==  EINTR);
    if (n < 0) {
        close(connfd);
        drift_prevent_write_log(ERROR, "%s-%d errno: %d, errstr: %s\n", __func__, __LINE__, errno, strerror(errno));
        return 0;
    }
    close(connfd);
    if(strncmp(buffer, PASSKEY, strlen(PASSKEY)) == 0) {
        return 0;
    }else{
        drift_prevent_write_log(ERROR, "%s-%d buffer: %s len: %d\n", __func__, __LINE__, buffer, strlen(buffer));
        errno = EACCES;
        return -1;
    }
    return 0;
}

static int is_block(const char *container_id , const char *name, const char *path, uint32_t checksum) {
    char buf[512];
    time_t time_now = time(NULL);
    char time_buf[32];
    // 2021-01-19T12:22:46+0100
    strftime(time_buf, 32, "%Y-%m-%dT%H:%M:%S%z", localtime(&time_now));
    sprintf(buf, "%s|%s|%s|%s|%X\n", time_buf, container_id, name, path, checksum);
    return send_info_via_socket(buf);
}

extern char **environ;
#define WHICH_DELIMITER ":"

char * which_path(const char *name, const char *_path, char *result) {

    drift_prevent_write_log(INFO, "%s-%d name: %s, path: %s\n", __func__, __LINE__, name, _path);
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

#define OPENFILEERROR -1
#define READERROR -2
#define MEMORYERROR -3

static int calc_file_crc32(const char *path, uint32_t *checksum)
{
    FILE *fp;
    long l_size;
    uint32_t crc = 0;
    int ret = 0;

    fp = fopen(path, "rb");
    if (!fp)
    {
        drift_prevent_write_log(ERROR,"open failed: %s %s\n", path, strerror(errno));
        return OPENFILEERROR;
    }
    fseek(fp, 0L, SEEK_END);
    l_size = ftell(fp);
    rewind(fp);
    char *buffer = calloc(1, hash_byte_size + 1);
    if (!buffer)
    {
        drift_prevent_write_log(ERROR, "Memory allocation for file content failed: %s\n", strerror(errno));
        ret = MEMORYERROR;
        goto cleanup_file;
    }
    int n = 0;
    if ((n = fread(buffer, 1, hash_byte_size, fp)) < 0)
    {
        drift_prevent_write_log(ERROR, "[%d]File content read failed: %s\n", __LINE__, strerror(errno));
        ret = READERROR;
        goto cleanup_content;
    }

    crc = rc_crc32(0,buffer,n);

    n = 0;
    if (l_size > hash_byte_size)
    {
        rewind(fp);
        fseek(fp, - hash_byte_size, SEEK_END);
        memset(buffer, 0, hash_byte_size);
        if ((n = fread(buffer, 1, hash_byte_size, fp)) < 0)
        {
            drift_prevent_write_log(ERROR, "[%d]File content read failed: %s\n", __LINE__, strerror(errno));
            ret = READERROR;
            goto cleanup_content;
        }
        crc += rc_crc32(0,buffer, n);
    }
    crc += (uint32_t)l_size;
    drift_prevent_write_log(INFO, "[cacl_file_crc32-%d]%s crc32: %X\n", __LINE__, path, crc);
    *checksum = crc;

cleanup_content:
    free(buffer);
    buffer = NULL;
cleanup_file:
    if (fclose(fp) != 0)
    {
        drift_prevent_write_log(ERROR, "could not close file: %s\n", strerror(errno));
    }
    return ret;
}

#define CONTAINID_LEN 64
typedef struct
{
    char real_path[PATH_MAX];
    uint32_t calculated_crc32;
    char container_id[CONTAINID_LEN + 1];
} pre_info;

static int init_pre_data(const char *path, pre_info *pre_data)
{
    int ret = 0;
    pre_data->real_path[0] = '\0';
    pre_data->calculated_crc32 = 0;

    get_container_id(pre_data->container_id, CONTAINID_LEN);
    pre_data->container_id[CONTAINID_LEN] = '\0';

    char *tmppath = realpath(path, pre_data->real_path);
    if(!tmppath){
        drift_prevent_write_log(ERROR, "realpath failed: %s %s\n", path, strerror(errno));
        tmppath = which(path, pre_data->real_path);
        drift_prevent_write_log(INFO, "which: %s\n", pre_data->real_path);
    }

    // calulate crc32
    if(tmppath){
        ret = calc_file_crc32(pre_data->real_path, &(pre_data->calculated_crc32));
    } else {
        ret = OPENFILEERROR;
    }


    return ret;
}

#define VA_STR(...) __VA_ARGS__

#define CHECKPROCESS(exec_str, exec_name, file_path, input_str, ret_str)                \
    typedef ssize_t (*exec_name##_func_t)(input_str);                                   \
    static exec_name##_func_t old_##exec_name = NULL;                                   \
    int exec_name(input_str)                                                            \
    {                                                                                   \
    drift_prevent_init_log();                                                           \
    pre_info pre_data = {""};                                                           \
    int retno = 0;                                                                      \
    if ((retno = init_pre_data(file_path, &pre_data)) != 0)                             \
        {                                                                               \
        drift_prevent_write_log(ERROR, "init data failed: %s %s\n",                     \
                        strerror(errno), file_path);                                    \
            goto old_ret;                                                               \
        }                                                                               \
        if(is_block(pre_data.container_id, exec_str, pre_data.real_path,                \
                    pre_data.calculated_crc32)){                                        \
            drift_prevent_write_log(ERROR, "block: %s %s reterr: %s\n\n",               \
                        exec_str, file_path,strerror(errno));                           \
            drift_prevent_teardown_log();                                               \
            errno = EACCES;                                                             \
            return errno;                                                               \
        }                                                                               \
    old_ret:                                                                            \
        drift_prevent_write_log(INFO, "old way exec_name: %s path: %s\n\n",             \
                exec_str, file_path);                                                   \
        drift_prevent_teardown_log();                                                   \
        old_##exec_name = dlsym(RTLD_NEXT, exec_str);                                   \
        return old_##exec_name(ret_str);                                                \
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

/*because can't pass VA_ARGS， the functions of execl* all use execve() */
#define CHECKPROCESS_VA(exec_str, exec_name, file_path, input_str, ret_str)     \
    typedef ssize_t (*exec_name##_func_t)(input_str);                           \
    static exec_name##_func_t old_##exec_name = NULL;                           \
    int exec_name(input_str)                                                    \
    {                                                                           \
        va_list args;                                                           \
        va_start(args, arg);                                                    \
        char **argv = strings_build(arg, &args);                                \
        if (!argv || !*argv)                                                    \
        {                                                                       \
            drift_prevent_write_log(ERROR,                                      \
                    "A NULL argv was passed through an exec system call.",      \
                    stderr);                                                    \
            exit(EXIT_FAILURE);                                                 \
        }                                                                       \
        char *const *envp = va_arg(args, char *const *);                        \
        int ret = envp ? execve(ret_str) : execve(file_path, argv, environ);    \
        va_end(args);                                                           \
        strings_release(argv);                                                  \
        return ret;                                                             \
    }


CHECKPROCESS("execv", execv, path, VA_STR(const char *path, char *const argv[]), VA_STR(pre_data.real_path, argv))
CHECKPROCESS("execvp", execvp, file, VA_STR(const char *file, char *const argv[]), VA_STR(pre_data.real_path, argv))
CHECKPROCESS("execve", execve, filename, VA_STR(const char *filename, char *const argv[], char *const envp[]), VA_STR(pre_data.real_path, argv, envp))

CHECKPROCESS_VA("execl", execl, path, VA_STR(const char *path, const char *arg, ...), VA_STR(path, argv, environ))
CHECKPROCESS_VA("execlp", execlp, file, VA_STR(const char *file, const char *arg, ...), VA_STR(file, argv, environ))
CHECKPROCESS_VA("execle", execle, path, VA_STR(const char *path, const char *arg, ... /*, (char *)0, char *const envp[] */), VA_STR(path, argv, envp))


#ifdef _DEBUG
CHECKPROCESS("exectest", exectest, path, VA_STR(const char *path, char *const argv[]), VA_STR(path, argv))
int main()
{
    printf("start test\n");
    exectest("dpkg-split", NULL);
    printf("end test\n");
    return 0;
}
#endif