#include <string.h>     // memcpy, memset
#include <sys/socket.h> // socket, connect
#include <netinet/in.h> // struct sockaddr_in, struct sockaddr
#include <netdb.h>      // struct hostent, gethostbyname
#include <stdlib.h>     // malloc, free
#include <stdio.h>      // printf, sprintf
#include <unistd.h>     // read, write, close
#include <stdint.h>     // uint32_t
#include <limits.h>     // PATH_MAX
#include <sys/time.h>   // struct timeval
#include <errno.h>      // strerror(errno)

// openssl libs
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "log.h"

static const char *REASON_CHECKSUM_MISMATCH = "ChecksumMismatch";
static const char *REASON_NOT_IN_WHITELIST = "NotInWhitelist";
static const char *REASON_COMMAND_NOT_INT_WHITELIST = "CommandNotInWhitelist";
static const char *REASON_COMMAND_CWD_NOT_ALLOW = "CommandPathNotAllow";
static const char *REASON_CHECKSUM_MISMATCH_CN = "文件校验值错误";
static const char *REASON_NOT_IN_WHITELIST_CN = "文件不在白名单中";
static const char *REASON_COMMAND_NOT_INT_WHITELIST_CN = "命令不在白名單中";
static const char *REASON_COMMAND_CWD_NOT_ALLOW_CN = "命令cwd不在白名單中";

static const char *ACTION_NOTIFIED = "Notified";
static const char *ACTION_BLOCKED = "Blocked";
static const char *ACTION_NOTIFIED_CN = "告警";
static const char *ACTION_BLOCKED_CN = "阻断";

typedef struct alert_t
{
    char filepath[2 * PATH_MAX];
    char podnamespace[256];
    char podname[256];
    char poduid[256];
    char syscall[256];
    char reason[64];
    char action[64];
    // char *syscall_args[];    // TODO
    uint32_t crc32_expected;
    uint32_t crc32_actual;
} alert_t;

static char const CAFile[] = "/auth/ca/tls.crt";
static char const CertFile[] = "/auth/client/tls.crt";
static const char KeyFile[] = "/auth/client/tls.key";

static int generate_random_uuid(char *uuid)
{
    // generate 19 digits
    srand((unsigned)time(NULL));

    // Max for int64: 9223372036854775807
    // start with 1~8
    unsigned int rand_num = rand() % 8 + 1;
    uuid[0] = '0' + rand_num;
    int pid = getpid();

    int uuid_len = 1;
    int i = 0;
    for (i = 0; i < 6 && uuid_len < 17; i++)
    {
        rand_num = (rand() + pid) % 1000;
        uuid_len += sprintf(uuid + uuid_len, "%03d", rand_num);
    }
    return 0;
}

// ssl reference https://stackoverflow.com/questions/11705815/client-and-server-communication-using-ssl-c-c-ssl-protocol-dont-works

static int load_certificates(SSL_CTX *ctx, const char *ca_file, const char *cert_file, const char *key_file)
{

    int ret = 0;
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) <= 0)
    {
        ret = 1;
        goto out;
    } //https://www.cnblogs.com/etangyushan/p/3679457.html

    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0)
    {
        ret = 1;
        goto out;
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0)
    {
        ret = 1;
        goto out;
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        ret = 1;
        goto out;
    }
out:
    return ret;
}

static SSL_CTX *init_ctx(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();    /* Load cryptos, et.al. */
    SSL_load_error_strings();        /* Bring in and register error messages */
    method = SSLv23_client_method(); /* Create new client-method instance */
    ctx = SSL_CTX_new(method);       /* Create new context */
    if (ctx == NULL)
    {
        return NULL;
    }
    return ctx;
}

static int send_https_request(const char *host, int port, const char *method, const char *path, const char *body, char *response, const int resp_size)
{

    // function based on https://stackoverflow.com/a/22135885

    int return_code = 1;

    // Prepare message

    char *message_fmt = "%s %s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Connection: close\r\n" // Need to specify this header in HTTP/1.1 otherwise we will hang, https://stackoverflow.com/a/17438094
                        "Content-Length: %s\r\n"
                        "Content-Type: application/json\r\n"
                        "\r\n"
                        "%s";

    const int content_length = strlen(body);
    char content_length_str[20];

    sprintf(content_length_str, "%d", content_length);

    // format characters like '%s' are treated as 2 chars, so we overestimate message_size
    // by a little bit, but whatever.
    const int message_size = strlen(message_fmt) +
                             strlen(method) +
                             strlen(path) +
                             strlen(host) +
                             strlen(content_length_str) +
                             strlen(body);

    char *message = malloc(message_size);
    if (!message)
    {
        drift_prevent_write_log(ERROR, "When allocating buffer for message to send: %s\n", strerror(errno));
        goto cleanup_msg;
    }

    sprintf(message, message_fmt, method, path, host, content_length_str, body);

    // openssl library init
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    int err;

    ctx = init_ctx();

    if (!ctx)
    {
        drift_prevent_write_log(ERROR, "SSL_CTX_new failed: %s\n", strerror(errno));
        goto cleanup_ctx;
    }

    if (load_certificates(ctx, CAFile, CertFile, KeyFile))
    {
        drift_prevent_write_log(ERROR, "When load cert : %s\n", strerror(errno));
        goto cleanup_ctx;
    }

    // get hostname
    const int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        drift_prevent_write_log(ERROR, "When creating socket: %s\n", strerror(errno));
        goto cleanup_sock;
    }
    struct hostent *server = gethostbyname(host);
    if (server == NULL)
    {
        drift_prevent_write_log(ERROR, "When getting host by name: %s\n", strerror(errno));
        goto cleanup_sock;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);

    // Set timeouts

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval));

    // Connect

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        drift_prevent_write_log(ERROR, "When connecting socket: %s\n", strerror(errno));
        goto cleanup_sock;
    }

    ssl = SSL_new(ctx);
    if (!ssl)
    {
        drift_prevent_write_log(ERROR, "SSL_new failed: %s\n", strerror(errno));
        goto cleanup_ssl;
    }

    SSL_set_fd(ssl, sockfd);
    err = SSL_connect(ssl);
    if (err < 0)
    {
        drift_prevent_write_log(ERROR, "SSL_connect failed: %s\n", strerror(err));
        goto cleanup_ssl;
    }

    // Uncomment print ssl cert

    // char *str;
    // X509 *server_cert;
    // server_cert = SSL_get_peer_certificate(ssl);
    // printf("server's certificate was received:\n\n");
    // if(server_cert == NULL){
    //     printf("server_cert is null\n");
    //     goto cleanup_ssl;
    // }
    // str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    // printf(" subject: %s\n", str);
    // str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    // printf(" issuer: %s\n\n", str);
    // X509_free(server_cert);

    // send http request
    int sent = 0;

    do
    {
        const int nbytes = SSL_write(ssl, message + sent, message_size - sent);
        if (nbytes < 0)
        {
            drift_prevent_write_log(ERROR, "When writing to socket: %s\n", strerror(errno));
            goto cleanup_sock;
        }
        if (nbytes == 0)
        {
            break;
        }
        sent += nbytes;
    } while (sent < message_size);

    // Receive response

    memset(response, 0, resp_size);
    int received = 0;

    do
    {
        const int nbytes = SSL_read(ssl, response + received, resp_size - received);
        if (nbytes < 0)
        {
            drift_prevent_write_log(ERROR, "When reading from socket. \
                              Received the following bytes up to this point: \n%s\n---\n",
                                    response);
            goto cleanup_sock;
        }
        if (nbytes == 0)
        {
            break;
        }
        received += nbytes;
    } while (received < resp_size);

    if (received == resp_size)
    {
        drift_prevent_write_log(WARN, "Buffer too small, response was truncated\n");
    }

    // Done

    return_code = 0;

cleanup_ssl:
    SSL_shutdown(ssl);
    SSL_free(ssl);
cleanup_sock:
    close(sockfd);
cleanup_ctx:
    SSL_CTX_free(ctx);
cleanup_msg:
    free(message);
out:
    return return_code;
}

static int raise_remote_alert(const char *host, int port, const struct alert_t *alert)
{

    int return_code = 1;

    static const char *method = "POST";
    static const char *path = "/eventcenter/sendNotification";
    time_t time_now = time(NULL);

    char uuid[20] = {'\0'};
    generate_random_uuid(uuid);

    // Format body

    char *body = NULL;

    if (strcmp(alert->reason, REASON_CHECKSUM_MISMATCH) == 0)
    {
        const char *body_fmt =
            "{\"RuleKey\": {"
            "\"Name\": \"driftPrevention\","
            "\"Module\": \"ContainerSecurity\","
            "\"Category\": \"driftPrevention\"}"
            ",\"NotifyContext\": {"
            "\"Namespace\": \"%s\","
            "\"PodName\": \"%s\","
            "\"PodUID\": \"%s\","
            "\"Cluster\":\"default\","
            "\"CustomKV\": ["
            "{\"KVHash\": {"
            "\"en\":{"
            "\"Key\": \"filepath\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\":{"
            "\"Key\": \"文件路径\","
            "\"Value\": \"%s\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\":{"
            "\"Key\": \"crc32Expected\","
            "\"Value\": \"%d\""
            "},"
            "\"zh\": {"
            "\"Key\": \"预期的校验值\","
            "\"Value\": \"%d\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\":{"
            "\"Key\": \"crc32Actual\","
            "\"Value\": \"%d\""
            "},"
            "\"zh\": {"
            "\"Key\": \"实际的校验值\","
            "\"Value\": \"%d\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\":{"
            "\"Key\": \"reason\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\": {"
            "\"Key\": \"原因\","
            "\"Value\": \"%s\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\": {"
            "\"Key\": \"action\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\":{"
            "\"Key\": \"行为\","
            "\"Value\": \"%s\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\": {"
            "\"Key\": \"syscall\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\": {"
            "\"Key\": \"系统调用\","
            "\"Value\": \"%s\""
            "}}}]}"
            ",\"Timestamp\": %d,"
            "\"UUID\": %s}";

        const int max_body_size =
            strlen(body_fmt) +
            strlen(alert->podnamespace) +
            strlen(alert->podname) +
            strlen(alert->poduid) +
            2 * strlen(alert->filepath) +
            2 * sizeof(uint32_t) +
            2 * sizeof(uint32_t) +
            2 * strlen(alert->reason) +
            strlen(alert->action) +
            strlen(REASON_CHECKSUM_MISMATCH_CN) +
            2 * strlen(alert->syscall) +
            sizeof(int) +
            strlen(uuid);

        body = malloc(max_body_size);
        if (!body)
        {
            perror("When allocating buffer for body");
            goto cleanup;
        }

        sprintf(body, body_fmt,
                alert->podnamespace,
                alert->podname,
                alert->poduid,
                alert->filepath,
                alert->filepath,
                alert->crc32_expected,
                alert->crc32_expected,
                alert->crc32_actual,
                alert->crc32_actual,
                alert->reason,
                REASON_CHECKSUM_MISMATCH_CN,
                alert->action,
                strcmp(alert->action, ACTION_BLOCKED) ? ACTION_NOTIFIED_CN : ACTION_BLOCKED_CN,
                alert->syscall,
                alert->syscall,
                time(&time_now),
                uuid);
    }
    else if (strcmp(alert->reason, REASON_NOT_IN_WHITELIST) == 0)
    {
        const char *body_fmt =
            "{\"RuleKey\": {"
            "\"Name\": \"driftPrevention\","
            "\"Module\": \"ContainerSecurity\","
            "\"Category\": \"driftPrevention\"}"
            ",\"NotifyContext\": {"
            "\"Namespace\": \"%s\","
            "\"PodName\": \"%s\","
            "\"PodUID\": \"%s\","
            "\"Cluster\":\"default\","
            "\"CustomKV\": ["
            "{\"KVHash\": {"
            "\"en\":{"
            "\"Key\": \"filepath\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\":{"
            "\"Key\": \"文件路径\","
            "\"Value\": \"%s\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\":{"
            "\"Key\": \"reason\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\":{"
            "\"Key\": \"原因\","
            "\"Value\": \"%s\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\": {"
            "\"Key\": \"action\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\":{"
            "\"Key\": \"行为\","
            "\"Value\": \"%s\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\": {"
            "\"Key\": \"syscall\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\": {"
            "\"Key\": \"系统调用\","
            "\"Value\": \"%s\""
            "}}}]}"
            ",\"Timestamp\": %d,"
            "\"UUID\": %s}";

        const int max_body_size =
            strlen(body_fmt) +
            strlen(alert->podnamespace) +
            strlen(alert->podname) +
            strlen(alert->poduid) +
            2 * strlen(alert->filepath) +
            strlen(alert->reason) +
            strlen(REASON_NOT_IN_WHITELIST_CN) +
            2 * strlen(alert->action) +
            2 * strlen(alert->syscall) +
            sizeof(int) + //timestamp
            strlen(uuid);

        body = malloc(max_body_size);
        if (!body)
        {
            perror("When allocating buffer for body");
            goto cleanup;
        }

        sprintf(body, body_fmt,
                alert->podnamespace,
                alert->podname,
                alert->poduid,
                alert->filepath,
                alert->filepath,
                alert->reason,
                REASON_NOT_IN_WHITELIST_CN,
                alert->action,
                strcmp(alert->action, ACTION_BLOCKED) ? ACTION_NOTIFIED_CN : ACTION_BLOCKED_CN,
                alert->syscall,
                alert->syscall,
                time(&time_now),
                uuid);
    }
    else if (strcmp(alert->reason, REASON_COMMAND_NOT_INT_WHITELIST) == 0)
    {
        const char *body_fmt =
            "{\"RuleKey\": {"
            "\"Name\": \"driftPrevention\","
            "\"Module\": \"ContainerSecurity\","
            "\"Category\": \"driftPrevention\"}"
            ",\"NotifyContext\": {"
            "\"Namespace\": \"%s\","
            "\"PodName\": \"%s\","
            "\"PodUID\": \"%s\","
            "\"Cluster\":\"default\","
            "\"CustomKV\": ["
            "{\"KVHash\": {"
            "\"en\":{"
            "\"Key\": \"filepath\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\":{"
            "\"Key\": \"文件路径\","
            "\"Value\": \"%s\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\":{"
            "\"Key\": \"reason\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\":{"
            "\"Key\": \"原因\","
            "\"Value\": \"%s\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\": {"
            "\"Key\": \"action\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\":{"
            "\"Key\": \"行为\","
            "\"Value\": \"%s\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\": {"
            "\"Key\": \"syscall\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\": {"
            "\"Key\": \"系统调用\","
            "\"Value\": \"%s\""
            "}}}]}"
            ",\"Timestamp\": %d,"
            "\"UUID\": %s}";

        const int max_body_size =
            strlen(body_fmt) +
            strlen(alert->podnamespace) +
            strlen(alert->podname) +
            strlen(alert->poduid) +
            2 * strlen(alert->filepath) +
            strlen(alert->reason) +
            strlen(REASON_COMMAND_NOT_INT_WHITELIST_CN) +
            2 * strlen(alert->action) +
            2 * strlen(alert->syscall) +
            sizeof(int) + //timestamp
            strlen(uuid);

        body = malloc(max_body_size);
        if (!body)
        {
            perror("When allocating buffer for body");
            goto cleanup;
        }

        sprintf(body, body_fmt,
                alert->podnamespace,
                alert->podname,
                alert->poduid,
                alert->filepath,
                alert->filepath,
                alert->reason,
                REASON_COMMAND_NOT_INT_WHITELIST_CN,
                alert->action,
                strcmp(alert->action, ACTION_BLOCKED) ? ACTION_NOTIFIED_CN : ACTION_BLOCKED_CN,
                alert->syscall,
                alert->syscall,
                time(&time_now),
                uuid);
    }
    else if (strcmp(alert->reason, REASON_COMMAND_CWD_NOT_ALLOW) == 0)
    {
        const char *body_fmt =
            "{\"RuleKey\": {"
            "\"Name\": \"driftPrevention\","
            "\"Module\": \"ContainerSecurity\","
            "\"Category\": \"driftPrevention\"}"
            ",\"NotifyContext\": {"
            "\"Namespace\": \"%s\","
            "\"PodName\": \"%s\","
            "\"PodUID\": \"%s\","
            "\"Cluster\":\"default\","
            "\"CustomKV\": ["
            "{\"KVHash\": {"
            "\"en\":{"
            "\"Key\": \"filepath\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\":{"
            "\"Key\": \"文件路径\","
            "\"Value\": \"%s\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\":{"
            "\"Key\": \"reason\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\":{"
            "\"Key\": \"原因\","
            "\"Value\": \"%s\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\": {"
            "\"Key\": \"action\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\":{"
            "\"Key\": \"行为\","
            "\"Value\": \"%s\""
            "}}},"
            "{\"KVHash\": {"
            "\"en\": {"
            "\"Key\": \"syscall\","
            "\"Value\": \"%s\""
            "},"
            "\"zh\": {"
            "\"Key\": \"系统调用\","
            "\"Value\": \"%s\""
            "}}}]}"
            ",\"Timestamp\": %d,"
            "\"UUID\": %s}";

        const int max_body_size =
            strlen(body_fmt) +
            strlen(alert->podnamespace) +
            strlen(alert->podname) +
            strlen(alert->poduid) +
            2 * strlen(alert->filepath) +
            strlen(alert->reason) +
            strlen(REASON_COMMAND_CWD_NOT_ALLOW_CN) +
            2 * strlen(alert->action) +
            2 * strlen(alert->syscall) +
            sizeof(int) + //timestamp
            strlen(uuid);

        body = malloc(max_body_size);
        if (!body)
        {
            perror("When allocating buffer for body");
            goto cleanup;
        }

        sprintf(body, body_fmt,
                alert->podnamespace,
                alert->podname,
                alert->poduid,
                alert->filepath,
                alert->filepath,
                alert->reason,
                REASON_COMMAND_CWD_NOT_ALLOW_CN,
                alert->action,
                strcmp(alert->action, ACTION_BLOCKED) ? ACTION_NOTIFIED_CN : ACTION_BLOCKED_CN,
                alert->syscall,
                alert->syscall,
                time(&time_now),
                uuid);
    }
    else
    {
        drift_prevent_write_log(WARN, "Not match any reason\n");
        goto finish;
    }

    // Send request

    char response[4096]; // 4096 for response should be large enough, we trust the target host
    const int resp_size = sizeof(response) - 1;

    if (send_https_request(host, port, method, path, body, response, resp_size))
    {
        goto cleanup;
    }

    // Parse response from server

    char resp_copy[4096];
    strcpy(resp_copy, response);

    char *tokens;
    tokens = strtok(response, " ");
    char *status_code_str = strtok(NULL, " "); // advance to 2nd token (status code integer)
    const int status_code = atoi(status_code_str);

    const char sc = status_code_str[0];

    // Handle response status code

    if (sc == '1' || sc == '3')
    {
        drift_prevent_write_log(ERROR, "Failed to raise alert - unhandled HTTP status code, "
                                       "this simple client doesn't handle 1xx and 3xx status codes: \n%s\n---\n",
                                resp_copy);
        goto cleanup;
    }

    if (sc == '4' || sc == '5')
    {
        drift_prevent_write_log(ERROR, "Failed to raise alert - status code: \n%s\n---\n", resp_copy);
        goto cleanup;
    }

    if (sc != '2')
    {
        drift_prevent_write_log(ERROR, "Failed to raise alert - unexpected status code: \n%s\n---\n", resp_copy);
        goto cleanup;
    }

    // Done

    return_code = 0;

    drift_prevent_write_log(INFO, "Alert with action %s and reason %s raised to collector successfuly\n", alert->action, alert->reason);

cleanup:
    free(body);
finish:
    return return_code;
}

// Uncomment int main() to test this unit
//
// For simple test server:
// while true; do { echo -e 'HTTP/1.1 200 OK\r\n'; } | nc -l 8080 -N; done

// int main() {
//     char *host = "moesedeMacBook-Pro.local";
//     char* podname = getenv("MY_POD_NAME");
//     char* poduid = getenv("MY_POD_UID");
//     char* podnamespace = getenv("MY_POD_NAMESPACE");

//     char unknow_str[] = "unknown";
//     if(!podname){
//         drift_prevent_write_log(ERROR, "Env var MY_POD_NAME not found: %s\n", strerror(errno));
//         podname = unknow_str;
//     }

//     if(!poduid){
//         drift_prevent_write_log(ERROR, "Env var MY_POD_UID not found: %s\n", strerror(errno));
//         poduid = unknow_str;
//     }

//     if(!podnamespace){
//         drift_prevent_write_log(ERROR, "Env var MY_POD_NAMESPACE not found: %s\n", strerror(errno));
//         podnamespace = unknow_str;
//     }

//     drift_prevent_init_log();
//     int port = 8080;
//     struct alert_t my_alert;
//     strcpy(my_alert.podname, podname);
//     strcpy(my_alert.poduid, poduid);
//     strcpy(my_alert.podnamespace, podnamespace);
//     strcpy(my_alert.filepath, "/some/file/path");
//     strcpy(my_alert.syscall, "execveeeeeeeeeeee");
//     strcpy(my_alert.reason, REASON_CHECKSUM_MISMATCH);
//     // strcpy(my_alert.reason, REASON_NOT_IN_WHITELIST);
//     strcpy(my_alert.action, ACTION_BLOCKED);
//     my_alert.crc32_expected = 1337;
//     my_alert.crc32_actual = 2137;
//     if (raise_remote_alert(host, port, &my_alert)) {
//         return 1;
//     }

//     drift_prevent_teardown_log();
//     return 0;
// }
