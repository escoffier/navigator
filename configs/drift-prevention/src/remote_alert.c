#include <string.h>         // memcpy, memset
#include <sys/socket.h>     // socket, connect
#include <netinet/in.h>     // struct sockaddr_in, struct sockaddr
#include <netdb.h>          // struct hostent, gethostbyname
#include <stdlib.h>         // malloc, free
#include <stdio.h>          // printf, sprintf
#include <unistd.h>         // read, write, close
#include <stdint.h>         // uint32_t
#include <limits.h>         // PATH_MAX
#include <sys/time.h>       // struct timeval

#include "log.h"

static const char* REASON_CHECKSUM_MISMATCH = "ChecksumMismatch";
static const char* REASON_NOT_IN_WHITELIST = "NotInWhitelist";

static const char* ACTION_NOTIFIED = "Notified";
static const char* ACTION_BLOCKED = "Blocked";

typedef struct alert_t {
    char filepath[PATH_MAX];
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

static int send_request(const char* host, int port, const char* method, const char* path, const char* body, char* response, const int resp_size) {
    // function based on https://stackoverflow.com/a/22135885

    int return_code = 1;

    // Prepare message

    char *message_fmt = "%s %s HTTP/1.1\r\n" \
                        "Host: %s\r\n" \
                        "Connection: close\r\n" // Need to specify this header in HTTP/1.1 otherwise we will hang, https://stackoverflow.com/a/17438094
                        "Content-Length: %s\r\n" \
                        "Content-Type: application/json\r\n" \
                        "\r\n" \
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
    if (!message) {
        drift_prevent_write_log(ERROR, "When allocating buffer for message to send: %s\n", strerror(errno)); 
        goto cleanup_msg;
    }

    sprintf(message, message_fmt, method, path, host, content_length_str, body);

    // Prepare socket

    const int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        drift_prevent_write_log(ERROR, "When creating socket: %s\n", strerror(errno)); 
        goto cleanup_sock;
    }

    struct hostent *server = gethostbyname(host);
    if (server == NULL) {
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

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        drift_prevent_write_log(ERROR, "When connecting socket: %s\n", strerror(errno)); 
        goto cleanup_sock;
    }

    // Send request

    int sent = 0;

    do {
        const int nbytes = write(sockfd, message + sent, message_size - sent);
        if (nbytes < 0) {
            drift_prevent_write_log(ERROR, "When writing to socket: %s\n", strerror(errno)); 
            goto cleanup_sock;
        }
        if (nbytes == 0) {
            break;
        }
        sent += nbytes;
    } while (sent < message_size);

    // Receive response

    memset(response, 0, sizeof(response));
    int received = 0;

    do {
        const int nbytes = read(sockfd, response + received, resp_size - received);
        if (nbytes < 0) {
            drift_prevent_write_log(ERROR, "When reading from socket. \
                              Received the following bytes up to this point: \n%s\n---\n", response); 
            goto cleanup_sock;
        }
        if (nbytes == 0) {
            break;
        }
        received += nbytes;
    } while (received < resp_size);

    if (received == resp_size) {
        drift_prevent_write_log(WARN, "Buffer too small, response was truncated\n"); 
    }

    // Done

    return_code = 0;

cleanup_sock:
    close(sockfd);
cleanup_msg:
    free(message);

    return return_code;
}

static int raise_remote_alert(const char* host, int port, const struct alert_t *alert) {

    int return_code = 1;

    static const char *method = "POST";
    static const char *path = "/api/v1/driftPrevention/raiseAlert";

    // Format body

    char *body = NULL;

    if (strcmp(alert->reason, REASON_CHECKSUM_MISMATCH) == 0) {
        const char *body_fmt = "{"
            "\"podnamespace\": \"%s\","
            "\"podname\": \"%s\","
            "\"poduid\": \"%s\","
            "\"filepath\": \"%s\","
            "\"crc32Expected\": %u,"
            "\"crc32Actual\": %u,"
            "\"reason\": \"%s\","
            "\"action\": \"%s\","
            "\"syscall\": \"%s\"}";

        const int max_body_size = 
            strlen(body_fmt) +
            strlen(alert->podnamespace) +
            strlen(alert->podname) +
            strlen(alert->poduid) +
            strlen(alert->filepath) +
            sizeof(uint32_t) +
            sizeof(uint32_t) +
            strlen(alert->reason) +
            strlen(alert->action) +
            strlen(alert->syscall);

        body = malloc(max_body_size);
        if (!body) {
            perror("When allocating buffer for body");
            goto cleanup;
        }

        sprintf(body, body_fmt,
            alert->podnamespace,
            alert->podname,
            alert->poduid,
            alert->filepath,
            alert->crc32_expected,
            alert->crc32_actual,
            alert->reason,
            alert->action,
            alert->syscall);
        
    } else if (strcmp(alert->reason, REASON_NOT_IN_WHITELIST) == 0) {
        const char *body_fmt = "{"
            "\"podnamespace\": \"%s\","
            "\"podname\": \"%s\","
            "\"poduid\": \"%s\","
            "\"filepath\": \"%s\","
            "\"reason\": \"%s\","
            "\"action\": \"%s\","
            "\"syscall\": \"%s\"}";

        const int max_body_size = 
            strlen(body_fmt) +
            strlen(alert->podnamespace) +
            strlen(alert->podname) +
            strlen(alert->poduid) +
            strlen(alert->filepath) +
            strlen(alert->reason) +
            strlen(alert->action) +
            strlen(alert->syscall);

        body = malloc(max_body_size);
        if (!body) {
            perror("When allocating buffer for body");
            goto cleanup;
        }

        sprintf(body, body_fmt,
            alert->podnamespace,
            alert->podname,
            alert->poduid,
            alert->filepath,
            alert->reason,
            alert->action,
            alert->syscall);
    }


    // Send request

    char response[4096]; // 4096 for response should be large enough, we trust the target host
    const int resp_size = sizeof(response) - 1;

    if (send_request(host, port, method, path, body, response, resp_size)) {
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

    if (sc == '1' || sc == '3') {
        drift_prevent_write_log(ERROR, "Failed to raise alert - unhandled HTTP status code, " \
            "this simple client doesn't handle 1xx and 3xx status codes: \n%s\n---\n", resp_copy);
        goto cleanup;
    }

    if (sc == '4' || sc == '5') {
        drift_prevent_write_log(ERROR, "Failed to raise alert - status code: \n%s\n---\n", resp_copy); 
        goto cleanup;
    }

    if (sc != '2') {
        drift_prevent_write_log(ERROR, "Failed to raise alert - unexpected status code: \n%s\n---\n", resp_copy); 
        goto cleanup;
    }

    // Done

    return_code = 0;

    drift_prevent_write_log(INFO, "Alert with action %s and reason %s raised to collector successfuly\n", alert->action, alert->reason);

cleanup:
    free(body);
    return return_code;
}

// Uncomment int main() to test this unit
//
// For simple test server:
//while true; do { echo -e 'HTTP/1.1 200 OK\r\n'; } | nc -l 8080 -N; done

// int main() {
//     char *host = "localhost";
//     int port = 8889;
//     struct alert_t my_alert;
//     strcpy(my_alert.filepath, "/some/file/path");
//     strcpy(my_alert.podname, "this-is-podracing");
//     strcpy(my_alert.syscall, "execveeeeeeeeeeee");
//     // strcpy(my_alert.reason, REASON_CHECKSUM_MISMATCH);
//     strcpy(my_alert.reason, REASON_NOT_IN_WHITELIST);
//     strcpy(my_alert.action, ACTION_BLOCKED);
//     my_alert.crc32_expected = 1337;
//     my_alert.crc32_actual = 2137;
//     if (raise_remote_alert(host, port, &my_alert)) {
//         return 1;
//     }
//     return 0;
// }