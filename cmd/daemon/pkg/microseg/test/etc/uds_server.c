/*
 * File server.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_NAME "/tmp/echo.socket"
#define BUFFER_SIZE 1200

int main(int argc, char *argv[]) {
  struct sockaddr_un name;
  int down_flag = 0;
  int ret;
  int connection_socket;
  int data_socket;
  int result;
  char buffer[BUFFER_SIZE];

  unlink(SOCKET_NAME);

  /* Create local socket. */

  connection_socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (connection_socket == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  /*
   * For portability clear the whole structure, since some
   * implementations have additional (nonstandard) fields in
   * the structure.
   */

  memset(&name, 0, sizeof(name));

  /* Bind socket to socket name. */

  name.sun_family = AF_UNIX;
  strncpy(name.sun_path, SOCKET_NAME, sizeof(name.sun_path) - 1);

  ret = bind(connection_socket, (const struct sockaddr *)&name, sizeof(name));
  if (ret == -1) {
    perror("bind");
    exit(EXIT_FAILURE);
  }

  /*
   * Prepare for accepting connections. The backlog size is set
   * to 20. So while one request is being processed other requests
   * can be waiting.
   */

  ret = listen(connection_socket, 20);
  if (ret == -1) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  /* This is the main loop for handling connections. */

  for (;;) {

    /* Wait for incoming connection. */

    data_socket = accept(connection_socket, NULL, NULL);
    if (data_socket == -1) {
      printf("accept");
      perror("accept");
      exit(EXIT_FAILURE);
    }

    printf("accept new conn\n");

    ssize_t n;
    // while ((n = read(data_socket, buffer, sizeof(buffer))) > 0) {
    //   buffer[sizeof(buffer) - 1] = 0;
    //   printf("recived data: %s\n", buffer);
    //   memset(buffer, 0, sizeof(buffer));
    // }
    if ((n = read(data_socket, buffer, sizeof(buffer))) > 0) {
      buffer[sizeof(buffer) - 1] = 0;
      printf("recived data: %s\n", buffer);
      memset(buffer, 0, sizeof(buffer));
    }

    printf("response 1\n");
    if (n < 0) {
      printf("read err\n");
      perror("read");
      exit(EXIT_FAILURE);
    }

    printf("response\n");
    char *reponse = "{\"status\": 11}";
    ret = write(data_socket, reponse, strlen(reponse));
    if (ret == -1) {
      printf("write err");
      perror("write");
      exit(EXIT_FAILURE);
    }

    /* Close socket. */

    // close(data_socket);
  }

  close(connection_socket);

  /* Unlink the socket. */

  unlink(SOCKET_NAME);

  exit(EXIT_SUCCESS);
}