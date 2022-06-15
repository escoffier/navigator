#include <stdio.h> // stderr
#include <errno.h> // errno
#include <stdlib.h> // EXIT_FAILURE
#include <string.h>         // strerror

#include "log.h"

#define CONTAINER_ID_PATH "/.container_id"


static int get_container_id(char *buf, int size)
{
    if (buf == NULL || size <= 0) {

        return -1;
    }
    FILE *fp;
    size_t len = 0;
    int ret = 0;

    fp = fopen(CONTAINER_ID_PATH, "r");
    if (fp == NULL){
        drift_prevent_write_log(ERROR,"open failed: %s\n", strerror(errno));
        return -1;
    }
    if(fgets(buf, size, fp) == NULL){
        drift_prevent_write_log(ERROR,"fgets failed: %s\n", strerror(errno));
        ret = 1;
    }

    fclose(fp);

    return ret;
}

#ifdef _DEBUG
int main() {
    int CONTAINID_LEN = 64;
    char buf[1024];
    printf("start\n");
    int ret = get_container_id(buf, CONTAINID_LEN);
    printf("ret :%d ,%s\n", ret, buf);
}
#endif