#define CGROUP_PATH "/proc/self/cgroup"
#define DOCKER_DELIMITER "docker"

static int get_container_id(char *buf, int size)
{
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char *p = NULL;
    int ret = -1;

    fp = fopen(CGROUP_PATH, "r");
    if (fp == NULL){
        printf("open failed: %s\n", strerror(errno));
        fflush(stdout);
        return ret;
    }
    while ((read = getline(&line, &len, fp)) != -1) {
        if ((p = strstr(line, DOCKER_DELIMITER)) != NULL) {
            strncpy(buf, p + strlen(DOCKER_DELIMITER) + 1, size);
            ret = 0;
            break;
        }
    }

    fclose(fp);
    if (line)
        free(line);

    return ret;
}
