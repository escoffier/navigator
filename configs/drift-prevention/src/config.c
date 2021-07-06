#define _GNU_SOURCE

#include <limits.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "types.c"

static int CHECKSUM_LEN = 8;

typedef struct
{
    char **filenames;
    uint32_t *checksums;
    size_t used;
    size_t size;
} Whitelist;

typedef struct
{
    char **filename_commands;
    char **cwd;
    bool *ok;
    size_t used;
    size_t size;
} CommandWhitelist;

static void whitelist_init(Whitelist *a, size_t initial_size)
{
    a->filenames = malloc(initial_size * sizeof(char *));
    a->checksums = malloc(initial_size * sizeof(uint32_t));
    a->used = 0;
    a->size = initial_size;
}

static void command_whitelist_init(CommandWhitelist *a, size_t initial_size)
{
    a->filename_commands = malloc(initial_size * sizeof(char *));
    a->cwd = malloc(initial_size * sizeof(char *));
    a->ok = malloc(initial_size * sizeof(bool));
    a->used = 0;
    a->size = initial_size;
}

static void command_whitelist_insert(CommandWhitelist *a, char *filename_command, char *cwd)
{
    if(!filename_command || !cwd){
        drift_prevent_write_log(ERROR, "command or cwd is null %s", strerror(errno));
        errno = 0;
        return ;
    }
    if (a->used == a->size)
    {
        a->size *= 2;
        a->filename_commands = realloc(a->filename_commands, a->size * sizeof(char *));
        a->ok = realloc(a->ok, a->size * sizeof(bool));
    }
    a->filename_commands[a->used] = malloc(2 * PATH_MAX * sizeof(char));
    a->cwd[a->used] = malloc(PATH_MAX * sizeof(char));

    strcpy(a->filename_commands[a->used], filename_command);
    strcpy(a->cwd[a->used], cwd);
    a->ok[a->used] = True;
    a->used++;
}

static void whitelist_insert(Whitelist *a, char *filename, uint32_t checksum)
{
    if (a->used == a->size)
    {
        a->size *= 2;
        a->filenames = realloc(a->filenames, a->size * sizeof(char *));
        a->checksums = realloc(a->checksums, a->size * sizeof(uint32_t));
    }
    a->filenames[a->used] = malloc(PATH_MAX * sizeof(char));
    strcpy(a->filenames[a->used], filename);
    a->checksums[a->used] = checksum;
    a->used++;
}

static void command_whitelist_free(CommandWhitelist *whitelist)
{
    free(whitelist->filename_commands);
    free(whitelist->ok);
    whitelist->filename_commands = NULL;
    whitelist->ok = NULL;
    whitelist->used = whitelist->size = 0;
}

static void whitelist_free(Whitelist *whitelist)
{
    free(whitelist->filenames);
    free(whitelist->checksums);
    whitelist->filenames = NULL;
    whitelist->checksums = NULL;
    whitelist->used = whitelist->size = 0;
}

static int read_command_config(CommandWhitelist *whitelist)
{
    FILE *fp;
    char line[PATH_MAX + CHECKSUM_LEN + 1];

    char *whitelist_file = "/tensorsec/commands.txt";

    fp = fopen(whitelist_file, "r");

    if (fp == NULL)
    {
        drift_prevent_write_log(ERROR, "Could not open config file: %s", strerror(errno));
        errno = 0;
        return 1;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        line[strlen(line)-1] = '\0';
        char *cwd = strstr(line, " PWD=");
        if(cwd){
            cwd[0] = '\0';
            cwd += 5;
            char *filename_command = line;
            command_whitelist_insert(whitelist, filename_command, cwd);
        }

    }
    if (fclose(fp) != 0)
    {
        drift_prevent_write_log(ERROR, "Could not close config file: %s", strerror(errno));
        errno = 0;
        return 1;
    }
    return 0;
}

static int read_config(Whitelist *whitelist)
{
    FILE *fp;
    char line[PATH_MAX + CHECKSUM_LEN + 1];

    char *whitelist_file = "/tensorsec/whitelist.txt";

    fp = fopen(whitelist_file, "r");
    if (fp == NULL)
    {
        drift_prevent_write_log(ERROR, "Could not open config file: %s", strerror(errno));
        errno = 0;
        return 1;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        char *filename = strtok(line, " ");
        char *checksum_str = strtok(NULL, " ");
        uint32_t checksum = (uint32_t)strtol(checksum_str, NULL, 16);
        whitelist_insert(whitelist, filename, checksum);
    }
    if (fclose(fp) != 0)
    {
        drift_prevent_write_log(ERROR, "Could not close config file: %s", strerror(errno));
        errno = 0;
        return 1;
    }
    return 0;
}
