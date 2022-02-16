#include <stdint.h>// uint8_t
#include <stdio.h>// printf
#include <stdlib.h>// malloc
#include <string.h>// strtok
#include "log.h"

#ifdef _DEBUG
uint64_t used_size = 0;
#endif

struct trie_node {
    struct trie_node *next[128];
    uint32_t checksum; // if use pointer, it will be 4(32bit) or 8(64bit) bytes so, it is better to use uint32_t(4 bytes)
    uint8_t is_binary:1;
};


static struct trie_node *trie_create() {
    struct trie_node *root = malloc(sizeof(struct trie_node));
    #ifdef _DEBUG
    used_size += sizeof(struct trie_node);
    #endif
    memset(root, 0, sizeof(struct trie_node));
    return root;
}

static struct trie_node *trie_insert(struct trie_node *root, const char *path) {
    struct trie_node *cur = root;
    for (int i = 0; path[i]; i++) {
        if (!cur->next[path[i]]) {
            cur->next[path[i]] = malloc(sizeof(struct trie_node));
            #ifdef _DEBUG
            used_size += sizeof(struct trie_node);
            #endif
            memset(cur->next[path[i]], 0, sizeof(struct trie_node));
        }
        cur = cur->next[path[i]];
    }
    cur->is_binary = 1;
    return cur;
}

static struct trie_node *trie_search(struct trie_node *root, const char *path) {
    struct trie_node *cur = root;
    for (int i = 0; path[i]; i++) {
        if (!cur->next[path[i]]) {
            return NULL;
        }
        cur = cur->next[path[i]];
    }
    return cur;
}

static void trie_delete(struct trie_node *root) {
    if (!root) {
        return;
    }
    for (int i = 0; i < 128; i++) {
        if (root->next[i]) {
            trie_delete(root->next[i]);
        }
    }
    free(root);
    #ifdef _DEBUG
    used_size -= sizeof(struct trie_node);
    #endif
}

static int trie_init(struct trie_node *root){

    root = trie_create();
    FILE *fp = fopen("/tmp/whitelist.txt", "r");
    char buf[4100];

    if (fp == NULL) {
        drift_prevent_write_log(ERROR, "open file error\n");
        return -1;
    }

    while (fgets(buf, sizeof(buf), fp)) {
        buf[strlen(buf) - 1] = 0;
        char *filename = strtok(buf, " ");
        char *checksum_str = strtok(NULL, " ");
        uint32_t checksum = (uint32_t)strtol(checksum_str, NULL, 16);
        struct trie_node *node = trie_insert(root, filename);
        if (node) {
            node->checksum = checksum;
        }else {
            drift_prevent_write_log(ERROR, "insert error %s %d\n", filename, checksum);
        }
    }
    fclose(fp);
}

#ifdef _TEST
int main(){
    char buf[5000];

    struct trie_node *root = trie_create();

    //read from file
    FILE *fp = fopen("/tmp/whitelist.txt", "r");

    if (fp == NULL) {
        printf("open file error\n");
        return -1;
    }


    while (fgets(buf, sizeof(buf), fp)) {
        buf[strlen(buf) - 1] = 0;
        char *filename = strtok(buf, " ");
        char *checksum_str = strtok(NULL, " ");
        uint32_t checksum = (uint32_t)strtol(checksum_str, NULL, 16);
        struct trie_node *node = trie_insert(root, filename);
        if (node) {
            node->checksum = checksum;
        }else {
            printf("%s %d\n", filename, checksum);
        }
    }
    fclose(fp);


    //Uncomment to test this unit input
#ifdef _DEBUG
    printf("total size %lu\n", used_size);
    while(~scanf("%s", buf)){
        struct trie_node *node = trie_search(root, buf);
        if(node){
            printf("%s %x\n", buf, node->checksum);
        }else{
            printf("%s is not binary\n", buf);
        }
    }
#endif
    strcpy(buf, "/bin/cat");
    struct trie_node *node = trie_search(root, buf);
    if(node){
        printf("%s %x\n", buf, node->checksum);
    }else{
        printf("%s is not binary\n", buf);
    }
    trie_delete(root);
    return 0;
}
#endif