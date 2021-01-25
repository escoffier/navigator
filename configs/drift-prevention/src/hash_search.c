#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include "log.h"

const unsigned int HASH_SEED = 131;

typedef int (*cmp_func)(void * node, void * key, uint32_t key_size);
typedef int (*add_node_func)(void * node, void * key, uint32_t key_size);
typedef int (*put_func)(void * node);
typedef uint64_t (*hash_func)(void * key, uint32_t key_size, uint64_t seed);

typedef struct _hash_bucket_s{
    struct _hash_bucket_s *next;
    uint32_t node_cnt;
    uint32_t total_cnt;
    uint8_t data[0];
}hash_bucket_t;

typedef struct _hash_config_s{
    uint32_t n_entries;
    uint32_t n_entries_per_bucket;
    uint32_t key_size;
    uint32_t entry_size;
    uint32_t bucket_size;
    add_node_func add_node;
    put_func put_node;
    cmp_func cmp;
    hash_func hash;
}hash_config_t;

typedef struct{
    uint32_t buckets;
    uint32_t n_entries_per_bucket;
    uint32_t bucket_size;
    uint32_t entry_size;
    uint32_t key_size;
    put_func put_node;
    add_node_func add_node;
    cmp_func cmp;
    hash_func hash;
    uint8_t mem_cache[0];
}hash_tbl_t;

void * hashtbl_node_get(void *key, hash_tbl_t *table)
{
    if(key == NULL || table == NULL){
        return NULL;
    }

    uint64_t sig, node_index, bucket_index;
    uint8_t * node_addr = NULL;
    uint8_t * node = NULL;
    hash_bucket_t * bucket = NULL;

    sig = table->hash(key, strlen((char *)key), HASH_SEED);
    bucket_index = sig & (table->buckets - 1);
    bucket = (hash_bucket_t *)&table->mem_cache[bucket_index * table->bucket_size];
    for(node_index = 0; node_index < table->n_entries_per_bucket; node_index++){
        node_addr = &bucket->data[node_index * table->entry_size];
        int res = 0;
        if((res = table->cmp(node_addr, key, table->key_size-1)) != 0) {
            node_addr = NULL;
            if(res<0){
                break;
            }
        }else{
            return (void *)node_addr;
        }
    }

    if(node_index == table->n_entries_per_bucket){
        if(!bucket){
            return NULL;
        }
        if(bucket->next){
            bucket=bucket->next;
            for(node_index = 0; node_index < bucket->total_cnt; node_index++){
                node_addr = &bucket->data[node_index * table->entry_size];
                int res = 0;
                if((res = table->cmp(node_addr, key, 0)) != 0) {
                    node_addr = NULL;
                    if(res<0) {
                        break;
                    }
                }else{
                    return (void *)node_addr;
                }
            }
        }
    }
    return (void *)node_addr;
}

void * hashtbl_node_insert(void *key, hash_tbl_t *table)
{
    if(key == NULL || table == NULL){
        return NULL;
    }
    uint64_t sig, node_index, bucket_index;
    uint8_t * node_addr = NULL;
    hash_bucket_t * bucket = NULL;
    sig = table->hash(key, strlen((char *)key), HASH_SEED);
    bucket_index = sig & (table->buckets - 1);
    bucket = (hash_bucket_t *)&table->mem_cache[bucket_index * table->bucket_size];

    for(node_index = 0; node_index < table->n_entries_per_bucket; node_index++){
        node_addr = &bucket->data[node_index * table->entry_size];
        int res = 0;
        if((res = table->cmp(node_addr, key, table->key_size)) != 0){
            if(res<0){
                table->add_node(node_addr, key, table->key_size);
                bucket->node_cnt++;
                return (void *)node_addr;
            }
        }else{
            return (void *)node_addr;
        }
    }

    if(node_index == table->n_entries_per_bucket){
        if(!bucket){
            return NULL;
        }
        hash_bucket_t *tmp_bucket = NULL, *table_bucket = bucket;
        if(bucket->next){
            bucket = bucket->next;
            for(node_index = 0; node_index < bucket->total_cnt; node_index++){
                node_addr = &bucket->data[node_index * table->entry_size];
                int res = 0;
                if((res = table->cmp(node_addr, key, table->key_size))!=0){
                    if(res<0){
                        if(table->add_node(node_addr, key, table->key_size)){
                            return NULL;
                        }
                        bucket->node_cnt++;
                        return (void *)node_addr;
                    }
                }else{
                    return (void *)node_addr;
                }
            }
            if(node_index == bucket->total_cnt){
                uint64_t new_bucket_size = table->bucket_size + (bucket->total_cnt +1) * table->entry_size;
                tmp_bucket = realloc(bucket, new_bucket_size);
                if(!tmp_bucket){
                    return NULL;
                }
                bucket = tmp_bucket;
                bucket->total_cnt += 1;
                table_bucket->next = bucket;
            }
        }else{
            node_index = 0;
            uint64_t new_bucket_size = table->bucket_size + table->entry_size;
            tmp_bucket = (hash_bucket_t *)malloc(new_bucket_size);
            if(!tmp_bucket){
                return NULL;
            }

            memset(tmp_bucket, 0, new_bucket_size);
            tmp_bucket->total_cnt = 1;
            bucket->next = tmp_bucket;
            bucket=bucket->next;
        }
    }
    node_addr = &bucket->data[node_index * table->entry_size];
    if(table->add_node(node_addr, key, table->key_size)){
        return NULL;
    }
    bucket->node_cnt++;
    return node_addr;
}

int hashtbl_node_free(hash_tbl_t *table)
{
    if(!table){
        write_log(ERROR, "hash table is null\n", strerror(errno));
        return -1;
    }
    hash_bucket_t * bucket = NULL, *tmp_ptr = NULL;

    for(int i = 0; i < table->buckets; i++){
        bucket = (hash_bucket_t *)&table->mem_cache[i * table->bucket_size];
        bucket = bucket->next;
        while(bucket&&bucket->next){
            tmp_ptr = bucket->next;
            free(bucket);
            bucket = tmp_ptr;
        }
        bucket = NULL;
        tmp_ptr = NULL;
    }
    free(table);
    table = NULL;
    return 0;
}

static uint32_t _power2_calc(uint32_t n_nums)
{
    n_nums--;
    n_nums |= n_nums >> 1;
    n_nums |= n_nums >> 2;
    n_nums |= n_nums >> 4;
    n_nums |= n_nums >> 8;
    n_nums |= n_nums >> 16;

    return n_nums + 1;
}

hash_tbl_t * hashtbl_init(hash_config_t *config)
{
    if(!config || config->n_entries == 0 || config->n_entries_per_bucket ==0){
        return NULL;
    }

    hash_tbl_t * hash_table = NULL;
    uint64_t n_buckets = 0;
    uint64_t total_size = 0;
    uint64_t bucket_size_cl = 0;

    n_buckets = _power2_calc(config->n_entries / config->n_entries_per_bucket + 1);

    bucket_size_cl = config->bucket_size + config->entry_size * config->n_entries_per_bucket;
    total_size = sizeof(hash_tbl_t) + (bucket_size_cl * n_buckets);


    hash_table = malloc(total_size);
    if(!hash_table){
        return NULL;
    }
    memset(hash_table, 0, total_size);

    hash_table->buckets = n_buckets;
    hash_table->n_entries_per_bucket = config->n_entries_per_bucket;
    hash_table->entry_size = config->entry_size;
    hash_table->key_size = config->key_size;
    hash_table->bucket_size = bucket_size_cl;
    hash_table->hash = config->hash;
    hash_table->cmp = config->cmp;
    hash_table->add_node = config->add_node;
    hash_table->put_node =config->put_node;

    return hash_table;
}

typedef struct _entry {
    char filename[PATH_MAX];
    uint32_t checksum;
}entry;

uint64_t bkdr_hash(void * key, uint32_t key_size, uint64_t seed)
{
    if(key == NULL) {
        return 0;
    }

    uint64_t hash = 0;
    char *str = (char *)key;
    int index = 0;
    while (*str&&index < key_size){
        hash = (*str++) + (hash << 6) + (hash << 16) - hash;
        index++;
    }

    return hash;
}

int add_whitelist_func(void * node, void * key, uint32_t key_size)
{
    entry * pstnode = (entry *)node;
    char * file_path = (char *)key;
    if(file_path == NULL){
        return -1;
    }
    if(pstnode){
        memset(pstnode->filename, 0, key_size);
        memcpy(pstnode->filename, file_path, key_size);
    }else{
        return -1;
    }
    return 0;
}

int cmp_whitelist_func(void * node, void * key, uint32_t key_size)
{

    entry *pstnode = (entry *) node;

    if(!pstnode->checksum && pstnode->filename[0] == '\0'){
        //null
        return -1;
    }
    if (!strcmp(pstnode->filename, (char *)key) && strlen(pstnode->filename) == strlen((char *)key)){
        //matched
        return 0;
    }
    return 1;
}

hash_config_t whitelist_hash_config = {
    .n_entries = 1000,
    .n_entries_per_bucket = 4,
    .key_size = PATH_MAX,//sizeof key
    .entry_size = sizeof(entry),
    .bucket_size = sizeof(hash_bucket_t),
    .hash = bkdr_hash,
    .cmp = cmp_whitelist_func,
    .add_node = add_whitelist_func,
};
