#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "hash_list.h"
#include "ntlg_hash.h"

#define NTLG_HASH_SIZE 100000


struct hlist_head ntlg_hash_head[NTLG_HASH_SIZE];

typedef struct ntlg_hash_entry{
	struct ntlg_info info;
	struct hlist_node node;
}ntlg_hash_entry_t;

#ifndef OS_STRING_BKDR_NUMBER
#define OS_STRING_BKDR_NUMBER   31
#endif

static inline uint32_t
__bkdr_push(uint32_t a, uint32_t b)
{
    return a * OS_STRING_BKDR_NUMBER + b;
}
 
static inline uint32_t
__binary_bkdr(const unsigned char *binary, uint32_t len)
{
    uint32_t hash = 0;

    if (binary) {
        int i;
        
        for (i=0; i<len; i++) {
            hash = __bkdr_push(hash, *(binary + i));
        }
    }
    
    return hash;
} 

static int 
ntlg_hash_head_init(void)
{
	int i;
	for(i=0; i<=NTLG_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&ntlg_hash_head[i]);	
	return 0;
}

static int
get_key_value(char *line, char *key, int klen, char *value, int vlen)
{
	char *p;
	if((p=strstr(line, "=")) == NULL)
		return 1;
	else{
		*p='\0';
		p++;
		memset(key, 0, klen);
		memset(value, 0, vlen);
		strncpy(key, line, klen-1);
		strncpy(value, p, vlen-1);
	}
	return 0;
}
static int 
parse_conntrack_line(char *line, ntlg_hash_entry_t *node)
{
	char buf[20][128]={0};
	char key[20]={0};
	char value[20]={0};
        int i=0;

        char *p=strtok(line, " ");
        while(p != NULL){
                if(i >= 20)
                        return 1;
		if((i==2) && strcmp(p, "tcp") && strcmp(p, "udp"))
			return 0;
                strcpy(buf[i++], p);
                p = strtok(NULL, " ");
        }

	//printf("buf[2]=%s\n", buf[2]);
	if(!strcmp(buf[2], "tcp")){

	    if(!strcmp(buf[10], "[UNREPLIED]"))	
            return -1;

		strcpy(node->info.procotol, buf[3]);		

		
        if(get_key_value(buf[6],key, sizeof(key), value, sizeof(value)) || strcmp(key, "src"))
            return 1;
        strcpy(node->info.privip, value);
        //printf("node->info.privip %s\n",node->info.privip);

        if(get_key_value(buf[8],key, sizeof(key), value, sizeof(value)) || strcmp(key, "sport"))
            return 1;
        strcpy(node->info.privport, value);
        //printf("node->info.privport=%s\n",node->info.privport);
        if(get_key_value(buf[11],key, sizeof(key), value, sizeof(value)) || strcmp(key, "dst"))
            return -1; 
        strcpy(node->info.pubip, value);
        //printf("%s node->info.pubip %s\n",buf[13],node->info.pubip);

        if(get_key_value(buf[13],key, sizeof(key), value, sizeof(value)) || strcmp(key, "dport"))
            return -1; 
        strcpy(node->info.pubport, value);
        //printf("node->info.pubport %s\n",node->info.pubport);

        if(get_key_value(buf[7],key, sizeof(key), value, sizeof(value)) || strcmp(key, "dst"))
            return 1;
        strcpy(node->info.dstip, value);
        //printf("node->info.dstip %s\n",node->info.dstip);

        if(get_key_value(buf[9],key, sizeof(key), value, sizeof(value)) || strcmp(key, "dport"))
            return 1;   
        strcpy(node->info.dstport, value);
        //printf("node->info.dstport %s\n",node->info.dstport);		
	}
	else if(!strcmp(buf[2], "udp")){

        if(!strcmp(buf[9], "[UNREPLIED]"))	
            return -1;

		strcpy(node->info.procotol, buf[3]);		

		
        if(get_key_value(buf[5],key, sizeof(key), value, sizeof(value)) || strcmp(key, "src"))
            return 1;
        strcpy(node->info.privip, value);

        if(get_key_value(buf[7],key, sizeof(key), value, sizeof(value)) || strcmp(key, "sport"))
            return 1;
        strcpy(node->info.privport, value);

        if(get_key_value(buf[10],key, sizeof(key), value, sizeof(value)) || strcmp(key, "dst"))
            return 1; 
        strcpy(node->info.pubip, value);

        if(get_key_value(buf[12],key, sizeof(key), value, sizeof(value)) || strcmp(key, "dport"))
            return 1; 
        strcpy(node->info.pubport, value);

        if(get_key_value(buf[6],key, sizeof(key), value, sizeof(value)) || strcmp(key, "dst"))
            return 1;
        strcpy(node->info.dstip, value);

        if(get_key_value(buf[8],key, sizeof(key), value, sizeof(value)) || strcmp(key, "dport"))
            return 1;
        strcpy(node->info.dstport, value);		

	}else{
		return -1;
	}
	return 0;
}

static unsigned int  
get_head(struct ntlg_info *info)
{
	unsigned int hash=0;
	hash = __binary_bkdr((char *)info, sizeof(struct ntlg_info));
	return (hash%NTLG_HASH_SIZE);
}


static int 
is_info_equal(struct ntlg_info *a, struct ntlg_info *b)
{
	if(strcmp(a->procotol, b->procotol))	
		return 0;
	if(strcmp(a->privip, b->privip))
		return 0;
	if(strcmp(a->privport, b->privport))
		return 0;
	if(strcmp(a->pubip, b->pubip))
		return 0;
	if(strcmp(a->pubport, b->pubport))
		return 0;
	if(strcmp(a->dstip, b->dstip))
		return 0;
	if(strcmp(a->dstport, b->dstport))
		return 0;
	return 1;
}

static struct ntlg_hash_entry * 
get_item(struct ntlg_info *info)
{
	struct ntlg_hash_entry *item;
#if 1 
    int n = get_head(info);
	hlist_for_each_entry(item, &ntlg_hash_head[n], node)
	{
		if(is_info_equal(&(item->info), info)){
			return item;
			}
	}
#endif
	return NULL;
}


int 
ntlg_hash_read_contrack(char *pathfile)
{
	int err;
	FILE *fd;
	char line[1024]={0};

	if (!(fd = fopen(pathfile, "r"))) {
		printf("Could not open configuration file %s exiting...", pathfile);
		return(1);
	}		

	while (!feof(fd) && fgets(line, sizeof(line), fd)) {

		ntlg_hash_entry_t *hash_node = malloc(sizeof(ntlg_hash_entry_t)); 		
		memset(hash_node, sizeof(ntlg_hash_entry_t), 0);
		err = parse_conntrack_line(line, hash_node);
		if(err == 1)
			return 1;
		else if(err == 0)
			hlist_add_head(&hash_node->node, &ntlg_hash_head[get_head(&hash_node->info)]); 		
	}
	return 0;
}
int  
ntlg_hash_can_get_item(struct ntlg_info *info)
{
		
	struct ntlg_hash_entry *p;
	p = get_item(info);
	if(p == NULL)	
		return 0;	
	return 1;
}
int hlist_free_all(void)
{
	int i;
	struct ntlg_hash_entry *item;
	struct hlist_node *ntmp;
	for(i=0; i<NTLG_HASH_SIZE; i++){
		if(ntlg_hash_head[i].first != NULL){
			item = NULL;
			hlist_for_each_entry_safe(item, ntmp,&ntlg_hash_head[i], node){
				hlist_del(&item->node);
				free(item);
			}
		}
	}
	/*
	for(i=0; i<NTLG_HASH_SIZE; i++){
		if(ntlg_hash_head[i].first != NULL)
			printf("hash_head[%d] != NULL\n", i);
	}
	*/
	return 0;
}