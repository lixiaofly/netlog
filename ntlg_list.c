#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntlg_hash.h"
#include "ntlg_list.h"

LIST_HEAD(ntlg_list);

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
parse_conntrack_line(char *line, struct ntlg_list_entry *node)
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

        strcpy(node->info.procotol, buf[3]);

        if(get_key_value(buf[5],key, sizeof(key), value, sizeof(value)) || strcmp(key, "src"))
            return 1;
        strcpy(node->info.privip, value);

        if(get_key_value(buf[7],key, sizeof(key), value, sizeof(value)) || strcmp(key, "sport"))
            return 1;
        strcpy(node->info.privport, value);

        if(get_key_value(buf[10],key, sizeof(key), value, sizeof(value)) || strcmp(key, "dst"))
            return -1;
        strcpy(node->info.pubip, value);

        if(get_key_value(buf[12],key, sizeof(key), value, sizeof(value)) || strcmp(key, "dport"))
            return -1;
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
    int
ntlg_list_read_contrack(char *pathfile)
{
    int err;
    FILE *fd;
    char line[1024]={0};

    if (!(fd = fopen(pathfile, "r"))) {
        printf("Could not open configuration file %s exiting...", pathfile);
        return(1);
    }

    while (!feof(fd) && fgets(line, sizeof(line), fd)) {
        ntlg_list_entry_t *entry = (ntlg_list_entry_t *)malloc(sizeof(ntlg_list_entry_t));
        memset(entry, sizeof(ntlg_list_entry_t), 0);

        err = parse_conntrack_line(line, entry);
		//printf("err=%d\n", err);
        if(err == 1){
			printf("ntlg failed with line: %s\n", line);
			return 1;
        }
		else if(err == 0)
        	list_add_tail(&entry->list,&ntlg_list);
    }

    return 0;
}
int test_list_free_all(struct list_head *list_head)
{
	
	struct ntlg_list_entry *tmp;
	
	list_for_each_entry(tmp,list_head,list){
		printf("list_head is not empty!");
	}
	return 0;
}

