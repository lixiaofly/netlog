#ifndef NTLG_LIST_H
#define NTLG_LIST_H

#include "hash_list.h"

struct ntlg_list_info{
	char procotol[8];
        char privip[20];
        char privport[8];
        char pubip[20];
        char pubport[8];
        char dstip[20];
        char dstport[8];
};

typedef struct ntlg_list_entry{
        struct list_head list;
        struct ntlg_list_info info;
}ntlg_list_entry_t;

extern struct list_head ntlg_list;

#define ntlg_list_each_entry_safe(tmp, ntmp)  \
	list_for_each_entry_safe(tmp,ntmp, &ntlg_list,list)  

extern  int ntlg_list_read_contrack(char *pathfile);
extern int test_list_free_all(struct list_head *list_head);

#endif
