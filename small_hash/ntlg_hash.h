#ifndef _NTLG_HASH_H_
#define _NTLG_HASH_H_

struct ntlg_info{
	char procotol[8];
	char privip[20];
	char privport[8];
	char pubip[20];
	char pubport[8];
	char dstip[20];
	char dstport[8];
};


extern int ntlg_hash_can_get_item(struct ntlg_info *info);
extern int ntlg_hash_read_contrack(char *pathfile);
extern int hlist_free_all(void);

#endif
