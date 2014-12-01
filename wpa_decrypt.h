#ifndef _WPA_DECRYPT_H
#define _WPA_DECRYPT_H

#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include "eapol.h"
#include <include/mpi.h>

#define SUCCESS  0
#define FAILURE  1
#define RESTART  2

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define MAX_DICTS 128

// #define ASCII_LOW_T 0x21
// #define ASCII_HIGH_T 0x7E
// #define ASCII_VOTE_STRENGTH_T 150
// #define ASCII_DISREGARD_STRENGTH 1
// 
// #define TEST_MIN_IVS	4
// #define TEST_MAX_IVS	32
// 
// #define PTW_TRY_STEP    5000

#define KEYHSBYTES PTW_KEYHSBYTES

#define MAX_THREADS 128

#define CLOSE_IT	100000

#define GENPMKMAGIC 0x43575041



struct hashdb_head 
{
	uint32_t magic;
	uint8_t reserved1[3];
	uint8_t ssidlen;
	uint8_t ssid[32];
};

struct hashdb_rec 
{
	uint8_t rec_size;
	char *word;
	uint8_t pmk[32];
} __attribute__ ((packed));

extern int getmac(char * macAddress, int strict, unsigned char * mac);
extern int readLine(char line[], int maxlength);
extern int hexToInt(char s[], int len);
extern int hexCharToInt(unsigned char c);

extern int wpa_decrypt(int argc,char **argv);

#define S_LLC_SNAP      "\xAA\xAA\x03\x00\x00\x00"
#define S_LLC_SNAP_ARP  (S_LLC_SNAP "\x08\x06")
#define S_LLC_SNAP_IP   (S_LLC_SNAP "\x08\x00")
#define IEEE80211_FC1_DIR_FROMDS                0x02    /* AP ->STA */
#define KEYLIMIT 1000000

#define N_ATTACKS 17

int myid, numprocs;
int master,count,tag;
MPI_Status status;
    
struct options
{
	int amode;					 /* attack mode          */
	int essid_set;				 /* essid set flag       */
	int bssid_set;				 /* bssid set flag       */
	char essid[33];				 /* target ESSID         */
	unsigned char bssid[6];				 /* target BSSID         */
	int nbcpu;					 /* # of cracker threads
									(= # of CPU)         */

	unsigned char maddr[6];				 /* MAC address filter   */
	float ffact;				 /* bruteforce factor    */

	int is_fritz;				 /* use numeric keyspace */
	int is_alnum;				 /* alphanum keyspace    */
	int is_bcdonly;				 /* binary coded decimal */

	int do_brute;				 /* bruteforce last 2 KB */
	int do_mt_brute;			 /* bruteforce last 2 KB
									multithreaded for SMP*/

	char *dicts[MAX_DICTS];			 /* dictionary files     */
	FILE *dict;				 /* dictionary file      */
	int nbdict;				 /* current dict number  */
	int no_stdin;				 /* if dict == stdin     */
	int hexdict[MAX_DICTS];			 /* if dict in hex       */


	int l33t;					 /* no comment           */
	int stdin_dict;

	int brutebytes[64];			/* bytes to bruteforce */

	int max_ivs;

	char *bssidmerge;
	unsigned char *firstbssid;
	struct mergeBSSID * bssid_list_1st;

	struct AP_info *ap;


	int visual_inspection;       /* Enabling/disabling visual    */
                                 /* inspection of the different  */
                                 /* keybytes                     */


	char * logKeyToFile;

        int forced_amode;	/* signals disregarding automatic detection of encryption type */
	char * hccap;				         /* Hashcat capture file */   
	char * wkp;					 /* EWSA Project file */
}opt;

struct AP_info
{
	struct AP_info *next;		 /* next AP in linked list       */
	unsigned char bssid[6];				 /* access point MAC address     */
	char essid[33];				 /* access point identifier      */
	unsigned char lanip[4];				 /* IP address if unencrypted    */
	unsigned char *ivbuf;				 /* table holding WEP IV data    */
	unsigned char **uiv_root;			 /* IV uniqueness root struct    */
	long ivbuf_size;			 /* IV buffer allocated size     */
	long nb_ivs;				 /* total number of unique IVs   */
	long nb_ivs_clean;			 /* total number of unique IVs   */
	long nb_ivs_vague;				 /* total number of unique IVs   */
	int crypt;					 /* encryption algorithm         */
	int eapol;					 /* set if EAPOL is present      */
	int target;					 /* flag set if AP is a target   */
	struct ST_info *st_1st;		 /* linked list of stations      */
	struct WPA_hdsk wpa;		 /* valid WPA handshake data     */
//         PTW_attackstate *ptw_clean;
//         PTW_attackstate *ptw_vague;
};

struct ST_info
{
	struct AP_info *ap;			 /* parent AP                    */
	struct ST_info *next;		 /* next supplicant              */
	struct WPA_hdsk wpa;		 /* WPA handshake data           */
	unsigned char stmac[6];		 /* client MAC address           */
};

struct mergeBSSID
{
	unsigned char bssid [6];     /* BSSID */
	char unused[2];				 /* Alignment */
	int convert;				 /* Does this BSSID has to       */
								 /* be converted                 */
	struct mergeBSSID * next;
};

struct WPA_data {
	struct AP_info* ap;				/* AP information */
	int	thread;						/* number of this thread */
	int nkeys;						/* buffer capacity */
	char *key_buffer;				/* queue as a circular buffer for feeding and consuming keys */
	int front;						/* front marker for the circular buffers */
	int back;						/* back marker for the circular buffers */
	char key[128];					/* cracked key (0 while not found) */
	pthread_cond_t cond;			/* condition for waiting when buffer is full until keys are tried and new keys can be written */
	pthread_mutex_t mutex;
};


#endif
