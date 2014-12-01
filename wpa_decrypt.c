#include "wpa_decrypt.h"
#include <sys/types.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <ctype.h>
#include <err.h>
#include <math.h>
#include <limits.h>
#include <unistd.h>

#include "sha1-sse2.h"
#include "pcap.h"
#include "common.h"
#include "byteorder.h"

static unsigned char ZERO[32] =
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00";

static int _speed_test;
struct timeval t_begin;			 /* time at start of attack      */
struct timeval t_stats;			 /* time since last update       */
struct timeval t_kprev;			 /* time at start of window      */
long long int nb_kprev;			 /* last  # of keys tried        */
long long int nb_tried;			 /* total # of keys tried        */

int close_aircrack = 0;

pthread_t tid[MAX_THREADS];
struct WPA_data wpa_data[MAX_THREADS];
int wpa_wordlists_done = 0;
static pthread_mutex_t mx_nb = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mx_wpastats = PTHREAD_MUTEX_INITIALIZER;

int  nb_eof = 0;				 /* # of threads who reached eof */
long nb_pkt = 0;				 /* # of packets read so far     */

/* IPC global data */
int mc_pipe[256][2];			 /* master->child control pipe   */
int cm_pipe[256][2];			 /* child->master results pipe   */
int bf_pipe[256][2];			 /* bruteforcer 'queue' pipe	 */
int bf_nkeys[256];
int id=0;


struct AP_info *ap_1st;			 /* first item in linked list    */
pthread_mutex_t mx_apl;			 /* lock write access to ap LL   */
pthread_mutex_t mx_eof;			 /* lock write access to nb_eof  */
pthread_mutex_t mx_ivb;			 /* lock access to ivbuf array   */
pthread_mutex_t mx_dic;			 /* lock access to opt.dict      */
pthread_cond_t  cv_eof;			 /* read EOF condition variable  */

extern int get_nb_cpus();

char * progname;
int intr_read = 0;

typedef struct
{
	int off1;
	int off2;
	void *buf1;
	void *buf2;
}read_buf;


int safe_write( int fd, void *buf, size_t len );
int set_dicts(char* optargs);
void clean_exit(int ret);
void sighandler( int signum );
int checkbssids(char *bssidlist);
void eof_wait( int *eof_notified );
int atomic_read( read_buf *rb, int fd, int len, void *buf );
void read_thread( void *arg );
void check_thread( void *arg );
float chrono( struct timeval *start, int reset );
void show_wpa_stats( char *key, int keylen, unsigned char pmk[32], unsigned char ptk[64],unsigned char mic[16], int force );
int crack_wpa_thread( void *arg );
int next_dict(int nb);
int do_wpa_crack();
int next_key( char **key, int keysize );
int set_dicts(char* optargs);

/*
 * MPI function listener 
 */
void * mpi_listener(void * param);


int wpa_decrypt(int argc, char** argv)
{
	int i, n, ret, option, /*j,*/ ret1, nbMergeBSSID, unused;
	int cpu_count, /*showhelp,*/ z, zz/*, forceptw*/;
	//char *s, buf[128];
	struct AP_info *ap_cur;
	int old=0;
	char essid[33];
	char *mpibuff;
	ret = FAILURE;
	int s1=0;
	int mpibuffsize=0;
	
	/* 
	 * MPI comunication setup
	 */
	
	MPI_Pack_size( 128, MPI_CHAR,MPI_COMM_WORLD, &s1 );
	
	mpibuffsize = 3 * MPI_BSEND_OVERHEAD + s1;
	
	mpibuff = (char *)malloc( mpibuffsize );
	
	MPI_Buffer_attach( mpibuff, mpibuffsize );
      
	/*
	 * MPI comunication setup
	 */
	
	// Start a new process group, we are perhaps going to call kill(0, ...) later
	setsid();

	memset( &opt, 0, sizeof( opt ) );

	srand( time( NULL ) );

	// Get number of CPU (return -1 if failed).
	cpu_count = get_nb_cpus();
	opt.nbcpu = 1;
	if (cpu_count > 1) {
		opt.nbcpu = cpu_count;
	}

	
	/* check the arguments */

	opt.nbdict		= 0;
	opt.amode		= 0;
	opt.do_brute    = 1;
	opt.do_mt_brute = 1;
	opt.max_ivs		= INT_MAX;
	opt.visual_inspection = 0;
	opt.firstbssid	= NULL;
	opt.bssid_list_1st = NULL;
	opt.bssidmerge	= NULL;
	opt.logKeyToFile = NULL;
	opt.wkp = NULL;
	opt.hccap = NULL;
	opt.forced_amode	= 0;

	while( 1 )
	{

		int option_index = 0;

		static struct option long_options[] = {
		    {"bssid",             1, 0, 'b'},
		    {"debug",             1, 0, 'd'},
		    {"combine",           0, 0, 'C'},
		    {"help",              0, 0, 'H'},
		    {"wep-decloak",       0, 0, 'D'},
		    {"ptw-debug",         1, 0, 'P'},
		    {"visual-inspection", 0, 0, 'V'},
		    {"oneshot",           0, 0, '1'},
		    {"cpu-detect",        0, 0, 'u'},
		    {0,                   0, 0,  0 }
		};

		option = getopt_long( argc, argv, "r:a:e:b:p:qcthd:l:E:J:m:n:i:f:k:x::Xysw:0HKC:M:DP:zV1Su",
                        long_options, &option_index );

		if( option < 0 ) break;

		switch( option )
		{
			case 'S':
				_speed_test = 1;
				opt.amode = 2;
				opt.dict = stdin;
				opt.bssid_set = 1;

				ap_1st = ap_cur = malloc(sizeof(*ap_cur));
				if (!ap_cur)
					err(1, "malloc()");

				memset(ap_cur, 0, sizeof(*ap_cur));

				ap_cur->target = 1;
				ap_cur->wpa.state = 7;
				strcpy(ap_cur->essid, "sorbo");

				goto __start;
				break;

			case ':' :

				printf("\"%s --help\" for help.\n", argv[0]);
				return( 1 );

			case '?' :

				printf("\"%s --help\" for help.\n", argv[0]);
				return( 1 );

			case 'u' :
				printf("Nb CPU detected: %d ", cpu_count);
#if defined(__i386__) || defined(__x86_64__)
				unused = shasse2_cpuid();

				if (unused == 1) {
					printf(" (MMX available)");
				}
				if (unused >= 2) {
					printf(" (SSE2 available)");
				}
#endif
				printf("\n");
				return( 0 );

			case 'a' :

				opt.amode=2;
    
				opt.forced_amode = 1;

				break;

			case 'e' :

				memset(  opt.essid, 0, sizeof( opt.essid ) );
				strncpy( opt.essid, optarg, sizeof( opt.essid ) - 1 );
				opt.essid_set = 1;
				break;

			case 'b' :

				if (getmac(optarg, 1, opt.bssid) != 0)
				{
						printf( "Invalid BSSID (not a MAC).\n" );
						printf("\"%s --help\" for help.\n", argv[0]);
						return( FAILURE );
				}

				opt.bssid_set = 1;
				break;

			case 'p' :
			  //Aqui a lo mejor hago otra tecnica o que se automatico
				if( sscanf( optarg, "%d", &opt.nbcpu ) != 1 || opt.nbcpu < 1 || opt.nbcpu > MAX_THREADS)
				{
					printf( "Invalid number of processes (recommended: %d)\n", cpu_count );
					printf("\"%s --help\" for help.\n", argv[0]);
					return( FAILURE );
				}

				break;

			case 'c' :

				opt.is_alnum = 1;
				break;

			case 'h' :

				opt.is_fritz = 1;
				break;

			case 't' :

				opt.is_bcdonly = 1;
				break;


			case 'm' :

				if ( getmac(optarg, 1, opt.maddr) != 0)
				{
					printf( "Invalid MAC address filter.\n" );
					printf("\"%s --help\" for help.\n", argv[0]);
					return( FAILURE );
				}

				break;


			case 'f' :

				if( sscanf( optarg, "%f", &opt.ffact ) != 1 ||
					opt.ffact < 1 )
				{
					printf( "Invalid fudge factor. [>=1]\n" );
					printf("\"%s --help\" for help.\n", argv[0]);
					return( FAILURE );
				}

				break;


			case 'l' :
				opt.logKeyToFile = (char *)calloc(1, strlen(optarg) + 1);
				if (opt.logKeyToFile == NULL)
				{
					printf("Error allocating memory\n");
					return( FAILURE );
				}

				strncpy(opt.logKeyToFile, optarg, strlen(optarg));
				break;

			case 'E' :
				// Make sure there's enough space for file extension just in case it was forgotten
				opt.wkp = (char *)calloc(1, strlen(optarg) + 1 + 4);
				if (opt.wkp == NULL)
				{
					printf("Error allocating memory\n");
					return( FAILURE );
				}

				strncpy(opt.wkp, optarg, strlen(optarg));

				break;

			case 'J' :
				// Make sure there's enough space for file extension just in case it was forgotten
				opt.hccap = (char *)calloc(1, strlen(optarg) + 1 + 6);
				if (opt.hccap == NULL)
				{
					printf("Error allocating memory\n");
					return( FAILURE );
				}

				strncpy(opt.hccap, optarg, strlen(optarg));

				break;


			case 'x' :

				opt.do_brute = 0;

				if (optarg)
				{
					if (sscanf(optarg, "%d", &opt.do_brute)!=1
						|| opt.do_brute<0 || opt.do_brute>4)
					{
						printf("Invalid option -x%s. [0-4]\n", optarg);
						printf("\"%s --help\" for help.\n", argv[0]);
						return FAILURE;
					}
				}

				break;

			case 'X' :

				opt.do_mt_brute = 0;
				break;


			case 'w' :
				if(set_dicts(optarg) != 0)
				{
					printf("\"%s --help\" for help.\n", argv[0]);
					return FAILURE;
				}
				break;


			case '0' :

				opt.l33t = 1;
				break;


			case 'C' :
				nbMergeBSSID = checkbssids(optarg);

				if(nbMergeBSSID < 1)
				{
					printf("Invalid bssids (-C).\n\"%s --help\" for help.\n", argv[0]);
					return FAILURE;
				}

				// Useless to merge BSSID if only one element
				if (nbMergeBSSID == 1)
					printf("Merging BSSID disabled, only one BSSID specified\n");
				else
					opt.bssidmerge = optarg;

				break;

			case 'z' :
				/* only for backwards compatibility - PTW used by default */
				if (opt.visual_inspection)
				{
					printf("Visual inspection can only be used with KoreK\n");
					printf("Use \"%s --help\" for help.\n", argv[0]);
					return FAILURE;
				}


				break;

			default : return 0;
		}
	}
	
	if( argc - optind < 1 )
	{
		if(argc == 1)
		{
//usage:
			printf ("Error, especificar -e ESSID -b BSSID -w Diccionario y archivo pcap\n Solo funciona con WPA Handshake\n");
			exit(0);
		}

		// Missing parameters
		if( argc - optind == 0)
		{
		    printf("No file to crack specified.\n");
		}
		if(argc > 1)
		{
		    printf("\"%s --help\" for help.\n", argv[0]);
		}
		return( ret );
	}

	if( opt.amode == 2 && opt.dict == NULL )
	{
	      nodict:
	      if (opt.wkp == NULL && opt.hccap == NULL)
	      {
		      printf( "Please specify a dictionary (option -w).\n" );
	      }
	      goto exit_main;
	}

	if( (! opt.essid_set && ! opt.bssid_set) && (opt.no_stdin) )
	{
		printf( "Please specify an ESSID or BSSID.\n" );
		goto exit_main;
	}

	/* start one thread per input file */

	signal( SIGINT,  sighandler );
	signal( SIGQUIT, sighandler );
	signal( SIGTERM, sighandler );
	signal( SIGALRM, SIG_IGN );

	pthread_mutex_init( &mx_apl, NULL );
	pthread_mutex_init( &mx_ivb, NULL );
	pthread_mutex_init( &mx_eof, NULL );
	pthread_mutex_init( &mx_dic, NULL );
	pthread_cond_init(  &cv_eof, NULL );

	ap_1st = NULL;

	old = optind;
	n = argc - optind;
	id = 0;

	if( !opt.bssid_set )
	{
		do
		{
			if( strcmp( argv[optind], "-" ) == 0 )
				opt.no_stdin = 1;

			if( pthread_create( &(tid[id]), NULL, (void *) check_thread,
				(void *) argv[optind] ) != 0 )
			{
				perror( "pthread_create failed" );
				goto exit_main;
			}

			usleep( 131071 );
			id++;
			if(id >= MAX_THREADS)
			{
				printf("Only using the first %d files, ignoring the rest.\n", MAX_THREADS);
				break;
			}
		}
		while( ++optind < argc );

		/* wait until each thread reaches EOF */

		printf( "Reading packets, please wait...\r" );
		fflush( stdout );


// 		#ifndef DO_PGO_DUMP
// 		signal( SIGINT, SIG_DFL );	 /* we want sigint to stop and dump pgo data */
// 		#endif
		intr_read=1;

		for(i=0; i<id; i++)
			pthread_join( tid[i], NULL);

		id=0;

		if( ! opt.no_stdin )
			printf( "\33[KRead %ld packets.\n\n", nb_pkt );

		if( ap_1st == NULL )
		{
			printf( "No networks found, exiting.\n" );
			goto exit_main;
		}

		if( ! opt.essid_set && ! opt.bssid_set )
		{
			/* ask the user which network is to be cracked */

			printf( "   #  BSSID%14sESSID%21sEncryption\n\n", "", "" );

			i = 1;

			ap_cur = ap_1st;

			while( ap_cur != NULL )
			{
				memset( essid, 0, sizeof(essid));
				memcpy( essid, ap_cur->essid, 32);
				for(zz=0;zz<32;zz++)
				{
					if( (essid[zz] > 0 && essid[zz] < 32) || (essid[zz] > 126) )
						essid[zz]='?';
				}

				printf( "%4d  %02X:%02X:%02X:%02X:%02X:%02X  %-24s  ",
					i, ap_cur->bssid[0], ap_cur->bssid[1],
					ap_cur->bssid[2], ap_cur->bssid[3],
					ap_cur->bssid[4], ap_cur->bssid[5],
					essid );

				if( ap_cur->eapol )
					printf( "EAPOL+" );

				switch( ap_cur->crypt )
				{
					case  0: printf( "None (%d.%d.%d.%d)\n",
						ap_cur->lanip[0], ap_cur->lanip[1],
						ap_cur->lanip[2], ap_cur->lanip[3] );
					break;

					case  1: printf( "No data - WEP or WPA\n" );
					break;

					case  2: printf( "WEP (%ld IVs)\n",
						ap_cur->nb_ivs );
					break;

					case  3: printf( "WPA (%d handshake)\n",
						ap_cur->wpa.state == 7 );
					break;

					default: printf( "Unknown\n" );
					break;
				}

				i++; ap_cur = ap_cur->next;
			}

			printf( "\n" );
			{
				printf( "Choosing first network as target.\n" );
				ap_cur = ap_1st;
			}

			printf( "\n" );

			memcpy( opt.bssid, ap_cur->bssid,  6 );
			opt.bssid_set = 1;

			
		}

		ap_1st = NULL;
		optind = old;
		id=0;
	}

	nb_eof=0;
	signal( SIGINT, sighandler );

	do
	{
		if( strcmp( argv[optind], "-" ) == 0 )
			opt.no_stdin = 1;

		if( pthread_create( &(tid[id]), NULL, (void *) read_thread,
			(void *) argv[optind] ) != 0 )
		{
			perror( "pthread_create failed" );
			goto exit_main;
		}

		id++;
		usleep( 131071 );
		if(id >= MAX_THREADS)
			break;
	}
	while( ++optind < argc );

	nb_pkt=0;

	/* wait until each thread reaches EOF */

	intr_read=0;
	pthread_mutex_lock( &mx_eof );


	printf( "Reading packets, please wait...\r" );
	fflush( stdout );

	while( nb_eof < n && ! intr_read )
		pthread_cond_wait( &cv_eof, &mx_eof );

	pthread_mutex_unlock( &mx_eof );

	intr_read=1;

	/* mark the targeted access point(s) */

	ap_cur = ap_1st;

	while( ap_cur != NULL )
	{
		if( memcmp( opt.maddr, BROADCAST, 6 ) == 0 ||
			( opt.bssid_set && ! memcmp( opt.bssid, ap_cur->bssid, 6 ) ) ||
			( opt.essid_set && ! strcmp( opt.essid, ap_cur->essid    ) ) )
			ap_cur->target = 1;

		ap_cur = ap_cur->next;
	}

	ap_cur = ap_1st;

	while( ap_cur != NULL )
	{
		if( ap_cur->target )
			break;

		ap_cur = ap_cur->next;
	}

	if( ap_cur == NULL )
	{
		printf( "No matching network found - check your %s.\n",
			( opt.essid_set ) ? "essid" : "bssid" );

		goto exit_main;
	}

	if( ap_cur->crypt < 2 )
	{
		switch( ap_cur->crypt )
		{
			case  0:
				printf( "Target network doesn't seem encrypted.\n" );
				break;

			default:
				printf( "Got no data packets from target network!\n" );
				break;
		}

		goto exit_main;
	}

	/* create the cracker<->master communication pipes */

	for( i = 0; i < opt.nbcpu; i++ )
	{
		unused = pipe( mc_pipe[i] );
		unused = pipe( cm_pipe[i] );

		if (opt.amode<=1 && opt.nbcpu>1 && opt.do_brute && opt.do_mt_brute)
		{
			unused = pipe(bf_pipe[i]);
			bf_nkeys[i] = 0;
		}
	}

__start:
	/* launch the attack */

	nb_tried = 0;
	nb_kprev = 0;

	chrono( &t_begin, 1 );
	chrono( &t_stats, 1 );
	chrono( &t_kprev, 1 );

	signal( SIGWINCH, sighandler );

	if( opt.amode == 2 )
		goto crack_wpa;

	pthread_t mpilis_t;
	pthread_create(&mpilis_t,NULL,mpi_listener,NULL);
	
	if( ap_cur->crypt == 3 )
	{
		crack_wpa:

		if ( opt.dict == NULL )
			goto nodict;


		ap_cur = ap_1st;

		while( ap_cur != NULL )
		{
			if( ap_cur->target && ap_cur->wpa.state == 7 )
				break;

			ap_cur = ap_cur->next;
		}

		if( ap_cur == NULL )
		{
			printf( "No valid WPA handshakes found.\n" );
			goto exit_main;
		}

		if( memcmp( ap_cur->essid, ZERO, 32 ) == 0 && ! opt.essid_set )
		{
			printf( "An ESSID is required. Try option -e.\n" );
			goto exit_main;
		}

		if( opt.essid_set && ap_cur->essid[0] == '\0' )
		{
			memset(  ap_cur->essid, 0, sizeof( ap_cur->essid ) );
			strncpy( ap_cur->essid, opt.essid, sizeof( ap_cur->essid ) - 1 );
		}

		for( i = 0; i < opt.nbcpu; i++ )
		{
			/* start one thread per cpu */
			wpa_data[i].ap = ap_cur;
			wpa_data[i].thread = i;
			wpa_data[i].nkeys = 17;
			wpa_data[i].key_buffer = (char*) malloc(wpa_data[i].nkeys * 128);
			wpa_data[i].front = 0;
			wpa_data[i].back = 0;
			memset(wpa_data[i].key, 0, sizeof(wpa_data[i].key));
			pthread_cond_init(&wpa_data[i].cond, NULL);
			pthread_mutex_init(&wpa_data[i].mutex, NULL);

			if( pthread_create( &(tid[id]), NULL, (void *) crack_wpa_thread,
				(void *) &(wpa_data[i]) ) != 0 )
			{
				perror( "pthread_create failed" );
				goto exit_main;
			}

  #ifdef pthread_setaffinity_np
			// set affinity to one processor
			cpu_set_t cpuset;
			CPU_ZERO(&cpuset);
			CPU_SET(i, &cpuset);
			pthread_setaffinity_np(tid[id], sizeof(cpu_set_t), &cpuset);
  #endif

			id++;
		}

		ret = do_wpa_crack();	// we feed keys to the cracking threads
		wpa_wordlists_done = 1; // we tell the threads that they shouldn't expect more words (don't wait for parallel crack)

		for( i = 0; i < opt.nbcpu; i++ ) // we wait for the cracking threads to end
			pthread_join(tid[--id], NULL);

		for( i = 0; i < opt.nbcpu; i++ )
		{
			if (wpa_data[i].key[0] != 0)
			{
				ret = SUCCESS;
				break;
			}
		}
		
		
		
		if (ret==SUCCESS)
		{			
			if( opt.l33t )
				printf( "\33[31;1m" );

			printf( "\33[8;%dH\33[2KKEY FOUND! [ %s ]\33[11B\n",
				( 80 - 15 - (int) strlen(wpa_data[i].key) ) / 2, wpa_data[i].key );
			
			/* 
			 * MPI comunication 
			 * 
			 * If not master then tell master we have found the
			 * password.
			 * 
			 * In case the master found it, then tell the others
			 * to finish.
			 */
			if(myid!=master)
			{
			    memcpy(mpibuff,wpa_data[i].key,(int) strlen(wpa_data[i].key));
			    
			    printf("\n\nContraseña encontrada [%d], enviarlo al Master!\n",myid);
			    
			    MPI_Bsend(mpibuff,(int) strlen(wpa_data[i].key),MPI_CHAR,master,tag,MPI_COMM_WORLD);
			}
			else
			{
			    sprintf(mpibuff,"FinishAll");
			    
			    printf("\n\nSoy master encontre la contraseña pedire a todos que terminen!\n");
			    
			    MPI_Bcast(mpibuff,(int) strlen(mpibuff),MPI_CHAR,master,MPI_COMM_WORLD);
			}
			
			
			if( opt.l33t )
				printf( "\33[32;22m" );

			ret=SUCCESS;
			
		}
		else
		{
			printf( "\nPassphrase not in dictionary \n" );
			printf("\33[5;30H %lld",nb_tried);
			printf("\33[32;0H\n");
		}

		printf("\n");

	}

	printf("Esperando a otros nodos\n");
	pthread_join(mpilis_t,NULL);
	printf("Saliendo\n");
	
	sleep(10);
	exit_main:

	#if ((defined(__INTEL_COMPILER) || defined(__ICC)) && defined(DO_PGO_DUMP))
	_PGOPTI_Prof_Dump();
	#endif

	printf( "\n" );

	fflush( stdout );

	clean_exit(ret);

	return ret;
}

void* mpi_listener(void* param)
{
    char msgbuf[128];
    MPI_Status stats;
    
    while(1)
    {
	if(myid==master)
	{
	    MPI_Recv(msgbuf,128,MPI_CHAR,MPI_ANY_SOURCE,tag,MPI_COMM_WORLD,&stats);
	    printf("WPA Key received: [%s]\n",msgbuf);
	    printf("MASTER Terminando a todos\n");
	    sprintf(msgbuf,"FinishAll");
	    MPI_Bcast(msgbuf,(int)strlen("FinishAll"),MPI_CHAR,master,MPI_COMM_WORLD);
	    //clean_exit(SUCCESS);
	    pthread_exit(SUCCESS);
	}
	else
	{
	    MPI_Bcast(msgbuf,(int)strlen("FinishAll"),MPI_CHAR,master,MPI_COMM_WORLD);
	    if(strncmp(msgbuf,"FinishAll",(int)strlen("FinishAll"))==0)
	    {
		printf("Message from master Terminate all!\n");
		//clean_exit(SUCCESS);
		pthread_exit(SUCCESS);
	    }
	}
    }
}

void clean_exit(int ret)
{
	struct AP_info *ap_cur;
	struct AP_info *ap_next;
	int i=0;
	int child_pid;

	char tmpbuf[128];
	memset(tmpbuf, 0, 128);

	if(ret )
	{
		printf("\nQuitting wpa decrypt mpi...\n");
		fflush(stdout);
	}
	close_aircrack = 1;

	for( i = 0; i < opt.nbcpu; i++ )
	{
            safe_write( mc_pipe[i][1], (void *) "EXIT\r", 5 );
            safe_write( bf_pipe[i][1], (void *) tmpbuf, 64 );
	}

	if( opt.amode != 2 )
	{
		for(i=0; i<id; i++)
		{
			if(pthread_join(tid[i], NULL) != 0)
			{
	 			printf("Can't join thread %d\n", i);
			}
		}

	}

	ap_cur = ap_1st;


	ap_cur = ap_1st;

	while( ap_cur != NULL )
	{
		ap_next = ap_cur->next;

		if( ap_cur != NULL )
			free(ap_cur);

		ap_cur = ap_next;
	}

	child_pid=fork();

	if(child_pid==-1)
	{
	  /* do error stuff here */
	}
	if(child_pid!=0)
	{
	  /* The parent process exits here. */

	  exit(0);
	}

	_exit(ret);
}

int safe_write( int fd, void *buf, size_t len )
{
	int n;
	size_t sum = 0;
	char  *off = (char *) buf;

	while( sum < len )
	{
		if( ( n = write( fd, (void *) off, len - sum ) ) < 0 )
		{
			if( errno == EINTR ) continue;
			return( n );
		}

		sum += n;
		off += n;
	}

	return( sum );
}

void sighandler( int signum )
{
	#if ((defined(__INTEL_COMPILER) || defined(__ICC)) && defined(DO_PGO_DUMP))
	_PGOPTI_Prof_Dump();
	#endif
	signal( signum, sighandler );

	if( signum == SIGQUIT )
		clean_exit( SUCCESS );
// 		_exit( SUCCESS );

	if( signum == SIGTERM )
		clean_exit( FAILURE );
// 		_exit( FAILURE );

	if( signum == SIGINT )
	{
	#if ((defined(__INTEL_COMPILER) || defined(__ICC)) && defined(DO_PGO_DUMP))
		clean_exit( FAILURE );
//		_exit( FAILURE );
	#else
/*		if(intr_read > 0)*/
			clean_exit( FAILURE );
/*		else
			intr_read++;*/
	#endif
	}

	if( signum == SIGWINCH )
		printf( "\33[2J\n" );
}


int checkbssids(char *bssidlist)
{
	int first = 1;
	int failed = 0;
	int i = 0;
	char *list, *frontlist, *tmp;
	int nbBSSID = 0;

	if(bssidlist == NULL) return -1;

#define IS_X(x) ((x) == 'X' || (x) == 'x')
#define VALID_CHAR(x)   ((IS_X(x)) || hexCharToInt(x) > -1)

#define VALID_SEP(arg)	( ((arg) == '_') || ((arg) == '-') || ((arg) == ':') )
	frontlist = list = strdup(bssidlist);
	do
	{
		tmp = strsep(&list, ",");

		if (tmp == NULL)
			break;

		++nbBSSID;

		if(strlen(tmp) != 17) failed = 1;

		//first byte
		if(!VALID_CHAR(tmp[ 0])) failed = 1;
		if(!VALID_CHAR(tmp[ 1])) failed = 1;
		if(!VALID_SEP( tmp[ 2])) failed = 1;

		//second byte
		if(!VALID_CHAR(tmp[ 3])) failed = 1;
		if(!VALID_CHAR(tmp[ 4])) failed = 1;
		if(!VALID_SEP( tmp[ 5])) failed = 1;

		//third byte
		if(!VALID_CHAR(tmp[ 6])) failed = 1;
		if(!VALID_CHAR(tmp[ 7])) failed = 1;
		if(!VALID_SEP( tmp[ 8])) failed = 1;

		//fourth byte
		if(!VALID_CHAR(tmp[ 9])) failed = 1;
		if(!VALID_CHAR(tmp[10])) failed = 1;
		if(!VALID_SEP( tmp[11])) failed = 1;

		//fifth byte
		if(!VALID_CHAR(tmp[12])) failed = 1;
		if(!VALID_CHAR(tmp[13])) failed = 1;
		if(!VALID_SEP( tmp[14])) failed = 1;

		//sixth byte
		if(!VALID_CHAR(tmp[15])) failed = 1;
		if(!VALID_CHAR(tmp[16])) failed = 1;

		if(failed) {
			free(frontlist);
			return -1;
		}

		if(first)
		{
			for(i=0; i< 17; i++) {
				if( IS_X(tmp[i])) {
					free(frontlist);
					return -1;
				}
			}

			opt.firstbssid = (unsigned char *) malloc(sizeof(unsigned char));
			getmac(tmp, 1, opt.firstbssid);
			first = 0;
		}

	} while(list);

	// Success
	free(frontlist);
	return nbBSSID;
}

void eof_wait( int *eof_notified )
{
	if( *eof_notified == 0 )
	{
		*eof_notified = 1;

		/* tell the master thread we reached EOF */

		pthread_mutex_lock( &mx_eof );
		nb_eof++;
		pthread_cond_broadcast( &cv_eof );
		pthread_mutex_unlock( &mx_eof );
	}

	usleep( 100000 );
}

inline int wpa_send_passphrase(char *key, struct WPA_data* data, int lock)
{
	pthread_mutex_lock(&data->mutex);

	if ((data->back+1) % data->nkeys == data->front)
	{
		if (lock != 0)
		{
			// wait until there's room in the queue
			pthread_cond_wait(&data->cond, &data->mutex);
		}
		else
		{
			pthread_mutex_unlock(&data->mutex);
			return 0; // full queue!
		}
	}

	// put one key in the buffer:
	memcpy(data->key_buffer + data->back*128, key, 128);
	data->back = (data->back+1) % data->nkeys;

	pthread_mutex_unlock(&data->mutex);

	return 1;
}


inline int wpa_receive_passphrase(char *key, struct WPA_data* data)
{
	pthread_mutex_lock(&data->mutex);

	if (data->front==data->back)
	{
		pthread_mutex_unlock(&data->mutex);
		return 0; // empty queue!
	}

	// get one key from the buffer:
	memcpy(key, data->key_buffer + data->front*128, 128);
	data->front = (data->front+1) % data->nkeys;

	// signal that there's now room in the queue for more keys
	pthread_cond_signal(&data->cond);
	pthread_mutex_unlock(&data->mutex);

	return 1;
}

/* fread isn't atomic, sadly */

int atomic_read( read_buf *rb, int fd, int len, void *buf )
{
	int n;

	if( close_aircrack )
		return( CLOSE_IT );

	if( rb->buf1 == NULL )
	{
		rb->buf1 = malloc( 65536 );
		rb->buf2 = malloc( 65536 );

		if( rb->buf1 == NULL || rb->buf2 == NULL )
			return( 0 );

		rb->off1 = 0;
		rb->off2 = 0;
	}

	if( len > 65536 - rb->off1 )
	{
		rb->off2 -= rb->off1;

		memcpy( rb->buf2, rb->buf1 + rb->off1, rb->off2 );
		memcpy( rb->buf1, rb->buf2, rb->off2 );

		rb->off1 = 0;
	}

	if( rb->off2 - rb->off1 >= len )
	{
		memcpy( buf, rb->buf1 + rb->off1, len );
		rb->off1 += len;
		return( 1 );
	}
	else
	{
		n = read( fd, rb->buf1 + rb->off2, 65536 - rb->off2 );

		if( n <= 0 )
			return( 0 );

		rb->off2 += n;

		if( rb->off2 - rb->off1 >= len )
		{
			memcpy( buf, rb->buf1 + rb->off1, len );
			rb->off1 += len;
			return( 1 );
		}
	}

	return( 0 );
}

void read_thread( void *arg )
{
	int fd, n, fmt;
	unsigned z;
	int eof_notified = 0;
	read_buf rb;
// 	int ret=0;

	unsigned char bssid[6];
	unsigned char dest[6];
	unsigned char stmac[6];
	unsigned char *buffer;
	unsigned char *h80211;
	unsigned char *p;
	//int weight[16];

	struct ivs2_pkthdr ivs2;
	struct ivs2_filehdr fivs2;
	struct pcap_pkthdr pkh;
	struct pcap_file_header pfh;
	struct AP_info *ap_prv, *ap_cur;
	struct ST_info *st_prv, *st_cur;

	signal( SIGINT, sighandler);

	memset( &rb, 0, sizeof( rb ) );
	ap_cur = NULL;

	memset(&pfh, 0, sizeof(struct pcap_file_header));

	if( ( buffer = (unsigned char *) malloc( 65536 ) ) == NULL )
	{
		/* there is no buffer */

		perror( "malloc failed" );
		goto read_fail;
	}

	h80211 = buffer;


	printf( "Opening %s\n", (char *) arg );

	if( strcmp( arg, "-" ) == 0 )
		fd = 0;
	else
	{
		if( ( fd = open( (char *) arg, O_RDONLY | O_BINARY ) ) < 0 )
		{
			perror( "open failed" );
			goto read_fail;
		}
	}

	if( ! atomic_read( &rb, fd, 4, &pfh ) )
	{
		perror( "read(file header) failed" );
		goto read_fail;
	}

	fmt = FORMAT_IVS;

	if( memcmp( &pfh, IVSONLY_MAGIC, 4 ) != 0 &&
            memcmp( &pfh, IVS2_MAGIC, 4 ) != 0)
	{
		fmt = FORMAT_CAP;

		if( pfh.magic != TCPDUMP_MAGIC &&
			pfh.magic != TCPDUMP_CIGAM )
		{
			fprintf( stderr, "Unsupported file format "
				"(not a pcap or IVs file).\n" );
			goto read_fail;
		}

		/* read the rest of the pcap file header */

		if( ! atomic_read( &rb, fd, 20, (unsigned char *) &pfh + 4 ) )
		{
			perror( "read(file header) failed" );
			goto read_fail;
		}

		/* take care of endian issues and check the link type */

		if( pfh.magic == TCPDUMP_CIGAM )
			SWAP32( pfh.linktype );

		if( pfh.linktype != LINKTYPE_IEEE802_11 &&
			pfh.linktype != LINKTYPE_PRISM_HEADER &&
			pfh.linktype != LINKTYPE_RADIOTAP_HDR &&
			pfh.linktype != LINKTYPE_PPI_HDR)
		{
			fprintf( stderr, "This file is not a regular "
				"802.11 (wireless) capture.\n" );
			goto read_fail;
		}
	}
	else
	{
		if (memcmp( &pfh, IVS2_MAGIC, 4 ) == 0)
		{
			fmt = FORMAT_IVS2;

			if( ! atomic_read( &rb, fd, sizeof(struct ivs2_filehdr), (unsigned char *) &fivs2 ) )
			{
				perror( "read(file header) failed" );
				goto read_fail;
			}
			if(fivs2.version > IVS2_VERSION)
			{
				printf( "Error, wrong %s version: %d. Supported up to version %d.\n", IVS2_EXTENSION, fivs2.version, IVS2_VERSION );
				goto read_fail;
			}
		} 
	}

	if( fcntl( fd, F_SETFL, O_NONBLOCK ) < 0 )
	{
		perror( "fcntl(O_NONBLOCK) failed" );
		goto read_fail;
	}

	while( 1 )
	{
		if( close_aircrack )
			break;

		
		if( fmt == FORMAT_IVS )
		{
			/* read one IV */

			while( ! atomic_read( &rb, fd, 1, buffer ) )
				eof_wait( &eof_notified );

			if( close_aircrack )
				break;

			if( buffer[0] != 0xFF )
			{
				/* new access point MAC */

				bssid[0] = buffer[0];

				while( ! atomic_read( &rb, fd, 5, bssid + 1 ) )
					eof_wait( &eof_notified );
				if( close_aircrack )
					break;
			}

			while( ! atomic_read( &rb, fd, 5, buffer ) )
				eof_wait( &eof_notified );
			if( close_aircrack )
				break;
		}
		else if( fmt == FORMAT_IVS2 )
		{
			while( ! atomic_read( &rb, fd, sizeof( struct ivs2_pkthdr ), &ivs2 ) )
				eof_wait( &eof_notified );
			if( close_aircrack )
				break;

			if(ivs2.flags & IVS2_BSSID)
			{
				while( ! atomic_read( &rb, fd, 6, bssid ) )
					eof_wait( &eof_notified );
				if( close_aircrack )
					break;
				ivs2.len -= 6;
			}

			while( ! atomic_read( &rb, fd, ivs2.len, buffer ) )
				eof_wait( &eof_notified );
			if( close_aircrack )
				break;
		}
		else
		{
			while( ! atomic_read( &rb, fd, sizeof( pkh ), &pkh ) )
				eof_wait( &eof_notified );
			if( close_aircrack )
				break;

			if( pfh.magic == TCPDUMP_CIGAM ) {
				SWAP32( pkh.caplen );
				SWAP32( pkh.len );
			}

			if( pkh.caplen <= 0 || pkh.caplen > 65535 )
			{
				fprintf( stderr, "\nInvalid packet capture length %d - "
					"corrupted file?\n", pkh.caplen );
				eof_wait( &eof_notified );
				_exit( FAILURE );
			}

			while( ! atomic_read( &rb, fd, pkh.caplen, buffer ) )
				eof_wait( &eof_notified );
			if( close_aircrack )
				break;

			h80211 = buffer;

			if( pfh.linktype == LINKTYPE_PRISM_HEADER )
			{
				/* remove the prism header */

				if( h80211[7] == 0x40 )
					n = 64;
				else
				{
					n = *(int *)( h80211 + 4 );

					if( pfh.magic == TCPDUMP_CIGAM )
						SWAP32( n );
				}

				if( n < 8 || n >= (int) pkh.caplen )
					continue;

				h80211 += n; pkh.caplen -= n;
			}

			if( pfh.linktype == LINKTYPE_RADIOTAP_HDR )
			{
				/* remove the radiotap header */

				n = *(unsigned short *)( h80211 + 2 );

				if( n <= 0 || n >= (int) pkh.caplen )
					continue;

				h80211 += n; pkh.caplen -= n;
			}

			if( pfh.linktype == LINKTYPE_PPI_HDR )
			{
				/* Remove the PPI header */

				n = le16_to_cpu(*(unsigned short *)( h80211 + 2));

				if( n <= 0 || n>= (int) pkh.caplen )
					continue;

				/* for a while Kismet logged broken PPI headers */
				if ( n == 24 && le16_to_cpu(*(unsigned short *)(h80211 + 8)) == 2 )
					n = 32;

				if( n <= 0 || n>= (int) pkh.caplen )
					continue;

				h80211 += n; pkh.caplen -= n;
			}
		}
		

		/* prevent concurrent access on the linked list */

		pthread_mutex_lock( &mx_apl );

		nb_pkt++;

		if( fmt == FORMAT_CAP )
		{
			/* skip packets smaller than a 802.11 header */

			if( pkh.caplen < 24 )
				goto unlock_mx_apl;

			/* skip (uninteresting) control frames */

			if( ( h80211[0] & 0x0C ) == 0x04 )
				goto unlock_mx_apl;

			/* locate the access point's MAC address */

			switch( h80211[1] & 3 )
			{
				case  0: memcpy( bssid, h80211 + 16, 6 ); break;  //Adhoc
				case  1: memcpy( bssid, h80211 +  4, 6 ); break;  //ToDS
				case  2: memcpy( bssid, h80211 + 10, 6 ); break;  //FromDS
				case  3: memcpy( bssid, h80211 + 10, 6 ); break;  //WDS -> Transmitter taken as BSSID
			}

			switch( h80211[1] & 3 )
			{
				case  0: memcpy( dest, h80211 +  4, 6 ); break;  //Adhoc
				case  1: memcpy( dest, h80211 + 16, 6 ); break;  //ToDS
				case  2: memcpy( dest, h80211 +  4, 6 ); break;  //FromDS
				case  3: memcpy( dest, h80211 + 16, 6 ); break;  //WDS -> Transmitter taken as BSSID
			}

		}


		if( memcmp( bssid, BROADCAST, 6 ) == 0 )
			/* probe request or such - skip the packet */
			goto unlock_mx_apl;

		if( memcmp( bssid, opt.bssid, 6 ) != 0 )
			goto unlock_mx_apl;

		if( memcmp( opt.maddr, ZERO,      6 ) != 0 &&
			memcmp( opt.maddr, BROADCAST, 6 ) != 0 )
		{
			/* apply the MAC filter */

			if( memcmp( opt.maddr, h80211 +  4, 6 ) != 0 &&
				memcmp( opt.maddr, h80211 + 10, 6 ) != 0 &&
				memcmp( opt.maddr, h80211 + 16, 6 ) != 0 )
				goto unlock_mx_apl;
		}

		/* search the linked list */

		ap_prv = NULL;
		ap_cur = ap_1st;

		while( ap_cur != NULL )
		{
			if( ! memcmp( ap_cur->bssid, bssid, 6 ) )
				break;

			ap_prv = ap_cur;
			ap_cur = ap_cur->next;
		}

		/* if it's a new access point, add it */

		if( ap_cur == NULL )
		{
			if( ! ( ap_cur = (struct AP_info *) malloc(
				sizeof( struct AP_info ) ) ) )
			{
				perror( "malloc failed" );
				break;
			}

			memset( ap_cur, 0, sizeof( struct AP_info ) );

			if( ap_1st == NULL )
				ap_1st = ap_cur;
			else
				ap_prv->next = ap_cur;

			memcpy( ap_cur->bssid, bssid, 6 );

			ap_cur->crypt = -1;

			// Shortcut to set encryption:
			// - WEP is 2 for 'crypt' and 1 for 'amode'.
			// - WPA is 3 for 'crypt' and 2 for 'amode'.
			if (opt.forced_amode)
				ap_cur->crypt = opt.amode + 1;

		}
		
		if( fmt == FORMAT_IVS )
		{
			ap_cur->crypt = 2;

			
			goto unlock_mx_apl;
		}

		if( fmt == FORMAT_IVS2 )
		{
			if(ivs2.flags & IVS2_ESSID)
			{
				memcpy( ap_cur->essid, buffer, ivs2.len);
			}
			else if(ivs2.flags & IVS2_WPA)
			{
				ap_cur->crypt = 3;
				memcpy( &ap_cur->wpa, buffer,
					sizeof( struct WPA_hdsk ) );
			}
			goto unlock_mx_apl;
		}

		/* locate the station MAC in the 802.11 header */

		st_cur = NULL;

		switch( h80211[1] & 3 )
		{
			case  0: memcpy( stmac, h80211 + 10, 6 ); break;
			case  1: memcpy( stmac, h80211 + 10, 6 ); break;
			case  2:

				/* reject broadcast MACs */

				if( (h80211[4]%2) != 0 ) 
				  goto skip_station;
				memcpy( stmac, h80211 +  4, 6 ); 
				break;

			default: 
			  goto skip_station; 
			  break;
		}

		st_prv = NULL;
		st_cur = ap_cur->st_1st;

		while( st_cur != NULL )
		{
			if( ! memcmp( st_cur->stmac, stmac, 6 ) )
				break;

			st_prv = st_cur;
			st_cur = st_cur->next;
		}

		/* if it's a new supplicant, add it */

		if( st_cur == NULL )
		{
			if( ! ( st_cur = (struct ST_info *) malloc(
				sizeof( struct ST_info ) ) ) )
			{
				perror( "malloc failed" );
				break;
			}

			memset( st_cur, 0, sizeof( struct ST_info ) );

			if( ap_cur->st_1st == NULL )
				ap_cur->st_1st = st_cur;
			else
				st_prv->next = st_cur;

			memcpy( st_cur->stmac, stmac, 6 );
		}

		skip_station:

		/* packet parsing: Beacon or Probe Response */

		if( h80211[0] == 0x80 ||
			h80211[0] == 0x50 )
		{
			if( ap_cur->crypt < 0 )
				ap_cur->crypt = ( h80211[34] & 0x10 ) >> 4;

			p = h80211 + 36;

			while( p < h80211 + pkh.caplen )
			{
				if( p + 2 + p[1] > h80211 + pkh.caplen )
					break;

				if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' )
				{
					/* found a non-cloaked ESSID */

					n = ( p[1] > 32 ) ? 32 : p[1];

					memset( ap_cur->essid, 0, 33 );
					memcpy( ap_cur->essid, p + 2, n );
				}

				p += 2 + p[1];
			}
		}

		/* packet parsing: Association Request */

		if( h80211[0] == 0x00 )
		{
			p = h80211 + 28;

			while( p < h80211 + pkh.caplen )
			{
				if( p + 2 + p[1] > h80211 + pkh.caplen )
					break;

				if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' )
				{
					n = ( p[1] > 32 ) ? 32 : p[1];

					memset( ap_cur->essid, 0, 33 );
					memcpy( ap_cur->essid, p + 2, n );
				}

				p += 2 + p[1];
			}
		}

		/* packet parsing: Association Response */

		if( h80211[0] == 0x10 )
		{
			/* reset the WPA handshake state */

			if( st_cur != NULL )
				st_cur->wpa.state = 0;
		}

		/* check if data */

		if( ( h80211[0] & 0x0C ) != 0x08 )
			goto unlock_mx_apl;

		/* check minimum size */

		z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
		if ( ( h80211[0] & 0x80 ) == 0x80 )
			z+=2; /* 802.11e QoS */

		if( z + 16 > pkh.caplen )
			goto unlock_mx_apl;

		/* check the SNAP header to see if data is encrypted */

		if( h80211[z] != h80211[z + 1] || h80211[z + 2] != 0x03 )
		{
			/* save the IV & first two output bytes */

			memcpy( buffer    , h80211 + z    , 3 );
			memcpy( buffer + 3, h80211 + z + 4, 2 );

			/* Special handling for spanning-tree packets */
			if ( memcmp( h80211 +  4, SPANTREE, 6 ) == 0 ||
			    memcmp( h80211 + 16, SPANTREE, 6 ) == 0 )
			{
			    buffer[3] = (buffer[3] ^ 0x42) ^ 0xAA;
			    buffer[4] = (buffer[4] ^ 0x42) ^ 0xAA;
			}

		}

		if( ap_cur->crypt < 0 )
			ap_cur->crypt = 0;	 /* no encryption */

		/* if ethertype == IPv4, find the LAN address */

		z += 6;

		if( z + 20 < pkh.caplen )
		{
			if( h80211[z] == 0x08 && h80211[z + 1] == 0x00 &&
				( h80211[1] & 3 ) == 0x01 )
				memcpy( ap_cur->lanip, &h80211[z + 14], 4 );

			if( h80211[z] == 0x08 && h80211[z + 1] == 0x06 )
				memcpy( ap_cur->lanip, &h80211[z + 16], 4 );
		}

		/* check ethertype == EAPOL */

		if( h80211[z] != 0x88 || h80211[z + 1] != 0x8E )
			goto unlock_mx_apl;

		z += 2;

		ap_cur->eapol = 1;

		/* type == 3 (key), desc. == 254 (WPA) or 2 (RSN) */

		if( h80211[z + 1] != 0x03 ||
			( h80211[z + 4] != 0xFE && h80211[z + 4] != 0x02 ) )
			goto unlock_mx_apl;

		ap_cur->eapol = 0;
		
		ap_cur->crypt = 3;		 /* set WPA */

		if( st_cur == NULL )
		{
			pthread_mutex_unlock( &mx_apl );
			continue;
		}

		/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

		if( ( h80211[z + 6] & 0x08 ) != 0 &&
			( h80211[z + 6] & 0x40 ) == 0 &&
			( h80211[z + 6] & 0x80 ) != 0 &&
			( h80211[z + 5] & 0x01 ) == 0 )
		{
			memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );

			/* authenticator nonce set */
			st_cur->wpa.state = 1;
		}

		/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

		if( ( h80211[z + 6] & 0x08 ) != 0 &&
			( h80211[z + 6] & 0x40 ) == 0 &&
			( h80211[z + 6] & 0x80 ) == 0 &&
			( h80211[z + 5] & 0x01 ) != 0 )
		{
			if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
			{
				memcpy( st_cur->wpa.snonce, &h80211[z + 17], 32 );

								 /* supplicant nonce set */
				st_cur->wpa.state |= 2;
			}

			if( (st_cur->wpa.state & 4) != 4 )
			{
				/* copy the MIC & eapol frame */

				st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
					+   h80211[z + 3] + 4;

				if (st_cur->wpa.eapol_size == 0 || st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol)
					|| pkh.len - z < st_cur->wpa.eapol_size)
				{
					// Ignore the packet trying to crash us.
					st_cur->wpa.eapol_size = 0;
					goto unlock_mx_apl;
				}

				memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
				memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
				memset( st_cur->wpa.eapol + 81, 0, 16 );

									/* eapol frame & keymic set */
				st_cur->wpa.state |= 4;

				/* copy the key descriptor version */

				st_cur->wpa.keyver = h80211[z + 6] & 7;
			}
		}

		/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

		if( ( h80211[z + 6] & 0x08 ) != 0 &&
			( h80211[z + 6] & 0x40 ) != 0 &&
			( h80211[z + 6] & 0x80 ) != 0 &&
			( h80211[z + 5] & 0x01 ) != 0 )
		{
			if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
			{
				memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );

								 /* authenticator nonce set */
				st_cur->wpa.state |= 1;
			}

			if( (st_cur->wpa.state & 4) != 4 )
			{
				/* copy the MIC & eapol frame */

				st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
					+   h80211[z + 3] + 4;

				if (st_cur->wpa.eapol_size == 0 || st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol)
					|| pkh.len - z < st_cur->wpa.eapol_size)
				{
					// Ignore the packet trying to crash us.
					st_cur->wpa.eapol_size = 0;
					goto unlock_mx_apl;
				}

				memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
				memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
				memset( st_cur->wpa.eapol + 81, 0, 16 );

									/* eapol frame & keymic set */
				st_cur->wpa.state |= 4;

				/* copy the key descriptor version */

				st_cur->wpa.keyver = h80211[z + 6] & 7;
			}
		}

		if( st_cur->wpa.state == 7 )
		{
			/* got one valid handshake */

			memcpy( st_cur->wpa.stmac, stmac, 6 );
			memcpy( &ap_cur->wpa, &st_cur->wpa,
				sizeof( struct WPA_hdsk ) );
		}

		unlock_mx_apl:

		pthread_mutex_unlock( &mx_apl );

		if( ap_cur != NULL )
		{
			if( ( ap_cur->nb_ivs >= opt.max_ivs) ||
			    ( ap_cur->nb_ivs_clean >= opt.max_ivs ) ||
			    ( ap_cur->nb_ivs_vague >= opt.max_ivs ) )
			{
				eof_wait( &eof_notified );
				return;
			}
		}
	}

	read_fail:

	if(rb.buf1 != NULL)
	{
		free(rb.buf1);
		rb.buf1=NULL;
	}
	if(rb.buf2 != NULL)
	{
		free(rb.buf2);
		rb.buf2=NULL;
	}
	if(buffer != NULL)
	{
		free(buffer);
		buffer=NULL;
	}

	if(close_aircrack)
		return;

	//everything is going down
	kill( 0, SIGTERM );
	_exit( FAILURE );
}

void check_thread( void *arg )
{
	int fd, n, fmt;
	unsigned z;
	int eof_notified = 0;
	read_buf rb;
// 	int ret=0;

	unsigned char bssid[6];
	unsigned char dest[6];
	unsigned char stmac[6];
	unsigned char *buffer;
	unsigned char *h80211;
	unsigned char *p;
	//int weight[16];
	
	struct ivs2_pkthdr ivs2;
	struct ivs2_filehdr fivs2;
	
	struct pcap_pkthdr pkh;
	struct pcap_file_header pfh;
	struct AP_info *ap_prv, *ap_cur;
	struct ST_info *st_prv, *st_cur;

	signal( SIGINT, sighandler);

	memset( &rb, 0, sizeof( rb ) );
	ap_cur = NULL;

	memset(&pfh, 0, sizeof(struct pcap_file_header));

	if( ( buffer = (unsigned char *) malloc( 65536 ) ) == NULL )
	{
		/* there is no buffer */

		perror( "malloc failed" );
		goto read_fail;
	}

	h80211 = buffer;


	printf( "Opening %s\n", (char *) arg );

	if( strcmp( arg, "-" ) == 0 )
		fd = 0;
	else
	{
		if( ( fd = open( (char *) arg, O_RDONLY | O_BINARY ) ) < 0 )
		{
			perror( "open failed" );
			goto read_fail;
		}
	}

	if( ! atomic_read( &rb, fd, 4, &pfh ) )
	{
		perror( "read(file header) failed" );
		goto read_fail;
	}

	fmt = FORMAT_IVS;
	
	if( memcmp( &pfh, IVSONLY_MAGIC, 4 ) != 0 &&
            memcmp( &pfh, IVS2_MAGIC, 4 ) != 0)
	{
		fmt = FORMAT_CAP;

		if( pfh.magic != TCPDUMP_MAGIC &&
			pfh.magic != TCPDUMP_CIGAM )
		{
			fprintf( stderr, "Unsupported file format "
				"(not a pcap or IVs file).\n" );
			goto read_fail;
		}

		/* read the rest of the pcap file header */

		if( ! atomic_read( &rb, fd, 20, (unsigned char *) &pfh + 4 ) )
		{
			perror( "read(file header) failed" );
			goto read_fail;
		}

		/* take care of endian issues and check the link type */

		if( pfh.magic == TCPDUMP_CIGAM )
			SWAP32( pfh.linktype );

		if( pfh.linktype != LINKTYPE_IEEE802_11 &&
			pfh.linktype != LINKTYPE_PRISM_HEADER &&
			pfh.linktype != LINKTYPE_RADIOTAP_HDR &&
			pfh.linktype != LINKTYPE_PPI_HDR )
		{
			fprintf( stderr, "This file is not a regular "
				"802.11 (wireless) capture.\n" );
			goto read_fail;
		}
	}
	else
	{
		if (memcmp( &pfh, IVS2_MAGIC, 4 ) == 0)
		{
			fmt = FORMAT_IVS2;

			if( ! atomic_read( &rb, fd, sizeof(struct ivs2_filehdr), (unsigned char *) &fivs2 ) )
			{
				perror( "read(file header) failed" );
				goto read_fail;
			}
			if(fivs2.version > IVS2_VERSION)
			{
				printf( "Error, wrong %s version: %d. Supported up to version %d.\n", IVS2_EXTENSION, fivs2.version, IVS2_VERSION );
				goto read_fail;
			}
		} 
	}
	
	/* avoid blocking on reading the file */
	if( fcntl( fd, F_SETFL, O_NONBLOCK ) < 0 )
	{
		perror( "fcntl(O_NONBLOCK) failed" );
		goto read_fail;
	}

	while( 1 )
	{
		if( close_aircrack )
			break;

		
		if( fmt == FORMAT_IVS )
		{
			/* read one IV */

			while( ! atomic_read( &rb, fd, 1, buffer ) )
				goto read_fail;

			if( buffer[0] != 0xFF )
			{
				/* new access point MAC */

				bssid[0] = buffer[0];

				while( ! atomic_read( &rb, fd, 5, bssid + 1 ) )
					goto read_fail;
			}

			while( ! atomic_read( &rb, fd, 5, buffer ) )
				goto read_fail;
		}
		else if( fmt == FORMAT_IVS2 )
		{
			while( ! atomic_read( &rb, fd, sizeof( struct ivs2_pkthdr ), &ivs2 ) )
				goto read_fail;

			if(ivs2.flags & IVS2_BSSID)
			{
				while( ! atomic_read( &rb, fd, 6, bssid ) )
					goto read_fail;
				ivs2.len -= 6;
			}

			while( ! atomic_read( &rb, fd, ivs2.len, buffer ) )
				goto read_fail;
		}
		else
		{
			while( ! atomic_read( &rb, fd, sizeof( pkh ), &pkh ) )
				goto read_fail;

			if( pfh.magic == TCPDUMP_CIGAM ) {
				SWAP32( pkh.caplen );
				SWAP32( pkh.len );
			}

			if( pkh.caplen <= 0 || pkh.caplen > 65535 )
			{
				fprintf( stderr, "\nInvalid packet capture length %d - "
					"corrupted file?\n", pkh.caplen );
				goto read_fail;
				_exit( FAILURE );
			}

			while( ! atomic_read( &rb, fd, pkh.caplen, buffer ) )
				goto read_fail;

			h80211 = buffer;

			if( pfh.linktype == LINKTYPE_PRISM_HEADER )
			{
				/* remove the prism header */

				if( h80211[7] == 0x40 )
					n = 64;
				else
				{
					n = *(int *)( h80211 + 4 );

					if( pfh.magic == TCPDUMP_CIGAM )
						SWAP32( n );
				}

				if( n < 8 || n >= (int) pkh.caplen )
					continue;

				h80211 += n; pkh.caplen -= n;
			}

			if( pfh.linktype == LINKTYPE_RADIOTAP_HDR )
			{
				/* remove the radiotap header */

				n = *(unsigned short *)( h80211 + 2 );

				if( n <= 0 || n >= (int) pkh.caplen )
					continue;

				h80211 += n; pkh.caplen -= n;
			}

			if( pfh.linktype == LINKTYPE_PPI_HDR )
			{
				/* Remove the PPI header */

				n = le16_to_cpu(*(unsigned short *)( h80211 + 2));

				if( n <= 0 || n>= (int) pkh.caplen )
					continue;

				/* for a whole Kismet logged broken PPI headers */
				if ( n == 24 && le16_to_cpu(*(unsigned short *)(h80211 + 8)) == 2 )
					n = 32;

				if( n <= 0 || n>= (int) pkh.caplen )
					continue;

				h80211 += n; pkh.caplen -= n;
			}
		}
		
		/* prevent concurrent access on the linked list */

		pthread_mutex_lock( &mx_apl );

		nb_pkt++;

		if( fmt == FORMAT_CAP )
		{
			/* skip packets smaller than a 802.11 header */

			if( pkh.caplen < 24 )
				goto unlock_mx_apl;

			/* skip (uninteresting) control frames */

			if( ( h80211[0] & 0x0C ) == 0x04 )
				goto unlock_mx_apl;

			/* locate the access point's MAC address */

			switch( h80211[1] & 3 )
			{
				case  0: memcpy( bssid, h80211 + 16, 6 ); break;  //Adhoc
				case  1: memcpy( bssid, h80211 +  4, 6 ); break;  //ToDS
				case  2: memcpy( bssid, h80211 + 10, 6 ); break;  //FromDS
				case  3: memcpy( bssid, h80211 + 10, 6 ); break;  //WDS -> Transmitter taken as BSSID
			}

			switch( h80211[1] & 3 )
			{
				case  0: memcpy( dest, h80211 +  4, 6 ); break;  //Adhoc
				case  1: memcpy( dest, h80211 + 16, 6 ); break;  //ToDS
				case  2: memcpy( dest, h80211 +  4, 6 ); break;  //FromDS
				case  3: memcpy( dest, h80211 + 16, 6 ); break;  //WDS -> Transmitter taken as BSSID
			}

		}


		if( memcmp( bssid, BROADCAST, 6 ) == 0 )
			/* probe request or such - skip the packet */
			goto unlock_mx_apl;

		if( memcmp( opt.maddr, ZERO,      6 ) != 0 &&
			memcmp( opt.maddr, BROADCAST, 6 ) != 0 )
		{
			/* apply the MAC filter */

			if( memcmp( opt.maddr, h80211 +  4, 6 ) != 0 &&
				memcmp( opt.maddr, h80211 + 10, 6 ) != 0 &&
				memcmp( opt.maddr, h80211 + 16, 6 ) != 0 )
				goto unlock_mx_apl;
		}

		/* search the linked list */

		ap_prv = NULL;
		ap_cur = ap_1st;

		while( ap_cur != NULL )
		{
			if( ! memcmp( ap_cur->bssid, bssid, 6 ) )
				break;

			ap_prv = ap_cur;
			ap_cur = ap_cur->next;
		}

		/* if it's a new access point, add it */

		if( ap_cur == NULL )
		{
			if( ! ( ap_cur = (struct AP_info *) malloc(
				sizeof( struct AP_info ) ) ) )
			{
				perror( "malloc failed" );
				break;
			}

			memset( ap_cur, 0, sizeof( struct AP_info ) );

			if( ap_1st == NULL )
				ap_1st = ap_cur;
			else
				ap_prv->next = ap_cur;

			memcpy( ap_cur->bssid, bssid, 6 );

			ap_cur->crypt = -1;

			// Shortcut to set encryption:
			// - WEP is 2 for 'crypt' and 1 for 'amode'.
			// - WPA is 3 for 'crypt' and 2 for 'amode'.
			if (opt.forced_amode)
				ap_cur->crypt = opt.amode + 1;
		}
		
		if( fmt == FORMAT_IVS )
		{
			ap_cur->crypt = 2;

// 			add_wep_iv:
// 			/* check for uniqueness first */
// 
// 			if( ap_cur->nb_ivs == 0 )
// 				ap_cur->uiv_root = uniqueiv_init();
// 
// 			if( uniqueiv_check( ap_cur->uiv_root, buffer ) == 0 )
// 			{
// 				uniqueiv_mark( ap_cur->uiv_root, buffer );
// 				ap_cur->nb_ivs++;
// 			}

			goto unlock_mx_apl;
		}

		if( fmt == FORMAT_IVS2 )
		{
			if(ivs2.flags & IVS2_ESSID)
			{
				if (ivs2.len > 32) { // Max length of the ESSID (and length -1 of that field)
					fprintf(stderr, "Invalid SSID length, it must be <= 32\n");
					exit(1);
				}
				memcpy( ap_cur->essid, buffer, ivs2.len);
				if(opt.essid_set && ! strcmp( opt.essid, ap_cur->essid ) )
					memcpy( opt.bssid, ap_cur->bssid, 6 );
			}
			else if(ivs2.flags & IVS2_WPA)
			{
				ap_cur->crypt = 3;
				memcpy( &ap_cur->wpa, buffer,
					sizeof( struct WPA_hdsk ) );
			}
			goto unlock_mx_apl;
		}
		/* locate the station MAC in the 802.11 header */

		st_cur = NULL;

		switch( h80211[1] & 3 )
		{
			case  0: memcpy( stmac, h80211 + 10, 6 ); break;
			case  1: memcpy( stmac, h80211 + 10, 6 ); break;
			case  2:

				/* reject broadcast MACs */

				if( (h80211[4]%2) != 0 ) 
				  goto skip_station;
				memcpy( stmac, h80211 +  4, 6 ); 
				break;

			default: 
			  goto skip_station; 
			  break;
		}

		st_prv = NULL;
		st_cur = ap_cur->st_1st;

		while( st_cur != NULL )
		{
			if( ! memcmp( st_cur->stmac, stmac, 6 ) )
				break;

			st_prv = st_cur;
			st_cur = st_cur->next;
		}

		/* if it's a new supplicant, add it */

		if( st_cur == NULL )
		{
			if( ! ( st_cur = (struct ST_info *) malloc(
				sizeof( struct ST_info ) ) ) )
			{
				perror( "malloc failed" );
				break;
			}

			memset( st_cur, 0, sizeof( struct ST_info ) );

			if( ap_cur->st_1st == NULL )
				ap_cur->st_1st = st_cur;
			else
				st_prv->next = st_cur;

			memcpy( st_cur->stmac, stmac, 6 );
		}

		skip_station:

		/* packet parsing: Beacon or Probe Response */

		if( h80211[0] == 0x80 ||
			h80211[0] == 0x50 )
		{
			if( ap_cur->crypt < 0 )
				ap_cur->crypt = ( h80211[34] & 0x10 ) >> 4;

			p = h80211 + 36;

			while( p < h80211 + pkh.caplen )
			{
				if( p + 2 + p[1] > h80211 + pkh.caplen )
					break;

				if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' )
				{
					/* found a non-cloaked ESSID */

					n = ( p[1] > 32 ) ? 32 : p[1];

					memset( ap_cur->essid, 0, 33 );
					memcpy( ap_cur->essid, p + 2, n );
				}

				p += 2 + p[1];
			}
		}

		/* packet parsing: Association Request */

		if( h80211[0] == 0x00 )
		{
			p = h80211 + 28;

			while( p < h80211 + pkh.caplen )
			{
				if( p + 2 + p[1] > h80211 + pkh.caplen )
					break;

				if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' )
				{
					n = ( p[1] > 32 ) ? 32 : p[1];

					memset( ap_cur->essid, 0, 33 );
					memcpy( ap_cur->essid, p + 2, n );
				}

				p += 2 + p[1];
			}
		}

		/* packet parsing: Association Response */

		if( h80211[0] == 0x10 )
		{
			/* reset the WPA handshake state */

			if( st_cur != NULL )
				st_cur->wpa.state = 0;
		}

		/* check if data */

		if( ( h80211[0] & 0x0C ) != 0x08 )
			goto unlock_mx_apl;

		/* check minimum size */

		z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
		if ( ( h80211[0] & 0x80 ) == 0x80 )
			z+=2; /* 802.11e QoS */

		if( z + 16 > pkh.caplen )
			goto unlock_mx_apl;

		/* check the SNAP header to see if data is encrypted */

		if( h80211[z] != h80211[z + 1] || h80211[z + 2] != 0x03 )
		{

			/* check the extended IV flag */

			if( ( h80211[z + 3] & 0x20 ) != 0 && !opt.forced_amode)
			{
				/* encryption = WPA */
				ap_cur->crypt = 3;
			}

			/* save the IV & first two output bytes */

			memcpy( buffer    , h80211 + z    , 3 );

		}

		if( ap_cur->crypt < 0 )
			ap_cur->crypt = 0;	 /* no encryption */

		/* if ethertype == IPv4, find the LAN address */

		z += 6;

		if( z + 20 < pkh.caplen )
		{
			if( h80211[z] == 0x08 && h80211[z + 1] == 0x00 &&
				( h80211[1] & 3 ) == 0x01 )
				memcpy( ap_cur->lanip, &h80211[z + 14], 4 );

			if( h80211[z] == 0x08 && h80211[z + 1] == 0x06 )
				memcpy( ap_cur->lanip, &h80211[z + 16], 4 );
		}

		/* check ethertype == EAPOL */

		if( h80211[z] != 0x88 || h80211[z + 1] != 0x8E )
			goto unlock_mx_apl;

		z += 2;

		ap_cur->eapol = 1;

		/* type == 3 (key), desc. == 254 (WPA) or 2 (RSN) */

		if( h80211[z + 1] != 0x03 ||
			( h80211[z + 4] != 0xFE && h80211[z + 4] != 0x02 ) )
			goto unlock_mx_apl;

		ap_cur->eapol = 0;
		
		ap_cur->crypt = 3;		 /* set WPA */

		if( st_cur == NULL )
		{
			pthread_mutex_unlock( &mx_apl );
			continue;
		}

		/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

		if( ( h80211[z + 6] & 0x08 ) != 0 &&
			( h80211[z + 6] & 0x40 ) == 0 &&
			( h80211[z + 6] & 0x80 ) != 0 &&
			( h80211[z + 5] & 0x01 ) == 0 )
		{
			memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );

			/* authenticator nonce set */
			st_cur->wpa.state = 1;
		}

		/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

		if( ( h80211[z + 6] & 0x08 ) != 0 &&
			( h80211[z + 6] & 0x40 ) == 0 &&
			( h80211[z + 6] & 0x80 ) == 0 &&
			( h80211[z + 5] & 0x01 ) != 0 )
		{
			if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
			{
				memcpy( st_cur->wpa.snonce, &h80211[z + 17], 32 );

								 /* supplicant nonce set */
				st_cur->wpa.state |= 2;
			}

			if( (st_cur->wpa.state & 4) != 4 )
			{
				/* copy the MIC & eapol frame */

				st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
					+   h80211[z + 3] + 4;

				if (st_cur->wpa.eapol_size == 0 || st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol)
					|| pkh.len - z < st_cur->wpa.eapol_size)
				{
					// Ignore the packet trying to crash us.
					st_cur->wpa.eapol_size = 0;
					goto unlock_mx_apl;
				}

				memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
				memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
				memset( st_cur->wpa.eapol + 81, 0, 16 );

									/* eapol frame & keymic set */
				st_cur->wpa.state |= 4;

				/* copy the key descriptor version */

				st_cur->wpa.keyver = h80211[z + 6] & 7;
			}
		}

		/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

		if( ( h80211[z + 6] & 0x08 ) != 0 &&
			( h80211[z + 6] & 0x40 ) != 0 &&
			( h80211[z + 6] & 0x80 ) != 0 &&
			( h80211[z + 5] & 0x01 ) != 0 )
		{
			if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
			{
				memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );

								 /* authenticator nonce set */
				st_cur->wpa.state |= 1;
			}

			if( (st_cur->wpa.state & 4) != 4 )
			{
				/* copy the MIC & eapol frame */

				st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
					+   h80211[z + 3] + 4;

				if (st_cur->wpa.eapol_size == 0 || st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol)
					|| pkh.len - z < st_cur->wpa.eapol_size)
				{
					// Ignore the packet trying to crash us.
					st_cur->wpa.eapol_size = 0;
					goto unlock_mx_apl;
				}

				memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
				memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
				memset( st_cur->wpa.eapol + 81, 0, 16 );

									/* eapol frame & keymic set */
				st_cur->wpa.state |= 4;

				/* copy the key descriptor version */

				st_cur->wpa.keyver = h80211[z + 6] & 7;
			}
		}

		if( st_cur->wpa.state == 7 )
		{
			/* got one valid handshake */

			memcpy( st_cur->wpa.stmac, stmac, 6 );
			memcpy( &ap_cur->wpa, &st_cur->wpa,
				sizeof( struct WPA_hdsk ) );
		}

		unlock_mx_apl:

		pthread_mutex_unlock( &mx_apl );

		if( ap_cur != NULL )
			if( ap_cur->nb_ivs >= opt.max_ivs )
				break;
	}

	read_fail:

	if(rb.buf1 != NULL)
	{
		free(rb.buf1);
		rb.buf1 = NULL;
	}
	if(rb.buf2 != NULL)
	{
		free(rb.buf2);
		rb.buf2 = NULL;
	}
	if(buffer != NULL)
	{
		free(buffer);
		buffer = NULL;
	}

	return;
}

/* timing routine */

float chrono( struct timeval *start, int reset )
{
	float delta;
	struct timeval current;

	gettimeofday( &current, NULL );

	delta = ( current.tv_sec  - start->tv_sec  ) + (float)
		( current.tv_usec - start->tv_usec ) / 1000000;

	if( reset )
		gettimeofday( start, NULL );

	return( delta );
}

/* display the current wpa key info, matrix-like */

void show_wpa_stats( char *key, int keylen, unsigned char pmk[32], unsigned char ptk[64],
unsigned char mic[16], int force )
{
	float delta;
	int i, et_h, et_m, et_s;
	char tmpbuf[28];

	if (chrono( &t_stats, 0 ) < 0.15 && force == 0)
		return;

	if (force != 0)
		pthread_mutex_lock(&mx_wpastats);  // if forced, wait until we can lock
	else
		if (pthread_mutex_trylock(&mx_wpastats) != 0)  // if not forced, just try
			return;

	chrono( &t_stats, 1 );

	delta = chrono( &t_begin, 0 );

	et_h =   delta / 3600;
	et_m = ( delta - et_h * 3600 ) / 60;
	et_s =   delta - et_h * 3600 - et_m * 60;

	if( ( delta = chrono( &t_kprev, 0 ) ) >= 6 )
	{
		int delta0;
		delta0 = delta;

		t_kprev.tv_sec += 3;
		delta = chrono( &t_kprev, 0 );
		nb_kprev *= delta / delta0;

	}

	if (_speed_test) {
		int ks = (int) ((float) nb_kprev / delta);

		printf("%d k/s\r", ks);
		fflush(stdout);

		if (et_s >= 5) {
			printf("\n");
			exit(0);
		}

		goto __out;
	}

	if( opt.l33t ) printf( "\33[33;1m" );
	printf( "\33[5;20H[%02d:%02d:%02d] %lld keys tested "
		"(%2.2f k/s)", et_h, et_m, et_s,
		nb_tried, (float) nb_kprev / delta);

	memset( tmpbuf, ' ', sizeof( tmpbuf ) );
	memcpy( tmpbuf, key, keylen > 27 ? 27 : keylen );
	tmpbuf[27] = '\0';

	if( opt.l33t ) printf( "\33[37;1m" );
	printf( "\33[8;24HCurrent passphrase: %s\n", tmpbuf );

	if( opt.l33t ) printf( "\33[32;22m" );
	printf( "\33[11;7HMaster Key     : " );

	if( opt.l33t ) printf( "\33[32;1m" );
	for( i = 0; i < 32; i++ )
	{
		if( i == 16 ) printf( "\n\33[23C" );
		printf( "%02X ", pmk[i] );
	}

	if( opt.l33t ) printf( "\33[32;22m" );
	printf( "\33[14;7HTransient Key  : " );

	if( opt.l33t ) printf( "\33[32;1m" );
	for( i = 0; i < 64; i++ )
	{
		if( i > 0 && i % 16 == 0 ) printf( "\n\33[23C" );
		printf( "%02X ", ptk[i] );
	}

	if( opt.l33t ) printf( "\33[32;22m" );
	printf( "\33[19;7HEAPOL HMAC     : " );

	if( opt.l33t ) printf( "\33[32;1m" );
	for( i = 0; i < 16; i++ )
		printf( "%02X ", mic[i] );

	printf( "\n" );
__out:
	pthread_mutex_unlock(&mx_wpastats);
}


int crack_wpa_thread( void *arg )
{
	
	FILE * keyFile;
	char  essid[36];
	char  key[4][128];
	unsigned char pmk[4][128];

	unsigned char pke[100];
	unsigned char ptk[4][80];
	unsigned char mic[4][20];

	struct WPA_data* data;
	struct AP_info* ap;
	int thread;
	int ret=0;
	int i, j, len, slen;
	int nparallel = 1;

#if defined(__i386__) || defined(__x86_64__)
	// Check for SSE2, with SSE2 the algorithm works with 4 keys
	if (shasse2_cpuid()>=2)
		nparallel = 4;
#endif

	data = (struct WPA_data*)arg;
	ap = data->ap;
	thread = data->thread;
	strncpy(essid, ap->essid, 36);

	/* pre-compute the key expansion buffer */
	memcpy( pke, "Pairwise key expansion", 23 );
	if( memcmp( ap->wpa.stmac, ap->bssid, 6 ) < 0 )	{
		memcpy( pke + 23, ap->wpa.stmac, 6 );
		memcpy( pke + 29, ap->bssid, 6 );
	} else {
		memcpy( pke + 23, ap->bssid, 6 );
		memcpy( pke + 29, ap->wpa.stmac, 6 );
	}
	if( memcmp( ap->wpa.snonce, ap->wpa.anonce, 32 ) < 0 ) {
		memcpy( pke + 35, ap->wpa.snonce, 32 );
		memcpy( pke + 67, ap->wpa.anonce, 32 );
	} else {
		memcpy( pke + 35, ap->wpa.anonce, 32 );
		memcpy( pke + 67, ap->wpa.snonce, 32 );
	}

	/* receive the essid */

	slen = strlen(essid) + 4;

	while( 1 )
	{
		if (close_aircrack)
			pthread_exit(&ret);

		/* receive passphrases */

		for(j=0; j<nparallel; ++j)
		{
			key[j][0]=0;

			while(wpa_receive_passphrase(key[j], data)==0)
			{
				if (wpa_wordlists_done==1) // if no more words will arrive and...
				{
					if (j==0) // ...this is the first key in this loop: there's nothing else to do
						return 0;
					else	  // ...we have some key pending in this loop: keep working
						break;
				}

				sched_yield(); // yield the processor until there are keys available
				// this only happens when the queue is empty (when beginning and ending the wordlist)
			}

			key[j][127]=0;
		}


		// PMK calculation
		if (nparallel==4)
			calc_4pmk(key[0], key[1], key[2], key[3], essid, pmk[0], pmk[1], pmk[2], pmk[3]);
		else
			for(j=0; j<nparallel; ++j)
				calc_pmk( key[j], essid, pmk[j] );

		for(j=0; j<nparallel; ++j)
		{
			/* compute the pairwise transient key and the frame MIC */

			for (i = 0; i < 4; i++)
			{
				pke[99] = i;
				HMAC(EVP_sha1(), pmk[j], 32, pke, 100, ptk[j] + i * 20, NULL);
			}

			if (ap->wpa.keyver == 1)
				HMAC(EVP_md5(), ptk[j], 16, ap->wpa.eapol, ap->wpa.eapol_size, mic[j], NULL);
			else
				HMAC(EVP_sha1(), ptk[j], 16, ap->wpa.eapol, ap->wpa.eapol_size, mic[j], NULL);

			if (memcmp( mic[j], ap->wpa.keymic, 16 ) == 0)
			{
				// to stop do_wpa_crack, we close the dictionary
				pthread_mutex_lock( &mx_dic );
				if(opt.dict != NULL)
				{
					if (!opt.stdin_dict) fclose(opt.dict);
					opt.dict = NULL;
				}
				pthread_mutex_unlock( &mx_dic );
				for( i = 0; i < opt.nbcpu; i++ )
				{
					// we make sure do_wpa_crack doesn't block before exiting,
					// now that we're not consuming passphrases here any longer
					pthread_mutex_lock(&wpa_data[i].mutex);
					pthread_cond_signal(&wpa_data[i].cond);
					pthread_mutex_unlock(&wpa_data[i].mutex);
				}

				memcpy(data->key, key[j], sizeof(data->key));

				// Write the key to a file
				if (opt.logKeyToFile != NULL) {
					keyFile = fopen(opt.logKeyToFile, "w");
					if (keyFile != NULL)
					{
						fprintf(keyFile, "%s", key[j]);
						fclose(keyFile);
					}
				}

				pthread_mutex_lock(&mx_nb);
				nb_tried += 4;

				// # of key tried might not always be a multiple of 4
				if(key[0][0]==0) nb_tried--;
				if(key[1][0]==0) nb_tried--;
				if(key[2][0]==0) nb_tried--;
				if(key[3][0]==0) nb_tried--;

				nb_kprev += 4;
				pthread_mutex_unlock(&mx_nb);

				len = strlen(key[j]);
				if (len > 64 ) len = 64;
				if (len < 8) len = 8;
				show_wpa_stats( key[j], len, pmk[j], ptk[j], mic[j], 1 );

				if (opt.l33t)
					printf( "\33[31;1m" );

				printf("\33[8;%dH\33[2KKEY FOUND! [ %s ]\33[11B\n",
					( 80 - 15 - (int) len ) / 2, key[j] );

				if (opt.l33t)
					printf( "\33[32;22m" );

				return SUCCESS;
			}
		}

		pthread_mutex_lock(&mx_nb);
		nb_tried += 4;

		// # of key tried might not always be a multiple of 4
		if(key[0][0]==0) nb_tried--;
		if(key[1][0]==0) nb_tried--;
		if(key[2][0]==0) nb_tried--;
		if(key[3][0]==0) nb_tried--;

		nb_kprev += 4;
		pthread_mutex_unlock(&mx_nb);

		{
			len = strlen(key[0]);
			if (len > 64 ) len = 64;
			if (len < 8) len = 8;

			show_wpa_stats(key[0], len, pmk[0], ptk[0], mic[0], 0);
		}
	}
}

/**
 * Open a specific dictionary
 * nb: index of the dictionary
 * return 0 on success and FAILURE if it failed
 */
int next_dict(int nb)
{

	pthread_mutex_lock( &mx_dic );
	if(opt.dict != NULL)
	{
		if(!opt.stdin_dict) fclose(opt.dict);
		opt.dict = NULL;
	}
	opt.nbdict = nb;
	if(opt.dicts[opt.nbdict] == NULL)
	{
		pthread_mutex_unlock( &mx_dic );
		return( FAILURE );
	}

	while(opt.nbdict < MAX_DICTS && opt.dicts[opt.nbdict] != NULL)
	{
		if( strcmp( opt.dicts[opt.nbdict], "-" ) == 0 )
		{
			opt.stdin_dict = 1;

			if( ( opt.dict = fdopen( fileno(stdin) , "r" ) ) == NULL )
			{
				perror( "fopen(dictionary) failed" );
				opt.nbdict++;
				continue;
			}

			opt.no_stdin = 1;
		}
		else
		{
			opt.stdin_dict = 0;
			if( ( opt.dict = fopen( opt.dicts[opt.nbdict], "r" ) ) == NULL )
			{
				perror( "fopen(dictionary) failed" );
				opt.nbdict++;
				continue;
			}

			fseek(opt.dict, 0L, SEEK_END);

			if ( ftello( opt.dict ) <= 0L )
			{
				printf("ERROR: %s\n", strerror(errno));
				fclose( opt.dict );
				opt.dict = NULL;
				opt.nbdict++;
				continue;
			}

			rewind( opt.dict );
		}
		break;
	}

	pthread_mutex_unlock( &mx_dic );

	if(opt.nbdict >= MAX_DICTS || opt.dicts[opt.nbdict] == NULL)
	    return( FAILURE );

	return( 0 );
}

int do_wpa_crack()
{
	int i, j, cid, num_cpus, res;
	char key1[128];

    i = 0;
	res = 0;
	opt.amode = 2;
	num_cpus = opt.nbcpu;


	if(  !_speed_test)
	{
		if( opt.l33t )
			printf( "\33[37;40m" );

		printf( "\33[2J" );

		if( opt.l33t )
			printf( "\33[34;1m" );

		printf("\33[2;34H%s",progname);
	}

	cid = 0;
	while( num_cpus > 0 )
	{
		/* read a couple of keys (skip those < 8 chars) */

		pthread_mutex_lock( &mx_dic );

		if(opt.dict == NULL)
		{
			pthread_mutex_unlock( &mx_dic );
			return( FAILURE );
		}
		else
			pthread_mutex_unlock( &mx_dic );
		do
		{
			memset(key1, 0, sizeof(key1));
			if (_speed_test)
				strcpy(key1, "sorbosorbo");
			else
			{
				pthread_mutex_lock( &mx_dic );
				if (fgets(key1, sizeof(key1), opt.dict) == NULL)
				{
					pthread_mutex_unlock( &mx_dic );

					if( opt.l33t )
						printf( "\33[32;22m" );
					/* printf( "\nPassphrase not in dictionary %s \n", opt.dicts[opt.nbdict] );*/
					if(next_dict(opt.nbdict+1) != 0)
					{
						/* no more words, but we still have to wait for the cracking threads */
						num_cpus = cid;
						//goto collect_and_test;
						return( FAILURE );
					}
					else
						continue;
				}
				else
					pthread_mutex_unlock( &mx_dic );
			}
			i = strlen( key1 );
			if( i < 8 ) continue;
			if( i > 64 ) i = 64;

			while(i>0 && (key1[i-1]=='\r' || key1[i-1]=='\n')) i--;
 			if (i<=0) continue;
			key1[i] = '\0';

			for(j=0; j<i; j++)
				if(!isascii(key1[j]) || key1[j] < 32) i=0;

		}
		while( i < 8 );

		/* send the keys */

		for(i=0; i<opt.nbcpu; ++i)
		{
			res = wpa_send_passphrase(key1, &(wpa_data[cid]), 0/*don't block*/);
			if (res != 0)
				break;
			cid = (cid+1) % opt.nbcpu;
		}

		if (res==0) // if all queues are full, we block until there's room
		{
			wpa_send_passphrase(key1, &(wpa_data[cid]), 1/*block*/);
			cid = (cid+1) % opt.nbcpu;
		}
	}

	//printf( "\nPassphrase not in dictionary \n" );
	return( FAILURE );
}


int next_key( char **key, int keysize )
{
	char *tmp, *tmpref;
	int i, rtn;
	unsigned int dec;
	char *hex;

	tmpref = tmp = (char*) malloc(1024);

	while(1)
	{
		rtn = 0;
		pthread_mutex_lock( &mx_dic );
		if(opt.dict == NULL)
		{
			pthread_mutex_unlock( &mx_dic );
			//printf( "\nPassphrase not in dictionary \n" );
			free(tmpref);
			tmp = NULL;
			return( FAILURE );
		}
		else
			pthread_mutex_unlock( &mx_dic );

		if( opt.hexdict[opt.nbdict] )
		{
			pthread_mutex_lock( &mx_dic );
			if( fgets( tmp, ((keysize*2)+(keysize-1)), opt.dict ) == NULL )
			{
				pthread_mutex_unlock( &mx_dic );
				if( opt.l33t )
					printf( "\33[32;22m" );

//				printf( "\nPassphrase not in dictionary \"%s\" \n", opt.dicts[opt.nbdict] );
				if(next_dict(opt.nbdict+1) != 0)
				{
					free(tmpref);
					tmp = NULL;
					return( FAILURE );
				}
				else
					continue;
			}
			else
				pthread_mutex_unlock( &mx_dic );

			i=strlen(tmp);

			if( i <= 2 ) continue;

			if( tmp[i - 1] == '\n' ) tmp[--i] = '\0';
			if( tmp[i - 1] == '\r' ) tmp[--i] = '\0';
			if( i <= 0 ) continue;

			i=0;

			hex = strsep(&tmp, ":");

			while( i<keysize && hex != NULL )
			{
				if(strlen(hex) > 2 || strlen(hex) == 0)
				{
					rtn = 1;
					break;
				}
				if(sscanf(hex, "%x", &dec) == 0 )
				{
					rtn = 1;
					break;
				}

				(*key)[i] = dec;
				hex = strsep(&tmp, ":");
				i++;
			}
			if(rtn)
			{
				continue;
			}
		}
		else
		{
			pthread_mutex_lock( &mx_dic );
			if( fgets( *key, keysize, opt.dict ) == NULL )
			{
				pthread_mutex_unlock( &mx_dic );
				if( opt.l33t )
					printf( "\33[32;22m" );

//				printf( "\nPassphrase not in dictionary \"%s\" \n", opt.dicts[opt.nbdict] );
				if(next_dict(opt.nbdict+1) != 0)
				{
					free(tmpref);
					tmp = NULL;
					return( FAILURE );
				}
				else
					continue;
			}
			else
				pthread_mutex_unlock( &mx_dic );

			i=strlen(*key);

			if( i <= 2 ) continue;

			if( (*key)[i - 1] == '\n' ) (*key)[--i] = '\0';
			if( (*key)[i - 1] == '\r' ) (*key)[--i] = '\0';

			if( i <= 0 ) continue;
		}

		break;
	}

	free(tmpref);
	return( SUCCESS );
}


int set_dicts(char* optargs)
{
	int len;
	char *optarg;

	opt.nbdict = 0;
	optarg = strsep(&optargs, ",");

	for(len=0; len<MAX_DICTS; len++)
	{
		opt.dicts[len] = NULL;
	}

	while(optarg != NULL && opt.nbdict<MAX_DICTS)
	{
		len = strlen(optarg)+1;
		opt.dicts[opt.nbdict] = (char*)malloc(len * sizeof(char));
		if(opt.dicts[opt.nbdict] == NULL)
		{
			perror("allocation failed!");
			return( FAILURE );
		}
		if(strncasecmp(optarg, "h:", 2) == 0)
		{
			strncpy(opt.dicts[opt.nbdict], optarg+2, len-2);
			opt.hexdict[opt.nbdict] = 1;
		}
		else
		{
			strncpy(opt.dicts[opt.nbdict], optarg, len);
			opt.hexdict[opt.nbdict] = 0;
		}
		optarg = strsep(&optargs, ",");
		opt.nbdict++;
	}

	next_dict(0);

	while(next_dict(opt.nbdict+1) == 0) {}

	next_dict(0);

	return 0;
}