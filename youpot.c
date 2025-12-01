/* YouPot proxy-back honeypot
 * Author: Jacek Lipkowski SQ5BPF youpot@lipkowski.org
 *
 * Youpot is a novel proxy-back pure honeypot for worms (and other adversaries)
 * While other honeypots will put a lot of effort into emulating some service,
 * we will just proxy the TCP connection back to the original host on the 
 * same destination port.
 *
 * For citation please use CITATION.cff
 *
 * This software is licensed under the GNU General Public License v3.0
 * Also provided in the file LICENSE.
 *
 * Currently tracked in https://github.com/sq5bpf/youpot
 *
 * Changelog:
 * 20251201: made tls detction more permissive
 * 20251127: added an option to cleanup the helper process so that ssh_mitm does not have to be patched
 * 20250530: initial public release
 *
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <linux/netfilter_ipv4.h>


#define CERT_FILE "/home/youpot/youpot/certs.pem"


#define PORT 65534
#define BACKLOG 10

#define LOG_DIR "/home/youpot/youpot/log"
#define LOG_FILE "/home/youpot/youpot/log/youpot.log"

#define PROTOCOL_GENERIC 0
#define PROTOCOL_GENERIC 0
#define PROTOCOL_SSH 1
#define PROTOCOL_OLDSSH 2
#define PROTOCOL_ANCIENTSSH 3
#define PROTOCOL_TLS 4


#define MAX_CLIENTS 100 /* overkill, rarely goes above 5 */
#define FIRST_PORT 10000

#define CONNECT_TIMEOUT 5
#define CONNECTION_TIME 60

#define STATE_NOTCONNECTED 0
#define STATE_CONNECTED 1
#define STATE_DISCONNECTED 2


/* pattern stuff, should be moved into a separate file */
#define MAX_PATTERNS 100 /* TODO: make this dynamic */
#define PATTERN_FROMCLIENT_DIR "/home/youpot/youpot/patterns_fromclient"
#define PATTERN_FROMSERVER_DIR "/home/youpot/youpot/patterns_fromserver"
struct pattern {
	char *description; /* a text description */
	unsigned char *pattern; /* what we search for */
	int pattern_len;
	unsigned char *replace; /* what we replace it with */
	int replace_len;
};
struct pattern patterns_fromclient[MAX_PATTERNS];
struct pattern patterns_fromserver[MAX_PATTERNS];

void init_patterns() {
	memset((void *)&patterns_fromclient,0,sizeof(patterns_fromclient));
	memset((void *)&patterns_fromserver,0,sizeof(patterns_fromserver));
}

/* read patterns */
void read_patterns(char *patdir,struct pattern patterns[]) {
	int i;
	char tmpstr[512];
	struct stat statbuf;
	int fp,fr,fd;
	
	printf("read patterns from %s\n",patdir);
	for(i=0;i<MAX_PATTERNS;i++) {
		if (patterns[i].description) { free(patterns[i].description); }
		if (patterns[i].pattern) { free(patterns[i].pattern); }
		if (patterns[i].replace) { free(patterns[i].replace); }
		memset((void *)&patterns[i],0,sizeof(struct pattern));
	}
	for(i=0;i<MAX_PATTERNS;i++) {

		snprintf(tmpstr,sizeof(tmpstr)-1,"%s/pattern_%i",patdir,i);
		fp=open(tmpstr,O_RDONLY);
		snprintf(tmpstr,sizeof(tmpstr)-1,"%s/replace_%i",patdir,i);
		fr=open(tmpstr,O_RDONLY);
		if ((fp>0)&&(fr>0)) {
			fstat(fp,&statbuf);
			patterns[i].pattern=calloc(statbuf.st_size,1);
			patterns[i].pattern_len=read(fp,patterns[i].pattern,statbuf.st_size);

			fstat(fr,&statbuf);
			patterns[i].replace=calloc(statbuf.st_size,1);
			patterns[i].replace_len=read(fr,patterns[i].replace,statbuf.st_size);


			snprintf(tmpstr,sizeof(tmpstr)-1,"%s/descr_%i",patdir,i);
			fd=open(tmpstr,O_RDONLY);
			if (fd>0) {
				fstat(fd,&statbuf);
				patterns[i].description=calloc(statbuf.st_size+1,1);
				read(fd,patterns[i].description,statbuf.st_size);
				close(fd);

				char *c=patterns[i].description;
				while (*c) { if ((*c=='\n')||(*c=='\r')) *c=0; c++; }

			} else {
				snprintf(tmpstr,sizeof(tmpstr)-1,"pattern %i",i);
				patterns[i].description=strdup(tmpstr);
			}

			printf("read pattern %i description:[%s] pattern_len=%i replace_len=%i\n",i,patterns[i].description,patterns[i].pattern_len,patterns[i].replace_len);

		}
		if (fp>0) { close(fp); }
		if (fr>0) { close(fr); }
	}
}

/* replace pattern in memory with another pattern. note: the whole replacement thing is very inefficient: is called multiple times, reallocates memory and copies constantly. TODO: write it so that it doesn't suck */
int replacer(unsigned char *origbuf,int origlen, unsigned char **newbuf, int *newlen, struct pattern *pat) 
{
        unsigned char *patptr=0;
        unsigned char *buf2;
        ptrdiff_t x;
        int nl;
        if ((pat->pattern_len)==0) { 
                *newbuf=origbuf;
                *newlen=origlen;
                return(0);
        }

        patptr=memmem(origbuf,origlen,pat->pattern,pat->pattern_len);
        if (!patptr) return(0);

        nl=origlen+pat->replace_len-pat->pattern_len;
        buf2=calloc(nl,1);
        x=(unsigned char *)patptr-(unsigned char *)origbuf;
        memcpy(buf2,origbuf,(int )x);
        memcpy((unsigned char *)(buf2+(int)x),pat->replace,pat->replace_len);
        memcpy((unsigned char *)(buf2+(int)x+pat->replace_len),(unsigned char *)(origbuf+(int)x+pat->pattern_len),origlen-((int)x+pat->pattern_len));

        *newbuf=buf2;
        *newlen=nl;

        return(1);

}

void sighup_handler(int s) {
	read_patterns(PATTERN_FROMCLIENT_DIR,patterns_fromclient);
	read_patterns(PATTERN_FROMSERVER_DIR,patterns_fromserver);
}


struct client {
	pid_t pid;
	int helper_port;
	int kill_port; /* when killing it, wait for the helper to close helper_port */
	char *log_dir;
	char *host_log_dir;
	char *hostport_log_dir;
	char *log_file;
	char *hexdump_file; /* file with hexdump of traffic, btw we have multiple files with the traffic because each type has a usecase */
	char *json_file; /* json file with traffic */
	char *pcap_file; /* made-up pcap file with traffic */
	char *text_file; /* text file with traffic, view in something which is binary safe like less or cat -A */
	char *client_addr; /* ip address of the client that is connectin to us */
	int client_srcport; /* the source port of the connection */
	int client_dstport; /* the destination port */
	int connection_state; /* did we have a real connection here? */
	int helper_pid; 
	int rxbytes;
	int txbytes;
	int rxblocks;
	int txblocks;
	time_t start_time;
};

volatile struct client clients[MAX_CLIENTS];
int current_slot=-1;

/* tell the oom killer that we like to be killed */
void adjust_oom() {
	int i;
	i=open("/proc/self/oom_score_adj",O_WRONLY);
	if (i>0) {
		write(i,"999\n",4); /* 666 upside-down */
		close(i);
	}
}

void appendfile(char *file,char *msg) {
	FILE *f;
	f=fopen(file,"ab");
	if (f) {
		//	fprintf(f,"%s\n",msg);
		fputs(msg,f);
		fclose(f);
	}
}

/* logs a message */
void logit(char *msg,char *file,int log_console,int log_file) {
	char buf1[64];
	char buf2[1024];
	struct tm *tmp;
	time_t	 t = time(NULL);

	tmp = gmtime(&t);
	if (strftime(buf1, sizeof(buf1), "%Y%m%d %H:%M:%S", tmp) == 0) {
		/* should not happen. panic! */
		fprintf(stderr, "strftime returned 0");
		exit(EXIT_FAILURE);
	}
	if (current_slot==-1) {
		snprintf(buf2,sizeof(buf2),"%s youpot[%i]: mainproc %s\n",buf1,getpid(),msg);
	} else
	{
		snprintf(buf2,sizeof(buf2),"%s youpot[%i]: slot:%i %s\n",buf1,getpid(),current_slot,msg);
	}
	if (log_console) {
		fputs(buf2,stderr);
	}
	if (log_file) {
		if (file) {
			appendfile(file,buf2);
		} else {
			appendfile(LOG_FILE,buf2);

		}
	}	
}

/* append buffer to a sort-of-plaintext file, useful for reading http, telnet etc  */
void dumptext (unsigned char *buf, unsigned len, char *opis,char *file)
{
	FILE *f;
	char line[128];
	f=fopen(file,"ab");
	if (f) {
		snprintf (line, sizeof(line),"%s [len: 0x%8.8x (%i)]\n\n", opis, len, len);
		fputs(line,f);
		fwrite(buf,1,len,f);
		fputs("\n\n",f);
		fclose(f);
	}
}

/* append a hexdump to a file */
void dumphex (unsigned char *buf, unsigned len, char *opis,char *file)
{
	char hex[128];
	char ascii[128];
	char line[128];
	char tb[128];
	int i = 0;
	int j;

	//return(0);
	sprintf (line, "\n\nlen: 0x%8.8x (%i)   %s\n", len, len, opis);
	appendfile (file, line);


	hex[0] = 0;
	ascii[0] = 0;

	while (len)
	{
		if (i % 16 == 0)
		{
			sprintf (line, "%s %s\n", hex, ascii);
			appendfile (file, line);
			sprintf (hex, "%4.4x:", i);
			ascii[0] = 0;
		}

		sprintf ((char *) &tb, " %2.2x", *buf);
		strcat (hex, tb);
		j = strlen (ascii);
		if ((*buf > 0x1f) && (*buf < 0x7e))
		{
			ascii[j] = *buf;
		}
		else
		{
			ascii[j] = '.';
		}
		ascii[j + 1] = 0;
		len--;
		i++;
		buf++;
	}
	if (i % 16 != 1)
	{
		while (i % 16 != 0)
		{
			strcat (hex, "   ");
			i++;
		}


		sprintf (line, "%s %s\n", hex, ascii);
		appendfile (file, line);
		sprintf (hex, "%4.4x:", i);
	}

}

/* make a directory for client logs, with port, timestamp  etc*/
int make_log_dir(int slot) {
	struct timeval tv;
	/* mkdir -p /tmp/youpot/101.102.103.104/22/123456_78901 */
	gettimeofday(&tv,NULL);

	mkdir (clients[slot].host_log_dir,0755);
	mkdir (clients[slot].hostport_log_dir,0755);

	if (mkdir (clients[slot].log_dir,0755)!=0) {
		fprintf(stderr,"ERROR: can't mkdir %s\n",clients[slot].log_dir);
		exit(1);
	}
	return(1);
}

/* called when a child exits */
void client_exit_handler(int slot) {
	char tmpstr[512];
	time_t t;

	t=time(NULL);
	/* only log closure if we had a real connection */
	//if (clients[slot].connection_state!=STATE_NOTCONNECTED) {
	if (clients[slot].rxblocks||clients[slot].txblocks) {
		snprintf (tmpstr, sizeof(tmpstr), "\n#### End connection slot %i   client:[%i bytes %i blocks] server:[%i bytes %i blocks]\n",
				slot, clients[slot].rxbytes, clients[slot].rxblocks, clients[slot].txbytes, clients[slot].txblocks);
		if (clients[slot].hexdump_file) appendfile (clients[slot].hexdump_file, tmpstr);
		if (clients[slot].text_file) appendfile (clients[slot].text_file, tmpstr);
		if (clients[slot].json_file) 
		{
			snprintf(tmpstr,sizeof(tmpstr),"],\n\"info\":{ \"txblocks\": %i, \"txbytes\": %i, \"rxblocks\": %i, \"rxbytes\": %i, \"ip\": \"%s\", \"srcport\": %i, \"dstport\": %i, \"time_start\": %i, \"time_stop\": %i, \"time_elapsed\": %i }\n}\n",
					clients[slot].txblocks, clients[slot].txbytes, clients[slot].rxblocks, clients[slot].rxbytes, 
					clients[slot].client_addr, clients[slot].client_srcport, clients[slot].client_dstport,
					clients[slot].start_time, t, t-clients[slot].start_time);

			appendfile (clients[slot].json_file, tmpstr);
		}
	}
	return;
}



/* handle SIGCHLD on child process exit, does housekeeping of the clients struct etc */
void sigchld_handler(int s)
{
	int wstat;
	pid_t   pid;
	int i;
	while (1) {
		pid=waitpid(-1, &wstat, WNOHANG);
		if ((pid==0)||(pid==-1)) 
		{ return; }
		else
		{
			printf ("Child exit handler: pid %i Return code: %d\n", pid,WEXITSTATUS(wstat));
			for (i=0;i<MAX_CLIENTS;i++) {
				if (clients[i].pid==pid) {
					if (clients[i].helper_pid) { kill(clients[i].helper_pid,SIGINT); }
					if (clients[i].host_log_dir) { free(clients[i].host_log_dir); }
					if (clients[i].hostport_log_dir) { free(clients[i].hostport_log_dir); }
					if (clients[i].log_dir) { free(clients[i].log_dir); }
					if (clients[i].log_file) { free(clients[i].log_file); }
					if (clients[i].hexdump_file) { free(clients[i].hexdump_file); }
					if (clients[i].client_addr) { free(clients[i].client_addr); }
					if (clients[i].pcap_file) { free(clients[i].pcap_file); }
					if (clients[i].text_file) { free(clients[i].text_file); }
					if (clients[i].json_file) { free(clients[i].json_file); }
					memset((void *)&clients[i],0,sizeof(struct client));
				}
			}
		}
	}

}


#ifndef max
#define max(a,b) \
	({ __typeof__ (a) _a = (a); \
	 __typeof__ (b) _b = (b); \
	 _a > _b ? _a : _b; })
#endif

/* try to detect the protocol from the first data packet */
int detect_protocol(unsigned char *buf,int len) {
	/* nice overview of tls: https://tls12.xargs.org/ 
	 * note: the 0-3 match for byte 2 are the different tls versions,
         * we could just do buf[2]<4 but wanted to enumerate them for readability
         */
        if ((len>2)&&(buf[0]==0x16)&&(buf[1]==0x03)&&((buf[2]==0)||(buf[2]==1)||(buf[2]==2)||(buf[2]==3))) {
		printf("protocol tls detected\n");
		return(PROTOCOL_TLS);
	}
	if ((len>7)&&(memcmp(buf,"SSH-2.0",7)==0)) {
		printf("protocol ssh detected\n");
		/* note from rfc4253: 
		   "The server MAY send other lines of data before sending the version
		   string.  Each line SHOULD be terminated by a Carriage Return and Line
		   Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
		   in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
		   MUST be able to process such lines. " 
		   we should be handling this too
		   */
		return(PROTOCOL_SSH);
	}

	/* rfc4253 section 5 */
	if ((len>8)&&(memcmp(buf,"SSH-1.99",8)==0)) {
		/* 1.99 means ssh1 and ssh2 is supported, we will try to mitm it anyway */
		printf("protocol old ssh detected\n");
		return(PROTOCOL_OLDSSH);
	}
	/* rfc4253 section 5 */
	if ((len>6)&&(memcmp(buf,"SSH-1.",6)==0)) {
		printf("protocol ancient ssh v1 detected\n");
		return(PROTOCOL_OLDSSH);
	}
	return(PROTOCOL_GENERIC);
}

/* tcp client */
int con_tcp(char *host,int port) {
	int s;
	struct sockaddr_in addr;
	socklen_t addr_size;
	memset(&addr,0,sizeof(addr));
	addr_size=sizeof(struct sockaddr_in);
	s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1) { perror ("socket"); exit (1); }
	addr.sin_addr.s_addr=inet_addr(host);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	if (connect (s, (struct sockaddr *)&addr,  addr_size)==-1) 
	{
		close(s);
		return(-1);
	}
	return (s);
}

/* ssh man-int-the middle helper. currently just a hack to fork a process. 
 * the child execs a shell script which launches ssh-mitm
 * the parent tries to repeatedly connects to the ssh-mitm tcp port and returns a desctiptor if succesful
 */
int ssh_mitm_helper(int slot, int fd1) {
	/* ssh-mitm server  --store-ssh-session --listen-address 127.0.0.1 --session-log-dir  $1  --remote-host $2 --remote-port $3 --listen-port $4 > $1/ssh_mitm.log 2>&1 
	*/
	char tmpstr[512];
	char dst_port[16];
	char helper_port[16];
	int s;
	int tries;
	pid_t pid;
	printf("mitm helper slot %i\n",slot);
	pid=fork();
	if (pid==0) {
		close(fd1);
		adjust_oom();
		//snprintf(tmpstr,sizeof(tmpstr),"./ssh_helper %s %s %i %i",clients[slot].log_dir,clients[slot].client_addr,clients[slot].client_dstport,clients[slot].helper_port);
		//system(tmpstr);
		sprintf(dst_port,"%i",clients[slot].client_dstport);
		sprintf(helper_port,"%i",clients[slot].helper_port);
		execl("/home/youpot/youpot/ssh_helper","ssh_helper",clients[slot].log_dir,clients[slot].client_addr,dst_port,helper_port,0);
		exit(0);
	} 
	clients[slot].helper_pid=pid;
	/* try to connect 50 times to the helper process, if it still isn't listening then just die */
	tries=50;
	while(tries) {
		usleep(100000);
		s=con_tcp("127.0.0.1",clients[slot].helper_port);
		if (s>0) { clients[slot].kill_port=1; return(s); }
		tries--;
	}
	printf("ERROR: could not connect to mitm helper slot %i, port %i\n",slot,clients[slot].helper_port);
	if (clients[slot].helper_pid) { kill(clients[slot].helper_pid,SIGINT); } 
	exit(1);
}

/* TLS stuff */             
int err_ssl (int eval, char *msg)
{
	char buf[128];
	char msgbuf[1024];

	ERR_error_string (ERR_get_error (), buf);
	sprintf(msgbuf,"%s: %s",msg,buf);      
	fprintf(stderr,"%s\n",msgbuf);	
	fflush(stderr);
	//	appendfile (log_file, msgbuf);

	//err(eval, "%s", buf);
}


int tls_init()
{

	/* setup ssl stuff */
	SSL_library_init ();
	SSL_load_error_strings ();
	OpenSSL_add_all_algorithms();

}

/* a callback to verify tls cert, currently unused */
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	return(1);
}

/* shows info about a tls certificate from the ssl context */
void show_cert(SSL* ssl,int slot)
{
	X509 *cert;
	char *l1,*l2,*l3;
	char msg[4096];

	cert = SSL_get_peer_certificate(ssl);
	if (cert)
	{

		l1 = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		l2 = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		X509_free(cert);
		snprintf(msg,sizeof(msg)-1,"Cert info: Subject: [%s] Issuer:[%s]\n",l1,l2);
		free(l1);
		free(l2);
		logit(msg,clients[slot].hexdump_file,1,1);

	}
}

#define DIR_FROMCLIENT 0
#define DIR_FROMSERVER 1

void dumpjson_data(unsigned char *buf, int len, unsigned char *buforig, int lenorig, char *description, int idx, int direction, char *file)
{
	char tmpstr[65536*64]; /* memory is cheap these days */
	char tmpstr2[16];
	unsigned char c;
	int i;

	snprintf(tmpstr,sizeof(tmpstr),"{ \"idx\": %i, \"fromclient\": %s, \"len\": %i, \"data\": \"",
			idx,(direction==DIR_FROMCLIENT)?"true":"false",len);

	/* which chars to escape in json: https://stackoverflow.com/questions/19176024/how-to-escape-special-characters-in-building-a-json-string */
	for (i=0;i<len;i++) {
		c=*buf;
		buf++;

		if (c=='\n') { strcat(tmpstr,"\\n"); }
		else if (c=='\r') { strcat(tmpstr,"\\r"); }
		else if (c=='\t') { strcat(tmpstr,"\\t"); }
		else if (c=='\f') { strcat(tmpstr,"\\f"); }
		else if (c=='\b') { strcat(tmpstr,"\\b"); }
		else if ((c<' ')||(c>'~')) { sprintf(tmpstr2,"\\u00%02x",c); strcat(tmpstr,tmpstr2); } 
		else if ((c=='"')||(c=='\\')||(c=='/')) {
			sprintf(tmpstr2,"\\%c",c); strcat(tmpstr,tmpstr2); 
		} else {
			sprintf(tmpstr2,"%c",c); strcat(tmpstr,tmpstr2); 
		}
	} 
	strcat(tmpstr,"\"");

	if (buforig) {
		if (description) {
			strcat(tmpstr,", \"mod_reason\": \"");
			strcat(tmpstr, description);
			strcat(tmpstr,"\"");
		}
		strcat(tmpstr,", \"original_len\": ");
		sprintf(tmpstr2,"%i",lenorig); strcat(tmpstr,tmpstr2);
		strcat(tmpstr,", \"original_data\": \"");

		for (i=0;i<lenorig;i++) {
			c=*buforig;
			buforig++;

			if (c=='\n') { strcat(tmpstr,"\\n"); }
			else if (c=='\r') { strcat(tmpstr,"\\r"); }
			else if (c=='\t') { strcat(tmpstr,"\\t"); }
			else if (c=='\f') { strcat(tmpstr,"\\f"); }
			else if (c=='\b') { strcat(tmpstr,"\\b"); }
			else if ((c<' ')||(c>'~')) { sprintf(tmpstr2,"\\u00%02x",c); strcat(tmpstr,tmpstr2); } 
			else if ((c=='"')||(c=='\\')||(c=='/')) {
				sprintf(tmpstr2,"\\%c",c); strcat(tmpstr,tmpstr2); 
			} else {
				sprintf(tmpstr2,"%c",c); strcat(tmpstr,tmpstr2); 
			}
		} 
		strcat(tmpstr,"\"");
	}

	strcat(tmpstr," }");
	appendfile(file,tmpstr);
}


/* handle a block of data sent through our little proxy */
void handle_block(unsigned char *buf, int len, unsigned char *buforig, int lenorig, char *description, int direction, int slot) {
	char tmpstr[512];
	int newconn=0;
	int idx;

	idx=clients[slot].rxblocks+clients[slot].txblocks;
	if (idx==0)
	{
		/* this is a new connection, write a header */
		snprintf(tmpstr,sizeof(tmpstr),"#### Connection from %s:%i to port %i\n\n",
				clients[slot].client_addr, clients[slot].client_srcport, clients[slot].client_dstport);
		appendfile(clients[slot].hexdump_file,tmpstr);
		appendfile(clients[slot].text_file,tmpstr);
		newconn=1;
		appendfile(clients[slot].json_file,"{\n\"packets\": [\n"); /* making json files manually, yuck! */
	} else {
		appendfile(clients[slot].json_file,",\n");
	}	

	dumpjson_data(buf, len, buforig, lenorig, description, idx, direction, clients[slot].json_file);

	if (direction==DIR_FROMCLIENT) {
		dumphex (buf, len, "<client<",clients[slot].hexdump_file);
		dumptext (buf, len, "<client<",clients[slot].text_file);
		clients[slot].rxbytes+=len;
		clients[slot].rxblocks++;
	} else if (direction==DIR_FROMSERVER) {
		dumphex (buf, len, ">server>",clients[slot].hexdump_file);
		dumptext (buf, len, ">server>",clients[slot].text_file);
		clients[slot].txbytes+=len;
		clients[slot].txblocks++;
	}
}

/* simple man-in-the-middle for tls. fd1 - connection from client , fd2 - connection to server */
int conn_tls (int fd1, int fd2, int slot) {

	fd_set fds;
	int len;
	int ret;
	SSL_METHOD *clmethod;

	SSL_CTX *ssl_client_ctx, *ssl_server_ctx;
	SSL *ssl_client, *ssl_server;

	unsigned char buf[1024];

	unsigned char *buf2;
	int repl;
	int plen;
	int newlen;
	unsigned char *pbuf;
	int i;

	ssl_client_ctx = SSL_CTX_new (SSLv23_server_method ());

	if (SSL_CTX_use_certificate_file (ssl_client_ctx, CERT_FILE, SSL_FILETYPE_PEM) == 0)
	{
		err_ssl (1, "SSL_CTX_use_certificate_file");
		//exit(1);
		return(0);
	}
	if (SSL_CTX_use_PrivateKey_file (ssl_client_ctx, CERT_FILE, SSL_FILETYPE_PEM) == 0) {
		err_ssl (1, "SSL_CTX_use_PrivateKey_file");
		//exit(1);
		return(0);
	}

	if (SSL_CTX_check_private_key (ssl_client_ctx) == 0) {
		err_ssl (1, "SSL_CTX_check_private_key");
		//exit(1);
		return(0);
	}

	ssl_client = SSL_new (ssl_client_ctx);
	//SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_NONE, verify_callback);
	SSL_set_fd (ssl_client, fd2);

	if (SSL_accept (ssl_client) == 0)
	{
		err_ssl (1, "SSL_accept");
		//exit(1);
		return(0);
	}

	clmethod =  TLS_client_method();
	//ssl_server_ctx = SSL_CTX_new (TLS_client_method ());
	ssl_server_ctx = SSL_CTX_new (clmethod); 
	ssl_server = SSL_new (ssl_server_ctx);
	//SSL_set_connect_state (ssl_server);

	SSL_set_fd (ssl_server, fd1);

	if (SSL_connect (ssl_server) < 0)
	{
		err_ssl (1, "SSL_connect");
		//exit(1);
		return(0);
	}
	show_cert(ssl_server,slot);
	for (;;)
	{
		FD_ZERO (&fds);
		FD_SET (fd1, &fds);
		FD_SET (fd2, &fds);

		ret = select (255, &fds, 0, 0, 0);

		if (ret < 0)
		{ 
			err_ssl(0,"conn1");
			break;
		}

		if (FD_ISSET (fd1, &fds))
		{
			len = SSL_read (ssl_server, buf, sizeof (buf));
			if (len < 1)
			{
				err_ssl(0,"conn3");
				//exit(1);
				break;
			}

			repl=0; 
			pbuf=buf;
			plen=len;

			for (i=0;i<MAX_PATTERNS;i++) {
				while (replacer(pbuf,plen, &buf2, (int *)&newlen, &patterns_fromserver[i]))
				{
					if (pbuf!=buf) { free(pbuf); }
					pbuf=buf2;
					plen=newlen;
					repl=1;
				}
			}
			if (repl) {
				handle_block(pbuf, plen, buf, len, patterns_fromserver[i].description, DIR_FROMSERVER, slot);
				SSL_write (ssl_client, pbuf, plen);
				free(pbuf);

			} else {

				handle_block(buf, len, 0, 0, 0, DIR_FROMSERVER, slot);
				SSL_write (ssl_client, buf, len);
			}
		}


		if (FD_ISSET (fd2, &fds))
		{
			len = SSL_read (ssl_client, buf, sizeof (buf));
			if (len < 1)
			{
				err_ssl(0,"conn2");
				//exit(1);
				break;
			}

			repl=0; 
			pbuf=buf;
			plen=len;

			for (i=0;i<MAX_PATTERNS;i++) {
				while (replacer(pbuf,plen, &buf2, (int *)&newlen, &patterns_fromclient[i]))
				{
					if (pbuf!=buf) { free(pbuf); }
					pbuf=buf2;
					plen=newlen;
					repl=1;
				}
			}
			if (repl) {
				handle_block(pbuf, plen, buf, len, patterns_fromclient[i].description,  DIR_FROMCLIENT, slot);
				SSL_write (ssl_server, pbuf, plen);
				free(pbuf);

			} else {


				handle_block(buf, len, 0, 0, 0, DIR_FROMCLIENT, slot);
				SSL_write (ssl_server, buf, len);
			}
		}

	}                           //for
	return(1);
}

/* join two filedescriptors, data read from one is written to the other. also tries to detect the protocol from the first buffer we get and launches a main-in-the-middle helper for known protocols (currently ssh and tls) */
int join_fds(int fd1,int fd2,int slot) {
	unsigned char buf[65536];
	unsigned char *buf2;
	int repl;
	int plen;
	unsigned char *pbuf;
	int i;
	int x;
	int newlen;
	fd_set fds;
	int len;
	int ret;
	int first=1;
	int prot=PROTOCOL_GENERIC;

	while(1) {

		FD_ZERO (&fds);
		FD_SET (fd1, &fds);
		FD_SET (fd2, &fds);

		ret = select (255, &fds, 0, 0, 0);

		if (ret < 0)
		{
			perror("conn1");
			break;
		}
		if (first) {
			if (!prot) {
				if (FD_ISSET (fd1, &fds))
				{
					len = recv(fd1, buf, sizeof(buf), MSG_PEEK);
					prot=detect_protocol(buf,len);
				}

				if (FD_ISSET (fd2, &fds))
				{
					len = recv(fd2, buf, sizeof(buf), MSG_PEEK);
					prot=detect_protocol(buf,len);
				}

				if ((prot==PROTOCOL_SSH)||(prot==PROTOCOL_OLDSSH))
				{
					printf("launching ssh mitm\n");
					close(fd2);
					fd2=ssh_mitm_helper(slot,fd1);
					continue;
				}
				if (prot==PROTOCOL_TLS)
				{
					printf("launching tls mitm\n");
					conn_tls (fd2,fd1,slot);
					break;
				}
			}
			first=0;
		}
		/* stuff that comes from the client */
		if (FD_ISSET (fd1, &fds))
		{
			len = read (fd1, buf, sizeof (buf));
			if (len < 1) { perror("conn2"); break; }

			repl=0;
			pbuf=buf;
			plen=len;

			for (i=0;i<MAX_PATTERNS;i++) {
				while (replacer(pbuf,plen, &buf2, (int *)&newlen, &patterns_fromclient[i]))
				{
					if (pbuf!=buf) { free(pbuf); }
					pbuf=buf2;
					plen=newlen;
					repl=1;
				}
			}
			if (repl) {
				handle_block(pbuf, plen, buf,len, patterns_fromclient[i].description,  DIR_FROMCLIENT, slot);
				write (fd2, pbuf, plen);
				free(pbuf);
			} else {
				handle_block(buf, len, 0, 0, 0, DIR_FROMCLIENT, slot);
				write (fd2, buf, len);
			}
		}

		/* stuff that comes from the server we're connecting to */
		if (FD_ISSET (fd2, &fds))
		{
			len = read (fd2, buf, sizeof (buf));
			if (len < 1) { perror("conn3"); break; }

			repl=0;
			pbuf=buf;
			plen=len;

			for (i=0;i<MAX_PATTERNS;i++) {
				while (replacer(pbuf,plen, &buf2, (int *)&newlen, &patterns_fromserver[i]))
				{
					if (pbuf!=buf) { free(pbuf); }
					pbuf=buf2;
					plen=newlen;
					repl=1;
				}
			}
			if (repl) {
				handle_block(pbuf, plen, buf,len, patterns_fromserver[i].description,  DIR_FROMSERVER, slot);
				write (fd1, pbuf, plen);
				free(pbuf);
			} else {
				handle_block(buf, len, 0, 0, 0, DIR_FROMSERVER, slot);
				write (fd1, buf, len);
			}



		}
	}
}


void sigalrm_handler(int s) {
	char tmpstr[512];
	int c;
	int tries;

	snprintf(tmpstr,sizeof(tmpstr),"alrm handler: Ending conenction slot:%i  state:%i",current_slot,clients[current_slot].connection_state);
	logit(tmpstr,NULL,1,1);
	if (clients[current_slot].helper_pid) { 
		fprintf(stderr,"*** slot %i  killing helper pid %i\n",current_slot,clients[current_slot].helper_pid);
		kill(clients[current_slot].helper_pid,SIGINT); 
		if ((clients[current_slot].kill_port)&&(clients[current_slot].helper_port))
		{
			tries=50;
			/* wait for the helper to stop listening, this is for ssh_mitm currently */
			while(tries) {
				tries--;
				c=con_tcp("127.0.0.1",clients[current_slot].helper_port);
				if (c>0) { usleep(100000); close(c); continue; }
			}
			if (!tries) { 
				fprintf(stderr,"*** slot %i  helper pid %i did not want to die\n",current_slot,clients[current_slot].helper_pid);
				kill(clients[current_slot].helper_pid,SIGKILL); }
		}
	}
	client_exit_handler(current_slot);
	exit(0);
}

/* handle an open tcp connection, opens a connection back to the host connecting to us, and if succesful calls ths join_fds() function */
int handle_conn(int client_socket,struct sockaddr_in *cli_addr, struct sockaddr_in *original_sa,int slot) {
	//		printf("child Connection accepted from %s:%d\n", inet_ntoa(cli_addr->sin_addr), ntohs(cli_addr->sin_port));
	//		printf("child To: %s:%d\n", inet_ntoa(original_sa->sin_addr), ntohs(original_sa->sin_port));

	int s;
	struct sockaddr_in addr;
	socklen_t addr_size;
	char tmpstr[512];

	addr_size=sizeof(struct sockaddr_in);
	s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1) { perror ("socket"); exit (1); }
	memcpy(&addr.sin_addr,&cli_addr->sin_addr,sizeof(addr.sin_addr));
	addr.sin_port = original_sa->sin_port;
	addr.sin_family = AF_INET;
	signal(SIGALRM,sigalrm_handler);
	alarm(CONNECT_TIMEOUT);

	snprintf(tmpstr,sizeof(tmpstr),"trying to connect to: %s:%i",inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));
	logit(tmpstr,NULL,1,1);

	if (connect (s, (struct sockaddr *)&addr,  addr_size) == -1) { 
		snprintf(tmpstr,sizeof(tmpstr),"ERROR [%s] connect() to %s:%i",strerror(errno),inet_ntoa(original_sa->sin_addr), ntohs(original_sa->sin_port));
		logit(tmpstr,NULL,1,1);
		//client_exit_handler(current_slot);
		exit (1); 
	}

	alarm(CONNECTION_TIME);
	printf("child connected\n");
	clients[slot].client_addr=strdup(inet_ntoa(cli_addr->sin_addr));
	clients[slot].client_srcport=ntohs(cli_addr->sin_port);
	clients[slot].client_dstport=ntohs(original_sa->sin_port);
	clients[slot].connection_state=STATE_CONNECTED;
	make_log_dir(slot); /* only mkdir if we connected to something */


	sprintf (tmpstr, "Success Connection from %s:%d , child connect to %s:%d", inet_ntoa(cli_addr->sin_addr), ntohs(cli_addr->sin_port),inet_ntoa(original_sa->sin_addr), ntohs(original_sa->sin_port));
	logit(tmpstr,NULL,1,1);

	join_fds(client_socket,s,slot);

	/* TODO: maybe add some more cleanup here? */
	client_exit_handler(slot);
}

/* simple forking tcp server, accepts the connection, inits some values, forks and in the child calls handle_conn() */
int listen_tcp()
{
	int sockfd, ret;
	struct sockaddr_in server_addr;
	int client_socket;
	struct sockaddr_in cli_addr;
	socklen_t addr_size;
	pid_t childpid;
	struct sockaddr_in original_sa;
	int opt=1;
	int slot;
	struct timeval tv;
	char tmpstr[512];
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		perror("create socket");
		exit(1);
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {    perror("setsockopt(SO_REUSEADDR) failed"); exit(1); }

	memset(&server_addr, 0, sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);

	//server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_addr.s_addr = INADDR_ANY;

	ret = bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));

	if (ret < 0) {
	}

	if (listen(sockfd, BACKLOG)) {
		perror("listen");
		exit(1);
	}

	while (1) {
		/* find a new client slot, sleep 5s if all are used */
		slot=MAX_CLIENTS;
		while (slot==MAX_CLIENTS) {
			for (slot=0;slot<MAX_CLIENTS;slot++) { if (!clients[slot].pid)  break; }
			if (slot==MAX_CLIENTS) { 
				fprintf(stderr,"WARNING: No free client slots, waiting...\n");
				sigchld_handler(0); /* ugly hack: sometimes we got zombie processes for some reason, so this reaps them if the sigchld handler missed them for whatever reason */
				sleep(5);
			}
		}



		addr_size=sizeof(struct sockaddr_in);
		client_socket = accept( sockfd, (struct sockaddr*)&cli_addr, &addr_size);

		if (client_socket < 0) {
			perror("accept");
			exit(1);
		}
		sigchld_handler(0); /* ugly hack: sometimes we got zombie processes for some reason, so this reaps them if the sigchld handler missed them for whatever reason */

		addr_size=sizeof(struct sockaddr_in);
		getsockopt (client_socket, SOL_IP, SO_ORIGINAL_DST, &original_sa, &addr_size);


		printf("Connection accepted from %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
		printf("To: %s:%d\n", inet_ntoa(original_sa.sin_addr), ntohs(original_sa.sin_port));

		/* mkdir -p /tmp/youpot/101.102.103.104/22/123456_78901 */
		gettimeofday(&tv,NULL);

		snprintf(tmpstr,sizeof(tmpstr)-1,"%s/%s",LOG_DIR,inet_ntoa(cli_addr.sin_addr));
		clients[slot].host_log_dir=strdup(tmpstr);
		snprintf(tmpstr,sizeof(tmpstr)-1,"%s/%s/%i",LOG_DIR,inet_ntoa(cli_addr.sin_addr),ntohs(original_sa.sin_port));
		clients[slot].hostport_log_dir=strdup(tmpstr);
		snprintf(tmpstr,sizeof(tmpstr)-1,"%s/%s/%i/%i_%i",LOG_DIR,inet_ntoa(cli_addr.sin_addr),ntohs(original_sa.sin_port),(long)tv.tv_sec,(long)tv.tv_usec);

		clients[slot].helper_port=FIRST_PORT+slot;

		clients[slot].log_dir=strdup(tmpstr);
		snprintf(tmpstr,sizeof(tmpstr)-1,"%s/hexdump.log",clients[slot].log_dir);
		printf("hexdump file: %s\n",tmpstr);
		clients[slot].hexdump_file=strdup(tmpstr);
		snprintf(tmpstr,sizeof(tmpstr)-1,"%s/textdump.log",clients[slot].log_dir);
		printf("text file: %s\n",tmpstr);
		clients[slot].text_file=strdup(tmpstr);
		snprintf(tmpstr,sizeof(tmpstr)-1,"%s/connection.json",clients[slot].log_dir);
		printf("json file: %s\n",tmpstr);
		clients[slot].json_file=strdup(tmpstr);
		childpid = fork();
		clients[slot].pid=childpid;

		if (childpid == 0) {
			/* child */
			adjust_oom();
			current_slot=slot;
			signal(SIGCHLD,SIG_IGN);
			close(sockfd);
			clients[slot].start_time=time(NULL);
			handle_conn(client_socket,&cli_addr,&original_sa,slot);
			if (clients[slot].helper_pid) { kill(clients[slot].helper_pid,SIGINT); } 
			exit(0);
		} else {
			close(client_socket);
		}

	} //while

	/* close the client socket fd */
	close(client_socket);
	return 0;
}

void setup() {
	init_patterns();
	read_patterns(PATTERN_FROMCLIENT_DIR,patterns_fromclient);
	read_patterns(PATTERN_FROMSERVER_DIR,patterns_fromserver);

	memset((void *)&clients,0,sizeof(clients));

	tls_init();

	signal(SIGCHLD,sigchld_handler);
	signal(SIGHUP,sighup_handler);
}

int main(int argc, char **argv) {

	setup();
	listen_tcp();
}
