/* tclink.c - Library code for the TCLink client API.
 * 
 * All code contained herein is copyright (c) 2001 TrustCommerce.
 * It is distributed to our clients for your convenience; it is for
 * use by those authorized persons ONLY and for no other purpose beyond
 * integrated with TrustCommerce's payment gateway.
 *
 * That said, please feel free to use this code in any way you see fit for
 * the purpose of TrustCommerce integration.  Should you find any bugs or
 * make interesting improvements/optimizations, please contact us via
 * developer@trustcommerce.com.
 */

#include "tclink.h"

#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>

#ifdef USE_SSLEAY
#include <ssl/crypto.h>
#include <ssl/x509.h>
#include <ssl/pem.h>
#include <ssl/ssl.h>
#include <ssl/err.h>
#else
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef NEEDS_RAND_SEED
#include <openssl/rand.h>
#endif
#endif

#define DEBUG_MSG         0    /* set to 1 for lots of annoying printf()'s */

#define TIMEOUT           40   /* in seconds */

#define DEFAULT_HOST       "gateway.trustcommerce.com"

char *tclink_host  = DEFAULT_HOST;
int tclink_port    = 443;

#define MAX_STRING        512
#define BUFF_MAX          32000

/*************************************************/
/* Data structures used only within this module. */
/*************************************************/

/* Variables used for transaction data. */

typedef struct param_data
{
	char *name;
	char *value;
	struct param_data *next;
} param;

static param *send_param_list = NULL, *send_param_tail = NULL;
static param *recv_param_list = NULL;

/* Variables used by SSL functions. */
static int ssl_inited = 0;
static int my_sd = -1;
static SSL_METHOD *meth;
static SSL_CTX *ctx;
static SSL *ssl;
static X509 *tc_cert = NULL;

/* the TrustCommerce certificate */
unsigned char cert_data[540]={
0x30,0x82,0x02,0x18,0x30,0x82,0x01,0x81,0x02,0x01,0x02,0x30,0x0D,0x06,0x09,0x2A,
0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x04,0x05,0x00,0x30,0x55,0x31,0x0B,0x30,0x09,
0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x14,0x30,0x12,0x06,0x03,0x55,
0x04,0x08,0x13,0x0B,0x4C,0x6F,0x73,0x20,0x41,0x6E,0x67,0x65,0x6C,0x65,0x73,0x31,
0x17,0x30,0x15,0x06,0x03,0x55,0x04,0x0A,0x13,0x0E,0x54,0x72,0x75,0x73,0x74,0x20,
0x43,0x6F,0x6D,0x6D,0x65,0x72,0x63,0x65,0x31,0x17,0x30,0x15,0x06,0x03,0x55,0x04,
0x03,0x13,0x0E,0x50,0x43,0x41,0x20,0x28,0x31,0x30,0x32,0x34,0x20,0x62,0x69,0x74,
0x29,0x30,0x1E,0x17,0x0D,0x30,0x30,0x30,0x34,0x32,0x39,0x30,0x35,0x30,0x39,0x30,
0x34,0x5A,0x17,0x0D,0x30,0x34,0x30,0x34,0x32,0x39,0x30,0x35,0x30,0x39,0x30,0x34,
0x5A,0x30,0x54,0x31,0x0B,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,
0x31,0x14,0x30,0x12,0x06,0x03,0x55,0x04,0x08,0x13,0x0B,0x4C,0x6F,0x73,0x20,0x41,
0x6E,0x67,0x65,0x6C,0x65,0x73,0x31,0x17,0x30,0x15,0x06,0x03,0x55,0x04,0x0A,0x13,
0x0E,0x54,0x72,0x75,0x73,0x74,0x20,0x43,0x6F,0x6D,0x6D,0x65,0x72,0x63,0x65,0x31,
0x16,0x30,0x14,0x06,0x03,0x55,0x04,0x03,0x13,0x0D,0x43,0x41,0x20,0x28,0x31,0x30,
0x32,0x34,0x20,0x62,0x69,0x74,0x29,0x30,0x81,0x9F,0x30,0x0D,0x06,0x09,0x2A,0x86,
0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00,0x03,0x81,0x8D,0x00,0x30,0x81,0x89,
0x02,0x81,0x81,0x00,0xBD,0x7C,0x7B,0x6F,0x77,0x46,0xE3,0x0F,0xF8,0x50,0x89,0x06,
0xFC,0x54,0x5A,0x59,0x30,0x55,0xC6,0x00,0x34,0x6F,0x6B,0x64,0x8E,0x11,0x3C,0xDD,
0xA9,0x0D,0xC5,0xE1,0x1C,0x49,0xF7,0x0A,0x6B,0x3E,0xAA,0x98,0xA4,0xA2,0x8D,0xEF,
0x9A,0xCB,0xA2,0x40,0x87,0x3B,0x4B,0x13,0x73,0xE6,0x6C,0x39,0x1C,0x48,0xBE,0x6C,
0x1C,0x78,0x0F,0x8E,0x40,0x27,0xAD,0x61,0x0E,0x5E,0x1F,0x94,0xD7,0xAB,0x61,0x3C,
0xB1,0xF4,0xC9,0xE2,0x0D,0x05,0x83,0xE8,0x75,0xAB,0x64,0x12,0x39,0xAB,0xEF,0x79,
0x53,0x49,0x48,0xA0,0x9C,0x55,0xD2,0xE3,0xD0,0x25,0x94,0x78,0x69,0x03,0x95,0xBA,
0x68,0xC6,0x35,0xFB,0x54,0x3D,0x05,0x6D,0xAD,0x50,0x5F,0xE7,0x63,0xB9,0x4A,0x28,
0xB0,0xB3,0xE2,0x07,0x02,0x03,0x01,0x00,0x01,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,
0x86,0xF7,0x0D,0x01,0x01,0x04,0x05,0x00,0x03,0x81,0x81,0x00,0x34,0xED,0xF6,0x9D,
0x32,0x51,0xCA,0x22,0xD6,0x8C,0x81,0x6F,0x64,0x41,0x7D,0xC0,0xD8,0x66,0xB7,0x2C,
0x65,0x54,0x8A,0xE4,0x21,0x6A,0xF2,0x0F,0x3F,0xD0,0x85,0xDC,0x15,0xC1,0x5C,0x72,
0x9A,0x0F,0x00,0x8D,0x38,0x59,0x70,0x7A,0x9C,0x40,0xA6,0x9A,0x2D,0x0E,0xA0,0x31,
0x61,0x2E,0xA2,0x77,0x11,0xBB,0x20,0xF8,0xF9,0x28,0x10,0x1E,0x12,0xB1,0x9D,0x29,
0xF7,0x86,0x12,0x05,0x83,0x83,0xE3,0xC3,0x82,0x65,0x97,0xE9,0xC2,0x5B,0x09,0x11,
0x1D,0xF1,0x01,0x37,0x20,0x2E,0xC5,0x69,0x9C,0xED,0xE3,0xC1,0x29,0x1B,0x3D,0x47,
0x72,0xED,0xA1,0x7B,0xE4,0x8B,0x2B,0x18,0x39,0xEA,0xDE,0x54,0x69,0xE7,0x35,0xDB,
0x8F,0xFB,0x34,0xC7,0xF7,0xB3,0x6A,0x9A,0xE5,0x27,0xA4,0x0F};

/* Variables used by internal TCLink functions. */
static char buffer[BUFF_MAX];
static char destbuff[BUFF_MAX];
static int is_error;

/*************************************
 * Internal functions, not exported. *
 *************************************/

/* Random number from min to max. */
static int number(int min, int max)
{
	return (rand() % (max - min + 1)) + min;
}

/* Add a parameter-value pair to the recieved list. */
static void AddRecvParam(const char *name, const char *value)
{
	param *p = (param *)malloc(sizeof(param));
	p->name = strdup(name);
	p->value = strdup(value);
	p->next = recv_param_list;
	recv_param_list = p;
}

/* Add a string to the received list. */
static int AddRecvString(char *string)
{
	char name[MAX_STRING], value[MAX_STRING];

	char *ptr = strchr(string, '=');
	if (ptr == NULL)
		return 0;

	*ptr = 0;
	strcpy(name, string);
	strcpy(value, ptr+1);

	if (name[0] == 0 || value[0] == 0)
		return 0;

	AddRecvParam(name, value);
	return 1;
}

/* Deallocate the send list. */
static void ClearSendList()
{
	param *p, *next;
	for (p = send_param_list; p; p = next)
	{
		next = p->next;
		free(p);
	}

	send_param_list = send_param_tail = NULL;
}

/* Deallocate the recv list. */
static void ClearRecvList()
{
	param *p, *next;
	for (p = recv_param_list; p; p = next)
	{
		next = p->next;
		free(p);
	}

	recv_param_list = NULL;
}

/* Open a socket to the host_ip specified.  Returns the socket's file
 * descriptor on success (the open attempt is underway) or -1 for failure
 * (should never happen in practice).  Note that this function DOES NOT block
 * and wait for the connection; you'll need to select() on the socket later to see
 * if it opened successfully.
 */
static int BeginConnection(int host_ip)
{
	struct sockaddr_in sa;
	int sd;

#if DEBUG_MSG
	printf("Trying %u.%u.%u.%u\n", host_ip & 0xff, host_ip >> 8 & 0xff, host_ip >> 16 & 0xff, host_ip >> 24 & 0xff);
#endif

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0)
		return -1;

	fcntl(sd, F_SETFL, O_NONBLOCK);

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = host_ip;
	sa.sin_port = htons(tclink_port);

	connect(sd, (struct sockaddr *) &sa, sizeof(sa));

	return sd;
}

/* This function is called on a socket file descriptor once the connection has been
 * established and we're ready to negotiate SSL.  If the SSL handshake fails for some
 * reason (such as the host on the other end not using SSL), it will return 0 for
 * failure.  Success returns 1.
 */
static int FinishConnection(int sd)
{
	int ssl_connected, is_error, errcode, res, n;
	struct pollfd pfd;
	X509 *server_cert;
	time_t start_time, remaining;

	/* check if socket has connected successfully */
	int val;
	socklen_t size = 4;
	getsockopt(sd, SOL_SOCKET, SO_ERROR, &val, &size);
	if (val != 0)
		return 0;

	ssl = SSL_new(ctx);
	if (!ssl)
		return 0;

	SSL_set_fd(ssl, sd);

	ssl_connected = 0;
	is_error = 0;
	start_time = time(0);

	while (!ssl_connected && !is_error)
	{
		remaining = 5 - (time(0) - start_time);
		if (remaining <= 0) {
			is_error = 1;
			break;
		}

		res = SSL_connect(ssl);

		ssl_connected = ((res == 1) && SSL_is_init_finished(ssl));

		if (!ssl_connected)
		{
			errcode = SSL_get_error(ssl, res);
			switch (errcode)
			{
				case SSL_ERROR_NONE:
					/* no error, we should have a connection, check again */
					break;

				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
					/* no error, just wait for more data */
					pfd.fd = sd; pfd.events = POLLOUT|POLLIN; pfd.revents = 0;
					while ((n = poll(&pfd, 1, remaining * 1000)) < 0)
						if (errno != EINTR) {
							is_error = 1;
							break;
						}

					if (!n || !(pfd.revents & (POLLOUT|POLLIN)))
						is_error = 1;

					break;

				case SSL_ERROR_ZERO_RETURN: /* peer closed the connection */
				case SSL_ERROR_SSL:         /* error in SSL handshake */
				default:
					is_error = 1;
			}
		}
	}

	if (is_error) {
		SSL_free(ssl);
		return 0;
	}
   
	fcntl(sd, F_SETFL, 0);           /* make the socket blocking again */

	/* verify that server certificate is authentic */
	server_cert = SSL_get_peer_certificate(ssl);
	if (!server_cert || (X509_cmp(server_cert, tc_cert) != 0)) {
		SSL_free(ssl);
		return 0;
	}

#if DEBUG_MSG
	/* some code to spit out the cipher and server certificate */
	printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
	server_cert = SSL_get_peer_certificate (ssl);
	if (server_cert)
	{
		char *str;
		printf ("Server certificate:\n");

		str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
		if (str) {
			printf ("\t subject: %s\n", str);
			Free (str);
		}

		str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
		if (str) {
			printf ("\t issuer: %s\n", str);
			Free (str);
		}
	}
#endif

	X509_free(server_cert);

	return 1;
}

/* This function should be called on list of socket file descriptors (sd) to determine
 * if any have opened successfully.  If so, it will return which one (index into
 * the array).  Otherwise it returns -1 if none have successfully opened.
 * This function will block for a maximum of 3 seconds.
 * As this function calls FinishConnection(), you shouldn't need to do anything special
 * after it returns success - the socket is set up and ready for use.
 */
static int CheckConnection(int *sd, int num_sd)
{
	fd_set wr_set, err_set;
	struct timeval tv;
	int max_sd = -1, i;

	tv.tv_sec = 3;        /* wait 3 seconds for something to happen */
	tv.tv_usec = 0;

	/* build the fd_sets used for select() */
	FD_ZERO(&wr_set);
	FD_ZERO(&err_set);
	for (i = 0; i < num_sd; i++)
	{
		if (sd[i] < 0) continue;
		FD_SET(sd[i], &wr_set);
		FD_SET(sd[i], &err_set);
		if (sd[i] > max_sd)
			max_sd = sd[i];
	}

	/* run the select and see what we have waiting for us */
	if (select(max_sd + 1, NULL, &wr_set, &err_set, &tv) < 1)
		return -1;     /* I hope this never happens */

	for (i = 0; i < num_sd; i++)
		if (sd[i] >= 0)
			if (FD_ISSET(sd[i], &err_set))
			{
				/* error - close the socket and mark it defunct */
				close(sd[i]);
				sd[i] = -1;
			}
			else if (FD_ISSET(sd[i], &wr_set))
			{
				/* socket has opened! try to negotiate SSL */
				if (FinishConnection(sd[i])) {
					/* socket is ready to go, so return success */
					my_sd = sd[i];
					return i;
				}
				else {
					/* SSL handshake had errors, close the socket and mark it defunct */
					close(sd[i]);
					sd[i] = -1;
				}
			}

	/* if we get here, nothing much interesting happened during those 3 seconds */
	return -1;
}

/* Open a connection to one of the TrustCommerce gateway servers. */
static int Connect(char prefer_host)
{
	struct hostent *he;

	time_t start_time;
	enum { MAX_HOSTS = 32 };
	time_t last_connect[MAX_HOSTS];
	int sd[MAX_HOSTS];
	int num_sd = 0, num_hosts;
	int host, pref_host_ip = 0, pref_host_try = 0, i;

	my_sd = -1;
	is_error = 0;

	/* do some SSL setup */
	if (ssl_inited < 1)
	{
#ifdef NEEDS_RAND_SEED
		/* Somewhat insecure hack to make OpenSSL work on legacy systems
		 * that don't have a /dev/random or /dev/urandom. */
		char rand_buf[32];
		srand(time(0));
		for (int i = 0; i < sizeof(rand_buf); i++)
			rand_buf[i] = rand();
		RAND_seed(rand_buf, sizeof(rand_buf));
#endif
		SSLeay_add_ssl_algorithms();
		meth = SSLv3_client_method();
		ssl_inited = 1;
	}

	if (ssl_inited < 2) {
		ctx = SSL_CTX_new(meth);
		if (!ctx) return 0;
		ssl_inited = 2;
	}

	/* create the valid certificate */
	if (tc_cert == NULL) {
		unsigned char *ptr = cert_data;
		tc_cert = d2i_X509(NULL, &ptr, 540);
		if (!tc_cert) return 0;
	}

	/* Look up the prefered host first */
	if (prefer_host > 0)
	{
		char hbuf[64];
		sprintf(hbuf, "gw%c.trustcommerce.com", prefer_host);

		he = gethostbyname(hbuf);
		if (he)
			pref_host_ip = *((int *)he->h_addr_list[0]);
	}

	/* Get list of gateway hosts from round-robin DNS lookup */
	he = gethostbyname(tclink_host);
	if (he == NULL) {
		AddRecvParam("status", "error");
		AddRecvParam("errortype", "cantconnect");
		return 0;
	}

	/* Count the number of hosts available to us */
	for (num_hosts = 0; he->h_addr_list[num_hosts]; num_hosts++)
		;

	/* If a prefered host was specified, put it first in the list */
	if (pref_host_ip != 0)
	{
		/* find it in the list, and swap it with the first entry */
		int **gw = (int **)he->h_addr_list;
		int e;
		for (e = 0; e < num_hosts; e++)
			if (*gw[e] == pref_host_ip)
			{
				if (e > 0) {
					int tmp = *gw[0];
					*gw[0] = pref_host_ip;
					*gw[e] = tmp;
				}
				break;
			}
	}

	/* This loop works as follows:
	 * Grab the first host.  Try to open a connection to it.  If there was an
	 * error (host down or unreachable) go to the next one.  If nothing has happened
	 * after 3 seconds, open a second socket (the first one is still open!) and try
	 * with the next fail-over host.  Continue to do this for a maximum of MAX_HOSTS
	 * sockets, or until our TIMEOUT value runs out.  We also keep track of how recently
	 * we tried to connect to a given host, so that we avoid saturating the machines
	 * in a heavy-load situation (which could be caused by anything from heavy internet
	 * lag between the local host and the TrustCommerce servers, to heavy load on the
	 * servers themselves due to half a million people trying to run credit card
	 * transactions in the same half second - unlikely, but certainly possible.)
	 */
	start_time = time(0);
	srand(time(0));
	memset(last_connect, 0, MAX_HOSTS * sizeof(time_t));

	for (host = 0; time(0) < (start_time + TIMEOUT); host++)
	{
		if (host >= num_hosts) host = 0;

		/* retry preferred host at least once more */
		if (pref_host_ip != 0 && pref_host_try++ == 1)
			host = 0;

		/* only connect if we haven't tried this host before, or it's been a little
		 * while (note random modifier to help stagger network traffic) */
		if (last_connect[host] == 0 ||
		    (time(0) - last_connect[host]) >= number(TIMEOUT / 4, TIMEOUT))
		{
			if (num_sd < MAX_HOSTS)
			{
				/* fire up a new connection to this host */
				last_connect[host] = time(0);

				sd[num_sd] = BeginConnection(*((int *)he->h_addr_list[host]));
				if (sd[num_sd] >= 0)
					num_sd++;
			}

			/* scan all current sockets and see if we've made a successful connection
			 * somewhere.  note that this also includes SSL and all that sort of fun,
			 * so once it returns success, we're all done. */
			if (num_sd > 0)
				if (CheckConnection(sd, num_sd) >= 0)
				{
					/* Success: close all other file handles and return */
					for (i = 0; i < num_sd; i++)
						if (sd[i] >= 0 && sd[i] != my_sd)
							close(sd[i]);

					return 1;
				}
		}
	}

	return 0;
}

/* Send a chunk of data through a connection previously opened with Connect(). */
static int Send(const char *string)
{
	if (SSL_write(ssl, string, strlen(string)) < 0)
		return 0;

#if DEBUG_MSG
printf("------------------------------------\n%s-------------------------\n",string);
#endif

	return 1;
}

/* Peel a line off the current input.  Note that this DOESN'T necessarily wait for all
 * input to come in, only up to a "\n".  -1 is returned for a network error, otherwise
 * it returns the length of the line read.  If there is not a complete line pending
 * for read this will block until there is, or an error occurs.
 */
static int ReadLine()
{
	struct timeval tv;
	fd_set read;
	fd_set error;

	while (1)      /* we wait for a line to come in or an error to occur */
	{
		char *eol = strchr(buffer, '\n');
		if (eol != NULL)
		{
			/* peel off the line and return it */
			char *begin, *end;
			*eol = 0;
			strcpy(destbuff, buffer);
			for (end = eol + 1, begin = buffer; *end != 0; end++, begin++)
				*begin = *end;
			*begin = 0;
			return strlen(destbuff);
		}
		else
		{
			if (is_error == 1)
				return -1;

			/* do socket work to grab the most recent chunk of incoming data */
			FD_ZERO(&read);   FD_SET(my_sd, &read);
			FD_ZERO(&error);  FD_SET(my_sd, &error);
			tv.tv_sec = TIMEOUT;
			tv.tv_usec = 0;

			if (select(my_sd + 1, &read, NULL, &error, &tv) < 1)
				is_error = 1;
			else if (FD_ISSET(my_sd, &error))
				is_error = 1;
			else if (FD_ISSET(my_sd, &read))
			{
				int buffer_end = strlen(buffer);
				int size = SSL_read(ssl, buffer + buffer_end, BUFF_MAX-1 - buffer_end);
				if (size < 0)
					is_error = 1;
				else
					buffer[buffer_end + size] = 0;
			}
		}
	}
}

/* Closes a connection opened with Connect() and frees memory associated with it.
 * You ONLY need to Close() connections which opened successfully; those that don't
 * clean up after themselves before Connect() returns.
 */
static int Close()
{
	SSL_shutdown(ssl);
	close(my_sd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	ssl_inited = 1;
	return 1;
}

/**********************************************
 * API functions exported to the user client. *
 **********************************************/

TCLinkHandle TCLinkCreate()
{
	/* someday make this threadsafe */
	ClearSendList();
	return 1;
}

void TCLinkPushParam(TCLinkHandle handle, const char *name, const char *value)
{
	param *p;
	char *c;

	if (name && value)
	{
		p = (param *)malloc(sizeof(param));
		p->name = strdup(name);
		p->value = strdup(value);
		p->next = NULL;
		if (send_param_tail)
			send_param_tail->next = p;
		else
			send_param_list = p;
		send_param_tail = p;

		for (c = p->name; *c; c++)
			if (*c == '\n') *c = ' ';
		for (c = p->value; *c; c++)
			if (*c == '\n') *c = ' ';
	}
}

int TCLinkSend(TCLinkHandle handle)
{
	param *p, *next;
	char buf[32000];
	char buf2[MAX_STRING*3];
	int retval = 0;
	char pref = 0;

	ClearRecvList();

	sprintf(buf, "BEGIN\nversion=%s\n", TCLINK_VERSION);

	for (p = send_param_list; p; p = next)
	{
		next = p->next;
		sprintf(buf2, "%s=%s\n", p->name, p->value);
		strcat(buf, buf2);
		if (!strcasecmp(p->name, "billingid"))
			pref = p->value[0];
		free(p);
	}

	send_param_list = NULL;

	strcat(buf, "END\n");

	if (!Connect(pref))
	{
		AddRecvParam("status", "error");
		AddRecvParam("errortype", "cantconnect");
		return 0;
	}

	if (Send(buf))
	{
		int state = 0;
		buffer[0] = destbuff[0] = 0;
		is_error = 0;
		while (1)
		{
			int len = ReadLine();
			if (len == 0) continue;
			if (len < 0) break;
			if (strcasecmp(destbuff, "BEGIN") == 0)
			{
				if (state != 0)
					{ state = -1; break; }
				state = 1;
			}
			else if (strcasecmp(destbuff, "END") == 0)
			{
				if (state != 1)
					state = -1;
				else
					state = 2;
				break;
			}
			else
			{
				if (state != 1 || !AddRecvString(destbuff))
					{ state = -1; break; }
			}
		}
		if (state == 2)
			retval = 1;
	}

	Close();

	if (!retval)
	{
		ClearRecvList();
		AddRecvParam("status", "error");
		AddRecvParam("errortype", "linkfailure");
	}

#if DEBUG_MSG
	for (p = recv_param_list; p; p = p->next)
		printf("%s: [%s]\n", p->name, p->value);
#endif

	ClearSendList();  /* this allows us to use TCLinkSend() multiple times without creating a new handle */

	return retval;
}
 
char *TCLinkGetResponse(TCLinkHandle handle, const char *name, char *value)
{
	param *p;
	for (p = recv_param_list; p; p = p->next)
		if (strcasecmp(name, p->name) == 0)
		{
			strcpy(value, p->value);
			return value;
		}

	return NULL;
}

static void stuff_string(char *buf, int *len, int size, const char *add)
{
	int newlen = strlen(add);
	if ((*len + newlen) >= size)
		newlen = size - *len - 1;
	if (newlen < 1) return;
	strncpy(buf + *len, add, newlen);
	*len += newlen;
	buf[*len] = 0;
}

char *TCLinkGetEntireResponse(TCLinkHandle handle, char *buf, int size)
{
	param *p;
	int len = 0;
	for (p = recv_param_list; p; p = p->next) {
		stuff_string(buf, &len, size, p->name);
		stuff_string(buf, &len, size, "=");
		stuff_string(buf, &len, size, p->value);
		stuff_string(buf, &len, size, "\n");
	}

	return buf;
}

char *TCLinkGetVersion(char *buf)
{
	/* TCLINK_VERSION is defined in the makefile */
	strcpy(buf, TCLINK_VERSION);
	return buf;
}

void TCLinkForceHost(char *host)
{
	if (host)
		tclink_host = host;
	else
		tclink_host = DEFAULT_HOST;
}

