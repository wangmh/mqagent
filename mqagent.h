/*
 * mqagent.h
 *
 *  Created on: 2011-1-5
 *      Author: saint
 */

#ifndef MQAGENT_H_
#define MQAGENT_H_
#include <glib.h>

#include "ketama.h"
#include <event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>
#include <arpa/inet.h>

#define VERSION "0.1"

#define OUTOFCONN "SERVER_ERROR OUT OF CONNECTION"

#define BUFFERLEN 2048
#define MAX_TOKENS 8
#define COMMAND_TOKEN 0
#define KEY_TOKEN 1
#define FLAGS_TOKEN 2
#define BYTES_TOKEN 4
#define KEY_MAX_LENGTH 250
#define BUFFER_PIECE_SIZE 16

#define UNUSED(x) ( (void)(x) )
#define STEP 5

/* structure definitions */
typedef struct conn conn;
typedef struct matrix matrix;
typedef struct list list;
typedef struct buffer buffer;
typedef struct server server;
typedef struct matrix_node matrix_node;

GHashTable *memcacheq; /* GHashTable<task_name, memcacheq_entry> */

typedef struct _memcacheq_entry
{
	matrix *matrixs;
	struct ketama *ketama ;
	int matrixcnt;
	int matrix_get_idx;
} memcacheq_entry;

typedef enum {
	CLIENT_COMMAND,
	CLIENT_NREAD, /* MORE CLIENT DATA */
	CLIENT_TRANSCATION
} client_state_t;

typedef enum {
	SERVER_INIT,
	SERVER_CONNECTING,
	SERVER_CONNECTED,
	SERVER_ERROR
} server_state_t;

struct buffer {
	char *ptr;

	size_t used;
	size_t size;
	size_t len; /* ptr length */

	struct buffer *next;
};

/* list to buffers */
struct list {
	buffer *first;
	buffer *last;
};

/* connection to memcached server */
struct server {
	int sfd;
	server_state_t state;
	struct event ev;
	int ev_flags;

	matrix *owner;

	/* first response line
	 * NOT_FOUND\r\n
	 * STORED\r\n
	 */
	char line[BUFFERLEN];
	int pos;

	/* get/gets key ....
	 * VALUE <key> <flags> <bytes> [<cas unique>]\r\n
	 */
	int valuebytes;
	int has_response_header:1;
	int remove_trail:1;

	/* input buffer */
	list *request;
	/* output buffer */
	list *response;

	int pool_idx;
};

struct conn {
	/* client part */
	int cfd;
	client_state_t state;
	struct event ev;
	int ev_flags;
	GString *content;
	char flags[10];

	/* command buffer */
	char line[BUFFERLEN+1];
	int pos;

	int storebytes; /* bytes stored by CAS/SET/ADD/... command */

	struct flag {
		unsigned int is_get_cmd:1;
		unsigned int is_gets_cmd:1;
		unsigned int is_set_cmd:1;
		unsigned int is_incr_decr_cmd:1;
		unsigned int no_reply:1;
		unsigned int is_update_cmd:1;
		unsigned int is_backup:1;
		unsigned int is_last_key:1;
	} flag;

	int keycount; /* GET/GETS multi keys */
	int keyidx;
	char **keys;

	/* input buffer */
	list *request;
	/* output buffer */
	list *response;

	struct server *srv;
};

/* memcached server structure */
struct matrix {
	char *ip;
	int port;
	struct sockaddr_in dstaddr;

	int size;
	int used;
	struct server **pool;
};

struct matrix_node
{
	matrix master;//master
	matrix slave;//slaver
};

typedef struct token_s {
	char *value;
	size_t length;
} token_t;


#endif /* MQAGENT_H_ */
