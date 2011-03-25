/*
 * mqagent.c
 *
 *  Created on: 2011-1-5
 *      Author: saint
 */
#define _GNU_SOURCE
#include <sys/types.h>

#if defined(__FreeBSD__)
#include <sys/uio.h>
#include <limits.h>
#else
#include <getopt.h>
#endif

#include <unistd.h>
#include <string.h>

#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <limits.h>
#include <bits/posix1_lim.h>
#include <glib.h>
#include "glib-ext.h"
#include "mqagent.h"
#include "log.h"
#include "config.h"
#include "mqagent_lib.h"

static char *config_file;
int sockfd = -1, curconns = 0;

static struct event ev_master;

const char *LOG_PROGRAMME = "mqagent";

static void drive_client(const int fd, const short which, void *arg);
static void out_string(conn *c, const char *str);

static void rewrite_request(conn *c, list* l);
static void drive_memcached_server(const int fd, const short which, void *arg);

static void set_nonblock(int fd) {
	int flags = 1;
	struct linger ling = { 0, 0 };
	if (fd > 0) {
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
		setsockopt(fd, SOL_SOCKET, SO_LINGER, (void *) &ling, sizeof(ling));
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *) &flags, sizeof(flags));
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &flags, sizeof(flags));
	}
}

static void reload_backend() {
	int i, j;
	char *task_name = NULL;
	memcacheq_entry *backend;
	char *host = NULL;
	char * p;
	matrix *m;
	char temp[65];
	for (i = 0; i < glob_config->task_group_size; i++) {
		task_name = strdup(glob_config->task_group[i]->task_name);
		if (NULL == (backend = g_hash_table_lookup(memcacheq, task_name))) {
			backend = NULL;
			backend = calloc(sizeof(memcacheq_entry), 1);
			if (NULL == backend) {
				jlog(L_ERR, "calloc backend wrong\n");
				exit(-1);
			}
			backend->matrixcnt = glob_config->task_group[i]->nodes_size;
			backend->matrix_get_idx = 0;
			backend->matrixs = (matrix *) calloc(sizeof(matrix),
					backend->matrixcnt);

			if (NULL == backend->matrixs) {
				jlog(L_ERR, "backend->matrixs wrong\n");
				exit(-1);
			}

			for (j = 0; j < glob_config->task_group[i]->nodes_size; j++) {
				m = backend->matrixs + j;
				host = strdup(glob_config->task_group[i]->nodes[j]->master);
				p = strchr(host, ':');
				if (NULL == p) {
					m->ip = strdup(host);
					m->port = 22201;
				} else {
					*p = '\0';
					m->ip = strdup(host);
					*p = ':';
					p++;
					m->port = atoi(p);
					if (m->port <= 0)
						m->port = 22201;
				}
				m->dstaddr.sin_family = AF_INET;
				m->dstaddr.sin_addr.s_addr = inet_addr(m->ip);
				m->dstaddr.sin_port = htons(m->port);
				//	log_debug("hostname is %s\n",m->ip);
			}
			//glob_config->task_group[i]->nodes_size
			if (glob_config->useketama) {
				backend->ketama = (struct ketama *) calloc(
						sizeof(struct ketama), 1);
				if (NULL == backend->ketama) {
					jlog(L_ERR, "calloc backend->ketama failed");
					exit(-1);
				} else {
					backend->ketama->count = backend->matrixcnt;
					backend->ketama->weight = (int *) calloc(sizeof(int *),
							backend->ketama->count);
					backend->ketama->name = (char **) calloc(sizeof(char *),
							backend->ketama->count);
					if (backend->ketama->weight == NULL
							|| backend->ketama->weight == NULL) {
						jlog(L_ERR, "not enough memory to create ketama\n");
						exit(-1);
					}
					for (j = 0; j < backend->ketama->count; j++) {
						backend->ketama->weight[j] = 100;
						backend->ketama->totalweight
								+= backend->ketama->weight[j];
						snprintf(temp, 64, "%s-%d", (backend->matrixs + j)->ip,
								(backend->matrixs + j)->port);
						log_debug("temp is %s\n", temp);
						backend->ketama->name[j] = strdup(temp);
						if (NULL == backend->ketama->name[j]) {
							jlog(L_ERR, "not enough memory to create ketama\n");
							exit(-1);
						}
					}
				}
				if (create_ketama(backend->ketama, 500)) {
					jlog(L_ERR, "can't create ketama\n");
					exit(-1);
				}
			}
			jlog(L_INFO, " %s taskqueue is ready\n", task_name);
			g_hash_table_insert(memcacheq, task_name, backend);
		} else {
			continue;
		}
	}

}

static void reload() {
	if (NULL == config_file) {
		jlog(L_ERR, "can't find config_file");
		return;
	}
	init_config(config_file);
	reload_backend();

}

static void free_matrix(matrix *m) {
	int i;
	struct server *s;

	if (m == NULL)
		return;

	for (i = 0; i < m->used; i++) {
		s = m->pool[i];
		if (s->sfd > 0)
			close(s->sfd);
		list_free(s->request, 0);
		list_free(s->response, 0);
		free(s);
	}

	free(m->pool);
	free(m->ip);
}

static gboolean hash_table_true(gpointer key, gpointer value,
		gpointer UNUSED_PARAM( u)) {
	return TRUE;
}
/*
 * typedef struct _node
 {
 char *master;
 char *slave;
 }s_node;

 typedef struct _task_group
 {
 s_node **nodes;
 int nodes_size;
 char *task_name;
 }s_task_group;

 typedef struct _config
 {
 char *logdir;
 s_task_group **task_group;
 int task_group_size;
 int maxconns;
 int maxidle;
 bool useketama;
 int port;
 bool daemon;
 bool verbose_mode;
 char *host_ip;

 } s_config;
 */
static void free_node(s_node *node) {
	if (NULL == node) {
		return;
	}
	if (NULL != node->master) {
		free(node->master);
	}
	if (NULL != node->slave) {
		free(node->slave);
	}
	free(node);
}

static void free_task_group(s_task_group *task_group) {
	int i;
	if (NULL == task_group)
		return;
	for (i = 0; i < task_group->nodes_size; i++) {
		free_node(task_group->nodes[i]);
	}
	free(task_group);
}
static void free_config() {
	int i;
	if (NULL == glob_config)
		return;
	if (NULL != glob_config->host_ip) {
		free(glob_config->host_ip);
	}
	if (NULL != glob_config->logdir) {
		free(glob_config->logdir);
	}
	if (NULL != glob_config->task_group) {
		for (i = 0; i < glob_config->task_group_size; i++) {
			free_task_group(glob_config->task_group[i]);
		}

	}
	free(glob_config->task_group);

	free(glob_config);
}

static void server_exit(int sig) {

	jlog(L_INFO, "mqagent is exiting");

	UNUSED(sig);

	if (sockfd > 0)
		close(sockfd);

	g_hash_table_foreach_remove(memcacheq, (GHRFunc) hash_table_true, NULL);

	g_hash_table_destroy(memcacheq);

	free_config();

	exit(0);
}
static void signal_handler(int sig) {
	switch (sig) {
	case SIGINT:
		server_exit(sig);
		break;
	case SIGTERM:
		server_exit(sig);
		break;
	case SIGHUP:
		reload();
		jlog(L_INFO, "%s has reloaded \n", LOG_PROGRAMME);
		break;
	}
}
//when the value remove from the hashtable，free the mem
static void g_queue_free_all(gpointer q) {
	int i;

	memcacheq_entry *backend = (memcacheq_entry *) q;

	free_ketama(backend->ketama);

	for (i = 0; i < backend->matrixcnt; i++) {
		free_matrix(backend->matrixs + i);
	}

	free(backend->matrixs);

	free(backend);
}

static void free_key(gpointer data) {
	free(data);
}

static void init_backend() {
	int i, j;
	memcacheq = g_hash_table_new_full(g_str_hash, g_str_equal, free_key,
			g_queue_free_all);
	char *task_name = NULL;
	memcacheq_entry *backend;
	char *host = NULL;
	char * p;
	matrix *m;
	char temp[65];
	for (i = 0; i < glob_config->task_group_size; i++) {
		task_name = strdup(glob_config->task_group[i]->task_name);
		backend = NULL;
		backend = calloc(sizeof(memcacheq_entry), 1);
		if (NULL == backend) {
			jlog(L_ERR, "calloc backend wrong\n");
			exit(-1);
		}
		backend->matrix_get_idx = 0;
		backend->matrixcnt = glob_config->task_group[i]->nodes_size;
		backend->matrixs
				= (matrix *) calloc(sizeof(matrix), backend->matrixcnt);

		if (NULL == backend->matrixs) {
			jlog(L_ERR, "backend->matrixs wrong\n");
			exit(-1);
		}

		for (j = 0; j < glob_config->task_group[i]->nodes_size; j++) {
			m = backend->matrixs + j;
			host = strdup(glob_config->task_group[i]->nodes[j]->master);
			p = strchr(host, ':');
			if (NULL == p) {
				m->ip = strdup(host);
				m->port = 22201;
			} else {
				*p = '\0';
				m->ip = strdup(host);
				*p = ':';
				p++;
				m->port = atoi(p);
				if (m->port <= 0)
					m->port = 22201;
			}
			free(host);
			m->dstaddr.sin_family = AF_INET;
			m->dstaddr.sin_addr.s_addr = inet_addr(m->ip);
			m->dstaddr.sin_port = htons(m->port);
			//	log_debug("hostname is %s\n",m->ip);
		}
		//glob_config->task_group[i]->nodes_size
		if (glob_config->useketama) {
			backend->ketama
					= (struct ketama *) calloc(sizeof(struct ketama), 1);
			if (NULL == backend->ketama) {
				jlog(L_ERR, "calloc backend->ketama failed");
				exit(-1);
			} else {
				backend->ketama->count = backend->matrixcnt;
				backend->ketama->weight = (int *) calloc(sizeof(int *),
						backend->ketama->count);
				backend->ketama->name = (char **) calloc(sizeof(char *),
						backend->ketama->count);
				if (backend->ketama->weight == NULL || backend->ketama->weight
						== NULL) {
					jlog(L_ERR, "not enough memory to create ketama\n");
					exit(-1);
				}
				for (j = 0; j < backend->ketama->count; j++) {
					backend->ketama->weight[j] = 100;
					backend->ketama->totalweight += backend->ketama->weight[j];
					snprintf(temp, 64, "%s-%d", (backend->matrixs + j)->ip,
							(backend->matrixs + j)->port);
					log_debug("temp is %s\n", temp);
					backend->ketama->name[j] = strdup(temp);
					if (NULL == backend->ketama->name[j]) {
						jlog(L_ERR, "not enough memory to create ketama\n");
						exit(-1);
					}
				}
			}
			if (create_ketama(backend->ketama, 500)) {
				jlog(L_ERR, "can't create ketama\n");
				exit(-1);
			}
		}
		jlog(L_INFO, " %s taskqueue is ready\n", task_name);
		g_hash_table_insert(memcacheq, task_name, backend);
		//free(task_name);
	}
	if (glob_config->useketama)
		jlog(L_INFO, "using ketama algorithm\n");
}

/* finish proxy transcation */
static void finish_transcation(conn *c) {
	int i;

	if (c == NULL)
		return;

	if (c->keys) {
		for (i = 0; i < c->keycount; i++)
			free(c->keys[i]);
		free(c->keys);
		c->keys = NULL;
		c->keycount = c->keyidx = 0;
	}
	g_string_assign(c->content, "");
	c->state = CLIENT_COMMAND;
	list_free(c->request, 1);
}

static void init_socket() {

	struct sockaddr_in server;
	if (glob_config->port > 0) {
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0) {
			jlog(L_ERR, "can't create network socket");
			exit(-1);
		}
		set_nonblock(sockfd);

		memset((char *) &server, 0, sizeof(server));
		server.sin_family = AF_INET;
		if (NULL == glob_config->host_ip) {
			server.sin_addr.s_addr = htonl(INADDR_ANY);
		} else
			server.sin_addr.s_addr = inet_addr(glob_config->host_ip);
		server.sin_port = htons(glob_config->port);
		if (bind(sockfd, (struct sockaddr*) &server, sizeof(server))) {
			if (errno != EINTR) {
				jlog(L_ERR, "bind errno = %d,%s \n", errno, strerror(errno));
			}
			close(sockfd);
			exit(-1);
		}
		if (listen(sockfd, 1024)) {
			jlog(L_ERR, "listen errno = %d, %s", errno, strerror(errno));
			close(sockfd);
			exit(-1);
		}
	}
}

static void server_error(conn *c, const char *s) {
	int i;

	if (c == NULL)
		return;

	if (c->srv) {
		server_free(c->srv);
		c->srv = NULL;
	}

	if (c->keys) {
		for (i = 0; i < c->keycount; i++)
			free(c->keys[i]);
		free(c->keys);
		c->keys = NULL;
	}

	c->pos = c->keycount = c->keyidx = 0;
	list_free(c->request, 1);
	list_free(c->response, 1);
	out_string(c, s);
	c->state = CLIENT_COMMAND;
}
/* return 0 if ok, return 1 if failed */
static int socket_connect(struct server *s) {
	socklen_t servlen;

	if (s == NULL || s->sfd <= 0 || s->state != SERVER_INIT)
		return 1;

	servlen = sizeof(s->owner->dstaddr);
	if (-1
			== connect(s->sfd, (struct sockaddr *) &(s->owner->dstaddr),
					servlen)) {
		if (errno != EINPROGRESS && errno != EALREADY)
			return 1;
		s->state = SERVER_CONNECTING;
	} else {
		s->state = SERVER_CONNECTED;
	}

	return 0;
}
static void pool_server_handler(const int fd, const short which, void *arg) {
	struct server *s;
	struct matrix *m;
	char buf[128];
	int toread = 0, toexit = 0, i;

	if (arg == NULL)
		return;
	s = (struct server *) arg;

	if (!(which & EV_READ))
		return;

	/* get the byte counts of read */
	if (ioctl(s->sfd, FIONREAD, &toread) || toread == 0) {
		jlog(L_ERR, " (%s.%d) CLOSE POOL SERVER FD1111 %d\n", __FILE__,
				__LINE__, s->sfd);
		toexit = 1;
	} else {
		if (toread > 128)
			toread = 128;

		if (0 == read(s->sfd, buf, toread))
			toexit = 1;
	}

	if (toexit) {
		jlog(L_ERR, " (%s.%d) CLOSE POOL SERVER FD %d\n", __FILE__, __LINE__,
				s->sfd);
		event_del(&(s->ev));
		close(s->sfd);

		list_free(s->request, 0);
		list_free(s->response, 0);
		m = s->owner;
		if (m) {
			if (s->pool_idx <= 0) {
				jlog(L_ERR, "%s: (%s.%d) POOL SERVER FD %d, IDX %d <= 0\n",
						__FILE__, __LINE__, s->sfd, s->pool_idx);
			} else {
				/* remove from list */
				for (i = s->pool_idx; i < m->used; i++) {
					m->pool[i - 1] = m->pool[i];
					m->pool[i - 1]->pool_idx = i;
				}
				--m->used;
			}
		}
		free(s);
	}
}

/* put server connection into keep alive pool */
static void put_server_into_pool(struct server *s) {
	struct matrix *m;
	struct server **p;

	if (s == NULL)
		return;

	if (s->owner == NULL || s->state != SERVER_CONNECTED || s->sfd <= 0) {
		server_free(s);
		return;
	}

	list_free(s->request, 1);
	list_free(s->response, 1);
	s->pos = s->has_response_header = s->remove_trail = 0;

	m = s->owner;
	if (m->size == 0) {
		m->pool = (struct server **) calloc(sizeof(struct server *), STEP);
		if (m->pool == NULL) {
			jlog(L_ERR, " (%s.%d) out of memory for pool allocation\n",
					__FILE__, __LINE__);
			m = NULL;
		} else {
			m->size = STEP;
			m->used = 0;
		}
	} else if (m->used == m->size) {
		if (m->size < glob_config->maxidle) {
			p = (struct server **) realloc(m->pool, sizeof(struct server *)
					* (m->size + STEP));
			if (p == NULL) {
				jlog(L_ERR, "(%s.%d) out of memory for pool reallocation\n",
						__FILE__, __LINE__);
				m = NULL;
			} else {
				m->pool = p;
				m->size += STEP;
			}
		} else {
			m = NULL;
		}
	}

	if (m != NULL) {
		jlog(L_DEBUG, "(%s.%d) PUT SERVER FD %d -> POOL\n", __FILE__, __LINE__,
				s->sfd);
		m->pool[m->used++] = s;
		s->pool_idx = m->used;
		event_del(&(s->ev));

		event_set(&(s->ev), s->sfd, EV_READ | EV_PERSIST, pool_server_handler,
				(void *) s);
		event_add(&(s->ev), 0);
	} else {
		server_free(s);
	}

}

static void process_update_response(conn *c) {
	struct server *s;
	buffer *b;
	int pos;

	if (c == NULL || c->srv == NULL || c->srv->pos == 0)
		return;
	s = c->srv;
#if 0
	pos = memstr(s->line, "\n", s->pos, 1);
	if (pos == -1) return; /* not found */
#else
	if (s->line[s->pos - 1] != '\n')
		return;
	pos = s->pos - 1;
#endif
	/* found \n */
	pos++;

	b = buffer_init_size(pos + 1);
	if (b == NULL) {
		jlog(L_ERR, "(%s.%d) SERVER OUT OF MEMORY\n", __FILE__, __LINE__);
		server_error(c, "SERVER_ERROR OUT OF MEMORY");
		return;
	}
	memcpy(b->ptr, s->line, pos);
	b->size = pos;

	append_buffer_to_list(s->response, b);
	move_list(s->response, c->response);
	put_server_into_pool(s);
	c->srv = NULL;
	if (writev_list(c->cfd, c->response) >= 0) {
		if (c->response->first && (c->ev_flags != EV_WRITE)) {
			event_del(&(c->ev));
			event_set(&(c->ev), c->cfd, EV_WRITE | EV_PERSIST, drive_client,
					(void *) c);
			event_add(&(c->ev), 0);
			c->ev_flags = EV_WRITE;
		}
		finish_transcation(c);
	} else {
		/* client reset/close connection*/
		conn_close(c);
	}
}

static void do_transcation(conn *c) {
	int idx;
	struct matrix *m;
	struct server *s;
	struct ketama *ketama = NULL;
	char *lookup;
	char *look_content;
	struct timeval now;
	char ketama_key[128];
	buffer *b;
	memcacheq_entry *task_entry = NULL;

	char *key = NULL;
	log_debug("come here %s.%d", __FILE__, __LINE__);
	if (c == NULL)
		return;
	if (c->flag.is_get_cmd) {
		//支持mget的协议下，我们不做
		if (c->keyidx >= c->keycount) {
			/* end of get transcation */
			finish_transcation(c);
			return;
		}
		key = c->keys[c->keyidx++];
		if (c->keyidx == c->keycount)
			c->flag.is_last_key = 1;
	} else {
		key = c->keys[0];
	}
	//get lookup by key->taskname with round_robin method
	if (c->flag.is_get_cmd) {
		lookup = strdup(key);
	} else//set lookup by content  taskname/jid
	{

		look_content = strdup(key);
		char *p = strchr(look_content, '/');
		if (NULL == p) {
			lookup = look_content;
		} else {
			*p = '\0';
			lookup = strdup(look_content);
			*p = '/';
			free(look_content);
		}

	}
	task_entry = (memcacheq_entry *) g_hash_table_lookup(memcacheq, lookup);
	jlog(L_DEBUG, "task %s is", lookup);
	if (NULL == task_entry) {
		jlog(L_ERR, "task %s is not found", lookup);
		out_string(c, "task is not found");
		finish_transcation(c);
		return;
	}
	free(lookup);
	if (c->flag.is_get_cmd) {
		idx = task_entry->matrix_get_idx++ % task_entry->matrixcnt;
		if (task_entry->matrix_get_idx >= task_entry->matrixcnt) {
			task_entry->matrix_get_idx = 0;
		}
	} else {
		ketama = task_entry->ketama;
		if (glob_config->useketama && ketama) {
			memset(ketama_key, 0 , sizeof(ketama_key));
			look_content = strdup(key);
			char *p = strchr(look_content, '/');//如果没有ketama的分布
			if ((NULL == p) || ('\0' == *(p + 1))) {
				gettimeofday(&now, NULL);
				snprintf(ketama_key, sizeof(ketama_key), "%s-%ld-%ld", look_content,now.tv_sec, now.tv_usec);
			} else {
				snprintf(ketama_key, sizeof(ketama_key), p + 1);
			}
			free(look_content);
			idx = get_server(ketama, ketama_key);
			if (idx < 0) {
				idx = hashme(key) % task_entry->matrixcnt;
			}
		} else {
			idx = hashme(key) % task_entry->matrixcnt;
		}

	}
	jlog(L_DEBUG, "matrixs is %d\n", idx);

	m = task_entry->matrixs + idx;

	if (m->pool && (m->used > 0)) {
		s = m->pool[--m->used];
		s->pool_idx = 0;
	} else {
		if (NULL == (s = (struct server*) calloc(sizeof(struct server), 1))) {
			jlog(L_ERR, "%s.%d out of memory", __FILE__, __LINE__);
			conn_close(c);
			return;
		}
		s->request = list_init();
		s->response = list_init();
		s->state = SERVER_INIT;
	}
	s->owner = m;
	c->srv = s;
	jlog(L_DEBUG, "%s KEY \"%s\" -> %s:%d", c->flag.is_get_cmd ? "GET" : "SET",
			key, m->ip, m->port);
	if (s->sfd <= 0) {
		if ((s->sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			jlog(L_ERR, "can't create tcp socket to memcached");
			server_error(c, "server_error can't connect to backent");
			return;
		}
		set_nonblock(s->sfd);

		memset(&(s->ev), 0, sizeof(struct event));
	} else {
		event_del(&(s->ev));
		s->state = SERVER_CONNECTED;
	}
	s->has_response_header = 0;
	s->remove_trail = 0;
	s->valuebytes = 0;
	if (c->flag.is_get_cmd) {
		b = buffer_init_size(strlen(key) + 20);
		if (b == NULL) {
			jlog(L_ERR, "%s: (%s.%d) SERVER OUT OF MEMORY\n", __FILE__,
					__LINE__);
			server_error(c, "SERVER_ERROR OUT OF MEMORY");
			return;
		}
		b->size = snprintf(b->ptr, b->len - 1, "%s %s\r\n",
				c->flag.is_gets_cmd ? "gets" : "get", key);
		append_buffer_to_list(s->request, b);
	} else {
		rewrite_request(c, s->request);
	}
	c->state = CLIENT_TRANSCATION;
	if (s->state == SERVER_INIT && socket_connect(s)) {
		server_error(c, "SERVER_ERROR CAN NOT CONNECT TO BACKEND SERVER");
		return;
	}
	event_set(&(s->ev), s->sfd, EV_PERSIST | EV_WRITE, drive_memcached_server,
			(void *) c);
	event_add(&(s->ev), 0);
	s->ev_flags = EV_WRITE;
	return;
}

static void process_get_response(conn *c, int r) {
	struct server *s;
	buffer *b;
	int pos;

	if (c == NULL || c->srv == NULL || c->srv->pos == 0)
		return;
	s = c->srv;
	if (s->has_response_header == 0) {
		pos = memstr(s->line, "\n", s->pos, 1);

		if (pos == -1)
			return; /* not found */

		/* found \n */
		s->has_response_header = 1;
		s->remove_trail = 0;
		pos++;

		s->valuebytes = -1;

		/* VALUE <key> <flags> <bytes> [<cas unique>]\r\n
		 * END\r\n*/

		//	jlog(L_INFO, "get response is %s", s->line);
		if (strncasecmp(s->line, "VALUE ", 6) == 0) {
			char *p = NULL;
			p = strchr(s->line + 6, ' ');
			if (p) {
				p = strchr(p + 1, ' ');
				if (p) {
					s->valuebytes = atol(p + 1);
					if (s->valuebytes < 0) {
						/* END\r\n or SERVER_ERROR\r\n
						 * just skip this transcation
						 */
						put_server_into_pool(s);
						c->srv = NULL;
						if (c->flag.is_last_key)
							out_string(c, "END");
						do_transcation(c); /* TO Next KEY */
						return;
					}
				}
			}
		}
		if (s->valuebytes < 0) {
			/* END\r\n or SERVER_ERROR\r\n
			 * just skip this transcation
			 */
			put_server_into_pool(s);
			c->srv = NULL;
			if (c->flag.is_last_key)
				out_string(c, "END");
			do_transcation(c); /* TO Next KEY */
			return;
		}

		s->valuebytes += 7; /* trailing \r\nEND\r\n */

		b = buffer_init_size(pos + 1);

		if (b == NULL) {
			jlog(L_ERR, " (%s.%d) SERVER OUT OF MEMORY\n", __FILE__, __LINE__);
			conn_close(c); /* TO Next KEY */
			return;
		}
		memcpy(b->ptr, s->line, pos);
		b->size = pos;
		append_buffer_to_list(s->response, b);

		if (s->pos > pos) {
			memmove(s->line, s->line + pos, s->pos - pos);
			s->pos -= pos;
		} else {
			s->pos = 0;
		}

		if (s->pos > 0)
			s->valuebytes -= s->pos;
	} else {
		/* HAS RESPONSE HEADER */
		s->valuebytes -= r;
	}

	if (s->remove_trail) {
		s->pos = 0;
	} else if (s->pos > 0) {
		b = buffer_init_size(s->pos + 1);
		if (b == NULL) {
			jlog(L_ERR, " (%s.%d) SERVER OUT OF MEMORY\n", __FILE__, __LINE__);
			conn_close(c);
			return;
		}
		memcpy(b->ptr, s->line, s->pos);
		b->size = s->pos;

		if (s->valuebytes <= 5) {
			b->size -= (5 - s->valuebytes); /* remove trailing END\r\n */
			s->remove_trail = 1;
		}
		s->pos = 0;

		append_buffer_to_list(s->response, b);
	}

	if (s->valuebytes == 0) {
		/* GET commands finished, go on next memcached server */
		move_list(s->response, c->response);
		put_server_into_pool(s);
		c->srv = NULL;
		if (c->flag.is_last_key) {
			b = buffer_init_size(6);
			if (b) {
				memcpy(b->ptr, "END\r\n", 5);
				b->size = 5;
				b->ptr[b->size] = '\0';
				append_buffer_to_list(c->response, b);
			} else {
				jlog(L_ERR, "%s: (%s.%d) OUT OF MEMORY\n", __FILE__, __LINE__);
			}
		}

		if (writev_list(c->cfd, c->response) >= 0) {
			if (c->response->first && (c->ev_flags != EV_WRITE)) {
				event_del(&(c->ev));
				event_set(&(c->ev), c->cfd, EV_WRITE | EV_PERSIST,
						drive_client, (void *) c);
				event_add(&(c->ev), 0);
				c->ev_flags = EV_WRITE;
			}
			do_transcation(c); /* NEXT MEMCACHED SERVER */
		} else {
			/* client reset/close connection*/
			conn_close(c);
		}
	}

}

static void drive_memcached_server(const int fd, const short which, void *arg) {
	struct server *s;
	conn *c;
	int socket_error, r, toread;
	socklen_t servlen, socket_error_len;

	if (NULL == arg)
		return;
	c = (conn *) arg;

	s = c->srv;
	if (NULL == arg)
		return;

	if (which & EV_WRITE) {
		switch (s->state) {
		case SERVER_INIT:
			servlen = sizeof(s->owner->dstaddr);
			if (-1 == connect(s->sfd, (struct sockaddr *) &(s->owner->dstaddr),
					servlen)) {
				if (errno != EINPROGRESS && errno != EALREADY) {
					jlog(L_ERR, "(%s.%d) can't connect to main server %s:%d",
							__FILE__, __LINE__, s->owner->ip, s->owner->port);
					server_error(c,
							"server_error can not connect to backend server");
					return;
				}
			}
			s->state = SERVER_CONNECTING;
			break;
		case SERVER_CONNECTING:
			socket_error_len = sizeof(socket_error);
			if ((0 != getsockopt(s->sfd, SOL_SOCKET, SO_ERROR, &socket_error,
					&socket_error_len)) || (socket_error != 0)) {
				jlog(L_ERR, "(%s.%d) can't connect to main server %s:%d",
						__FILE__, __LINE__, s->owner->ip, s->owner->port);
				server_error(c,
						"server_error can not connect to backend server");
				return;
			}
			jlog(L_DEBUG, "connected fd %d <-> %s:%d", s->sfd, s->owner->ip,
					s->owner->port);
			s->state = SERVER_CONNECTED;
			break;
		case SERVER_CONNECTED:
			r = writev_list(s->sfd, s->request);
			if (r < 0) {
				server_error(c,
						"SERVER_ERROR CAN NOT WRITE REQUEST TO BACKEND SERVER");
				return;
			} else {
				if (s->request->first == NULL) {
					if (c->flag.no_reply) {
						finish_transcation(c);
					} else if (s->ev_flags != EV_READ) {
						event_del(&(s->ev));
						event_set(&(s->ev), s->sfd, EV_READ | EV_PERSIST,
								drive_memcached_server, arg);
						event_add(&(s->ev), 0);
						s->ev_flags = EV_READ;
					}
				}
			}
			break;
		case SERVER_ERROR:
			server_error(c, "server_error backend ");
			break;
		}
		return;
	}
	if (!(which & EV_READ))
		return;

	if (ioctl(s->sfd, FIONREAD, &toread) || toread == 0) {
		server_error(c, "SERVER_ERROR BACKEND SERVER RESET OR CLOSE CONNECTION");
		return;
	}
	if (c->flag.is_get_cmd) {
		if (s->has_response_header == 0) {
			/* NO RESPONSE HEADER */
			if (toread > (BUFFERLEN - s->pos))
				toread = BUFFERLEN - s->pos;
		} else {
			/* HAS RESPONSE HEADER */
			if (toread > (BUFFERLEN - s->pos))
				toread = BUFFERLEN - s->pos;
			if (toread > s->valuebytes)
				toread = s->valuebytes;
		}
	} else {
		if (toread > (BUFFERLEN - s->pos))
			toread = BUFFERLEN - s->pos;
	}
	r = read(s->sfd, s->line + s->pos, toread);
	if (r <= 0) {
		if (r == 0 || (errno != EAGAIN && errno != EINTR)) {
			server_error(c, "SERVER_ERROR BACKEND SERVER CLOSE CONNECTION");
		}
		return;
	}
	s->pos += r;
	s->line[s->pos] = '\0';
	if (c->flag.is_get_cmd)
		process_get_response(c, r);
	else
		process_update_response(c);

}

static void rewrite_request(conn *c, list* l) {
	buffer *b;
	int storebytes;
	GString *request;
	char *newkey = NULL;
	if(c->keycount < 1) return;
	char *oldkey = c->keys[0];
	request = g_string_new(NULL);

	char *content = strdup(oldkey);
	char *p = strchr(content, '/');
	if(p == NULL || *(p + 1) == '\0')
	{
		newkey = content;
	}
	else
	{
		*p = '\0';
		newkey = strdup(content);
		*p = '/';
		free(content);
	}
	storebytes = c->content->len - 2;
	g_string_append_printf(request, "set %s %s 0 %d\r\n%s", newkey,c->flags,storebytes,
			c->content->str);
	jlog(L_INFO, "%s -> connection %s:%d", request->str, c->srv->owner->ip,
			c->srv->owner->port);
	free(newkey);

	b = buffer_init_size(request->len + 1);
	memcpy(b->ptr, request->str, request->len);
	b->ptr[request->len] = '\0';
	b->size = request->len;
	append_buffer_to_list(l, b);
	g_string_free(request, TRUE);
}

static void start_magent_transcation(conn *c) {
	if (c == NULL)
		return;
	/* start first transaction to normal server */
	do_transcation(c);
}

static void process_command(conn *c) {
	char *p;
	int len, skip = 0, i, j;
	buffer *b;
	token_t tokens[MAX_TOKENS];
	size_t ntokens;

	//当不是command命令的时候
	if (c->state != CLIENT_COMMAND)
		return;

	/*协议/r/n*/
	p = strchr(c->line, '\n');
	if (NULL == p)
		return;
	len = p - c->line;
	*p = '\0';
	if (*(p - 1) == '\r') {
		*(p - 1) = '\0';
		len--;
	}

	b = buffer_init_size(len + 3);

	memcpy(b->ptr, c->line, len);
	b->ptr[len] = '\r';
	b->ptr[len + 1] = '\n';
	b->ptr[len + 2] = '\0';
	b->size = len + 2;

	jlog(L_DEBUG, " (%s.%d) PROCESSING COMMAND: %s", __FILE__, __LINE__, b->ptr);

	memset(&(c->flag), 0, sizeof(c->flag));
	c->flag.is_update_cmd = 1;
	c->storebytes = c->keyidx = 0;

	ntokens = tokenize_command(c->line, tokens, MAX_TOKENS);
	if ((ntokens == 6 || ntokens == 7) && (strcmp(tokens[COMMAND_TOKEN].value,
			"set") == 0)) {
		
		c->flag.is_set_cmd = 1;
		c->storebytes = atol(tokens[BYTES_TOKEN].value);
		c->storebytes += 2; /* \r\n */
		jlog(L_DEBUG, "process command %s,len is %d", b->ptr, b->size);
	} else if (ntokens >= 3 && ((strcmp(tokens[COMMAND_TOKEN].value, "get")
			== 0)))//only support get and set
	{
		/*
		 * get <key>*\r\n
		 *
		 * VALUE <key> <flags> <bytes> [<cas unique>]\r\n
		 * <data block>\r\n
		 * "END\r\n"
		 */
		c->keycount = ntokens - KEY_TOKEN - 1;
		c->keys = (char **) calloc(sizeof(char*), c->keycount);
		if (c->keys == NULL) {
			c->keycount = 0;
			out_string(c, "SERVER OUT OF MEMORY");
			skip = 1;
		} else {
			if (ntokens < MAX_TOKENS) {
				for (i = KEY_TOKEN, j = 0; (i < ntokens) && (j < c->keycount); i++, j++)
					c->keys[j] = strdup(tokens[i].value);
			} else {
				char *pp, **nn;
				for (i = KEY_TOKEN, j = 0; (i < (MAX_TOKENS - 1)) && (j
						< c->keycount); i++, j++)
					c->keys[j] = strdup(tokens[i].value);

				if (tokens[MAX_TOKENS - 1].value != NULL) {
					/* check for last TOKEN */
					pp = strtok(tokens[MAX_TOKENS - 1].value, " ");

					while (pp != NULL) {
						nn = (char **) realloc(c->keys, (c->keycount + 1)
								* sizeof(char *));
						if (nn == NULL) {
							/* out of memory */
							break;
						}
						c->keys = nn;
						c->keys[c->keycount] = strdup(pp);
						c->keycount++;
						pp = strtok(NULL, " ");
					}
				} else {
					/* last key is NULL, set keycount to actual number*/
					c->keycount = j;
				}
			}

			c->flag.is_get_cmd = 1;
			c->keyidx = 0;
			c->flag.is_update_cmd = 0;

		}

	} else if (ntokens == 2 && (strcmp(tokens[COMMAND_TOKEN].value, "quit")
			== 0)) {
		buffer_free(b);
		conn_close(c);
		return;
	} else {
		out_string(c, "UNSUPPORTED COMMAND");
		skip = 1;
	}
	if (0 == skip) {
		append_buffer_to_list(c->request, b);
		if (0 == c->flag.is_get_cmd)//if not get
		{
			if (tokens[ntokens - 2].value && strcmp(tokens[ntokens - 2].value,
					"noreply") == 0)
				c->flag.no_reply = 1;
			c->keycount = 1;
			c->keys = (char **) calloc(sizeof(char *), 1);
			if (c->keys == NULL) {
				jlog(L_ERR, "server out of memory");
				conn_close(c);
				return;
			}
			c->keys[0] = strdup(tokens[KEY_TOKEN].value);
			memset(c->flags,0, sizeof(c->flags));
			snprintf(c->flags,sizeof(c->flags), "%s", tokens[FLAGS_TOKEN].value);
		}
	} else {
		buffer_free(b);
	}

	i = p - c->line + 1;
	if (i < c->pos) {
		memmove(c->line, p + 1, c->pos - i);
		c->pos -= i;
	} else {
		c->pos = 0;
	}

	if (c->storebytes > 0) {
		if (c->pos > 0) {

			b = buffer_init_size(c->pos + 1);
			if (NULL == b) {
				jlog(L_ERR, "(%s.%d)server out of memory\n", __FILE__, __LINE__);
				conn_close(c);
				return;
			}
			memcpy(b->ptr, c->line, c->pos);

			b->size = c->pos;
			c->storebytes -= b->size;
			append_buffer_to_list(c->request, b);
			g_string_append(c->content, b->ptr);//
			c->pos = 0;
		}
		if (c->storebytes > 0) {
			c->state = CLIENT_NREAD;
		} else
			start_magent_transcation(c);
	} else {
		if (skip == 0)
			start_magent_transcation(c);
	}

}

static void out_string(conn *c, const char *str) {
	/* append str to c->wbuf */
	int len = 0;
	buffer *b;

	if (c == NULL || str == NULL || str[0] == '\0')
		return;

	len = strlen(str);

	b = buffer_init_size(len + 3);
	if (b == NULL)
		return;

	memcpy(b->ptr, str, len);
	memcpy(b->ptr + len, "\r\n", 2);
	b->size = len + 2;
	b->ptr[b->size] = '\0';

	append_buffer_to_list(c->response, b);

	if (writev_list(c->cfd, c->response) >= 0) {
		if (c->response->first && (c->ev_flags != EV_WRITE)) {
			/* update event handler */
			event_del(&(c->ev));
			event_set(&(c->ev), c->cfd, EV_WRITE | EV_PERSIST, drive_client,
					(void *) c);
			event_add(&(c->ev), 0);
			c->ev_flags = EV_WRITE;
		}
	} else {
		/* client reset/close connection*/
		conn_close(c);
	}
}

/* drive machine of client connection */
static void drive_client(const int fd, const short which, void *arg) {
	conn *c;
	int r, toread;
	buffer *b;

	c = (conn *) arg;
	if (NULL == c)
		return;
	if (which & EV_READ) {
		if (ioctl(c->cfd, FIONREAD, &toread) || toread == 0) {
			conn_close(c);
			return;
		}
		switch (c->state) {
		case CLIENT_TRANSCATION:
		case CLIENT_COMMAND:
			r = BUFFERLEN - c->pos;
			if (r > toread)
				r = toread;
			toread = read(c->cfd, c->line + c->pos, r);
			if ((toread <= 0) && (errno != EINTR && errno != EAGAIN)) {
				conn_close(c);
				return;
			}
			c->pos += toread;
			c->line[c->pos] = '\0';
			process_command(c);
			break;
		case CLIENT_NREAD:
			if (c->flag.is_set_cmd == 0) {
				jlog(L_ERR, "wrong state, should be set command\n");
				conn_close(c);
				return;
			}
			if (toread > c->storebytes)
				toread = c->storebytes;
			b = buffer_init_size(toread + 1);
			if (NULL == b) {
				jlog(L_ERR, "out of memory");
				conn_close(c);
				return;
			}
			r = read(c->cfd, b->ptr, toread);
			if ((r < 0) && (errno != EINTR && errno != EAGAIN)) {
				buffer_free(b);
				conn_close(c);
				return;
			}
			b->size = r;
			b->ptr[r] = '\0';
			append_buffer_to_list(c->request, b);
			g_string_append(c->content, b->ptr);//add @saint
			c->storebytes -= r;
			if (c->storebytes <= 0) {
				start_magent_transcation(c);
			}

		}
	} else if (which & EV_WRITE) {
		/* write to client */
		r = writev_list(c->cfd, c->response);
		if (r < 0) {
			conn_close(c);
			return;
		}

		if (c->response->first == NULL) {
			/* finish writing buffer to client
			 * switch back to reading from client
			 */
			event_del(&(c->ev));
			event_set(&(c->ev), c->cfd, EV_READ | EV_PERSIST, drive_client,
					(void *) c);
			event_add(&(c->ev), 0);
			c->ev_flags = EV_READ;
		}
	}
}

static void server_accept(const int fd, const short which, void*arg) {

	conn *c = NULL;
	int newfd;
	struct sockaddr_in s_in;
	socklen_t len = sizeof(s_in);

	UNUSED(arg);
	UNUSED(which);

	memset((char *) &s_in, 0, len);
	newfd = accept(fd, (struct sockaddr*) &s_in, &len);
	if (newfd < 0) {
		jlog(L_ERR, "accept() failed");
		return;
	}

	if (curconns >= glob_config->maxconns) {
		int wbit = write(newfd, OUTOFCONN, sizeof(OUTOFCONN));
		if (1 || wbit >= 0)// don't care about this
			close(newfd);
		return;
	}
	c = (struct conn*) calloc(sizeof(struct conn), 1);
	if (NULL == c) {
		jlog(L_ERR, "(%s.%d) out of memory for new connection\n", __FILE__,
				__LINE__);
		close(newfd);
		return;
	}
	c->request = list_init();
	c->response = list_init();
	c->content = g_string_new(NULL);
	c->cfd = newfd;
	curconns++;
	jlog(L_DEBUG, " new client FD %d", newfd);
	set_nonblock(c->cfd);
	memset(&(c->ev), 0, sizeof(struct event));
	event_set(&(c->ev), c->cfd, EV_READ | EV_PERSIST, drive_client, (void*) c);
	event_add(&(c->ev), 0);
	c->ev_flags = EV_READ;
	return;
}

int main(int argc, char *argv[]) {
	char c;
	if (argc <= 2) {
		fprintf(stderr, "please usage ./mqagent -c mqagent.conf\n");
		exit(-1);
	}
	while (-1 != (c = getopt(argc, argv, "c:h:"))) {
		switch (c) {
		case 'c':
			config_file = (char *) malloc(strlen(optarg) + 1);
			sprintf(config_file, "%s", optarg);
			break;
		case 'h':
		case '?':
			printf("usage ./lightredis -c lightredis.conf");
			break;
		}
	}
	init_config(config_file);
	log_init(glob_config->logdir,  glob_config->log_level, LOG_PROGRAMME);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGPIPE, SIG_IGN);
	init_backend();
	init_socket();
	if (glob_config->daemon && daemon(0, 0) == -1) {
		fprintf(stderr, "failed to be a daemon\n");
		exit(1);
	}
	event_init();
	if (sockfd > 0) {
		jlog(L_INFO, "listen on port %d", glob_config->port);
		event_set(&ev_master, sockfd, EV_READ | EV_PERSIST, server_accept, NULL);
		event_add(&ev_master, 0);
	}

	event_loop(0);

	config_free();
	return 0;
}
