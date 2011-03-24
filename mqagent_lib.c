/*
 * mqagent_lib.c
 *
 *  Created on: 2011-1-6
 *      Author: saint
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <glib.h>
#include <unistd.h>
#include "config.h"
#include "mqagent.h"
#include <event.h>
#include "mqagent_lib.h"

void copy_list(list *src, list *dst) {
	buffer *b, *r;
	int size = 0;

	if (src == NULL || dst == NULL || src->first == NULL)
		return;

	b = src->first;
	while (b) {
		size += b->size;
		b = b->next;
	}

	if (size == 0)
		return;

	r = buffer_init_size(size + 1);
	if (r == NULL)
		return;

	b = src->first;
	while (b) {
		if (b->size > 0) {
			memcpy(r->ptr + r->size, b->ptr, b->size);
			r->size += b->size;
		}
		b = b->next;
	}
	append_buffer_to_list(dst, r);
}

/* the famous DJB hash function for strings from stat_cache.c*/
int hashme(char *str) {
	unsigned int hash = 5381;
	const char *s;

	if (str == NULL)
		return 0;

	for (s = str; *s; s++) {
		hash = ((hash << 5) + hash) + *s;
	}
	hash &= 0x7FFFFFFF; /* strip the highest bit */
	return hash;
}

void remove_finished_buffers(list *l) {
	buffer *n, *b;

	if (l == NULL)
		return;
	b = l->first;
	while (b) {
		if (b->used < b->size) /* incompleted buffer */
			break;
		n = b->next;
		buffer_free(b);
		b = n;
	}

	if (b == NULL) {
		l->first = l->last = NULL;
	} else {
		l->first = b;
	}
}
/* ------------- from lighttpd's network_writev.c ------------ */

#ifndef UIO_MAXIOV
# if defined(__FreeBSD__) || defined(__APPLE__) || defined(__NetBSD__)
/* FreeBSD 4.7 defines it in sys/uio.h only if _KERNEL is specified */
#  define UIO_MAXIOV 1024
# elif defined(__sgi)
/* IRIX 6.5 has sysconf(_SC_IOV_MAX) which might return 512 or bigger */
#  define UIO_MAXIOV 512
# elif defined(__sun)
/* Solaris (and SunOS?) defines IOV_MAX instead */
#  ifndef IOV_MAX
#   define UIO_MAXIOV 16
#  else
#   define UIO_MAXIOV IOV_MAX
#  endif
# elif defined(IOV_MAX)
#  define UIO_MAXIOV IOV_MAX
# else
#  error UIO_MAXIOV nor IOV_MAX are defined
# endif
#endif

/* return 0 if success */
int writev_list(int fd, list *l) {
	size_t num_chunks, i, num_bytes = 0, toSend, r, r2;
	struct iovec chunks[UIO_MAXIOV];
	buffer *b;

	if (l == NULL || l->first == NULL || fd <= 0)
		return 0;

	for (num_chunks = 0, b = l->first; b && num_chunks < UIO_MAXIOV; num_chunks++, b
			= b->next)
		;

	for (i = 0, b = l->first; i < num_chunks; b = b->next, i++) {
		if (b->size == 0) {
			num_chunks--;
			i--;
		} else {
			chunks[i].iov_base = b->ptr + b->used;
			toSend = b->size - b->used;

			/* protect the return value of writev() */
			if (toSend > SSIZE_MAX || (num_bytes + toSend) > SSIZE_MAX) {
				chunks[i].iov_len = SSIZE_MAX - num_bytes;

				num_chunks = i + 1;
				break;
			} else {
				chunks[i].iov_len = toSend;
			}

			num_bytes += toSend;
		}
	}

	if ((r = writev(fd, chunks, num_chunks)) < 0) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			return 0; /* try again */
			break;
		case EPIPE:
		case ECONNRESET:
			return -2; /* connection closed */
			break;
		default:
			return -1; /* error */
			break;
		}
	}

	r2 = r;

	for (i = 0, b = l->first; i < num_chunks; b = b->next, i++) {
		if (r >= (ssize_t) chunks[i].iov_len) {
			r -= chunks[i].iov_len;
			b->used += chunks[i].iov_len;
		} else {
			/* partially written */
			b->used += r;
			break;
		}
	}

	remove_finished_buffers(l);
	return r2;
}

size_t tokenize_command(char *command, token_t *tokens, const size_t max_tokens) {
	char *s, *e;
	size_t ntokens = 0;

	if (command == NULL || tokens == NULL || max_tokens < 1)
		return 0;

	for (s = e = command; ntokens < max_tokens - 1; ++e) {
		if (*e == ' ') {
			if (s != e) {
				tokens[ntokens].value = s;
				tokens[ntokens].length = e - s;
				ntokens++;
				*e = '\0';
			}
			s = e + 1;
		} else if (*e == '\0') {
			if (s != e) {
				tokens[ntokens].value = s;
				tokens[ntokens].length = e - s;
				ntokens++;
			}

			break; /* string end */
		}
	}

	/*
	 * If we scanned the whole string, the terminal value pointer is null,
	 * otherwise it is the first unprocessed character.
	 */
	tokens[ntokens].value = *e == '\0' ? NULL : e;
	tokens[ntokens].length = 0;
	ntokens++;

	return ntokens;
}

list * list_init(void) {
	list *l;

	l = (struct list *) calloc(sizeof(struct list), 1);
	return l;
}


void buffer_free(buffer *b) {
	if (!b)
		return;

	free(b->ptr);
	free(b);
}

buffer * buffer_init_size(int size) {
	buffer *b;

	if (size <= 0)
		return NULL;
	b = (struct buffer *) calloc(sizeof(struct buffer), 1);
	if (b == NULL)
		return NULL;

	size += BUFFER_PIECE_SIZE - (size % BUFFER_PIECE_SIZE);

	b->ptr = (char *) calloc(1, size);
	if (b->ptr == NULL) {
		free(b);
		return NULL;
	}

	b->len = size;
	return b;
}

void server_free(struct server *s) {
	if (s == NULL)
		return;

	if (s->sfd > 0) {
		event_del(&(s->ev));
		close(s->sfd);
	}

	list_free(s->request, 0);
	list_free(s->response, 0);
	free(s);
}

void list_free(list *l, int keep_list) {
	buffer *b, *n;

	if (l == NULL)
		return;

	b = l->first;
	while (b) {
		n = b->next;
		buffer_free(b);
		b = n;
	}

	if (keep_list)
		l->first = l->last = NULL;
	else
		free(l);
}
void move_list(list *src, list *dst) {
	if (src == NULL || dst == NULL || src->first == NULL)
		return;

	if (dst->first == NULL)
		dst->first = src->first;
	else
		dst->last->next = src->first;

	dst->last = src->last;

	src->last = src->first = NULL;
}

void append_buffer_to_list(list *l, buffer *b) {
	if (l == NULL || b == NULL)
		return;

	if (l->first == NULL) {
		l->first = l->last = b;
	} else {
		l->last->next = b;
		l->last = b;
	}
}

void conn_close(conn *c) {
	int i;

	if (c == NULL)
		return;

	/* check client connection */
	if (c->cfd > 0) {
		event_del(&(c->ev));
		close(c->cfd);
		curconns--;
		c->cfd = 0;
	}

	server_free(c->srv);
	g_string_free(c->content, TRUE);
	if (c->keys) {
		for (i = 0; i < c->keycount; i++)
			free(c->keys[i]);
		free(c->keys);
		c->keys = NULL;
	}

	list_free(c->request, 0);
	list_free(c->response, 0);
	free(c);
}

int memstr(char *s, char *find, int srclen, int findlen) {
	char *bp, *sp;
	int len = 0, success = 0;

	if (findlen == 0 || srclen < findlen)
		return -1;
	for (len = 0; len <= (srclen - findlen); len++) {
		if (s[len] == find[0]) {
			bp = s + len;
			sp = find;
			do {
				if (!*sp) {
					success = 1;
					break;
				}
			} while (*bp++ == *sp++);
			if (success)
				break;
		}
	}

	if (success)
		return len;
	else
		return -1;
}

