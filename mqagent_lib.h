/*
 * mqagent_lib.h
 *
 *  Created on: 2011-1-6
 *      Author: saint
 */

#ifndef MQAGENT_LIB_H_
#define MQAGENT_LIB_H_
extern int curconns;
int hashme(char *str);
void append_buffer_to_list(list *l, buffer *b);
list * list_init(void);
void list_free(list *l, int keep_list);
void buffer_free(buffer *b);
void server_free(struct server *s);

void  copy_list(list *src, list *dst);

buffer * buffer_init_size(int size);
void conn_close(conn *c);
size_t tokenize_command(char *command, token_t *tokens, const size_t max_tokens);

int writev_list(int fd, list *l);
void  move_list(list *src, list *dst);
int memstr(char *s, char *find, int srclen, int findlen);
void  remove_finished_buffers(list *l);
#endif /* MQAGENT_LIB_H_ */
