/*
 * config.h
 *
 *  Created on: 2011-1-5
 *      Author: saint
 */



#ifndef CONFIG_H_
#define CONFIG_H_
#include <stdbool.h>
typedef struct _node
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
	int log_level;

} s_config;


s_config * glob_config ;
void init_config(const char *config_file);
void config_free();

#endif /* CONFIG_H_ */
