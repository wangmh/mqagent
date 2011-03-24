/*
 * glibconf.c
 *
 *  Created on: 2011-1-5
 *      Author: saint
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include "config.h"
#include <error.h>


static GKeyFile *load_config(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;
	keyfile = g_key_file_new();
	g_key_file_set_list_separator(keyfile, ',');
	if (!g_key_file_load_from_file(keyfile, file, 0, &err))
	{
		fprintf(stderr, "Parsing %s failed: %s", file, err->message);
		g_error_free(err);
		g_key_file_free(keyfile);
		return NULL;
	}
	return keyfile;
}

static void init_general_config(GKeyFile *keyfile)
{
	GError *err = NULL;
	glob_config->daemon = g_key_file_get_boolean(keyfile, "General",
			"daemon_mode", &err);
	if (err)
	{
		glob_config->daemon = true;
		g_clear_error(&err);
	}
	glob_config->logdir = g_key_file_get_string(keyfile, "General", "logdir",
			&err);
	if (err)
	{
		glob_config->logdir = "./";
		g_clear_error(&err);
	}
	glob_config->verbose_mode = g_key_file_get_boolean(keyfile, "General",
			"verbose_mode", &err);
	if (err)
	{
		glob_config->verbose_mode = false;
		g_clear_error(&err);
	}
	glob_config->useketama = g_key_file_get_boolean(keyfile, "General",
			"useketama", &err);
	if (err)
	{
		glob_config->useketama = false;
		g_clear_error(&err);
	}
	glob_config->port
			= g_key_file_get_integer(keyfile, "General", "port", &err);
	if (err)
	{
		glob_config->port = 11215;
		g_clear_error(&err);
	}
	glob_config->useketama = g_key_file_get_boolean(keyfile, "General",
			"useketama", &err);
	if (err)
	{
		glob_config->useketama = true;
		g_clear_error(&err);
	}
	glob_config->maxidle = g_key_file_get_integer(keyfile, "General",
			"maxidle", &err);
	if (err)
	{
		glob_config->maxidle = 20;
		g_clear_error(&err);
	}
	glob_config->maxconns = g_key_file_get_integer(keyfile, "General",
			"maxconns", &err);
	if (err)
	{
		glob_config->maxconns = 4096;
		g_clear_error(&err);
	}
	glob_config->host_ip = g_key_file_get_string(keyfile, "General",
			"host_ip", &err);
	if (err)
	{
		glob_config->host_ip = NULL;
		g_clear_error(&err);
	}



}

static void init_tasks_config(GKeyFile * keyfile)
{
	char **tasks;
	GError *err = NULL;
	gsize task_length;
	char **node;
	gsize node_length;
	tasks = g_key_file_get_keys(keyfile, "tasks", &task_length, &err);
	if (err)
	{
		printf("%s", err->message);
		g_clear_error(&err);
		exit(-1);
	}
	glob_config->task_group_size = task_length;
	glob_config->task_group = calloc(sizeof(s_task_group *), task_length);
	if (NULL == glob_config->task_group)
	{
		fprintf(stderr, "calloc task_group failed\n");
		exit(-1);
	}
	int i, j;
	char *p;
	for (i = 0; i < task_length; i++)
	{
		glob_config->task_group[i] = calloc(sizeof(s_task_group), 1);
		glob_config->task_group[i]->task_name = strdup(tasks[i]);
		//printf("task is %s\n", glob_config->task_group[i]->task_name);
		node = g_key_file_get_string_list(keyfile, "tasks", tasks[i],
				&node_length, &err);
		glob_config->task_group[i]->nodes
				= calloc(sizeof(s_node*), node_length);
		if (glob_config->task_group[i]->nodes == NULL)
		{
			fprintf(stderr, "calloc task_group failed\n");
			exit(-1);
		}
		glob_config->task_group[i]->nodes_size = node_length;
		for (j = 0; j < node_length; j++)
		{
			glob_config->task_group[i]->nodes[j] = calloc(sizeof(s_node), 1);
			p = strchr(node[j], '/');
			if (NULL == p)
			{
				glob_config->task_group[i]->nodes[j]->master = strdup(node[j]);
			}
			else
			{
				p[0] = '\0';
				glob_config->task_group[i]->nodes[j]->master = strdup(node[j]);
				p++;
				glob_config->task_group[i]->nodes[j]->slave = strdup(p);
				p--;
				p[0] = '/';
			}


		}
		g_strfreev(node);
	}

	g_strfreev(tasks);

}

void init_config(const char *config_file)
{
	GKeyFile *keyfile;
	keyfile = load_config(config_file);
	glob_config = calloc(sizeof(s_config), 1);
	if (NULL == glob_config)
	{
		fprintf(stderr, "calloc glob_config failed\n");
		exit(-1);
	}
	init_tasks_config(keyfile);
	init_general_config(keyfile);

}

void config_free()
{
	int i, j;
	for (i = 0; i < glob_config->task_group_size; i++)
	{
		for (j = 0; j < glob_config->task_group[i]->nodes_size; j++)
		{
			free(glob_config->task_group[i]->nodes[j]->master);
			free(glob_config->task_group[i]->nodes[j]->slave);
		}
		free(glob_config->task_group[i]->task_name);
		free(glob_config->task_group[i]->nodes);
		free(glob_config->task_group[i]);
	}
	free(glob_config->task_group);
	free(glob_config->logdir);
	free(glob_config);

}
