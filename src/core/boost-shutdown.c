/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include "list.h"
#include "fileio.h"
#include "special.h"
#include "manager.h"
#include "strv.h"
#include "boost-shutdown.h"

//LIST_HEAD(struct QuickCmd, cmd_queue);

#define EXEC_START "ExecStart="
#define MAX_THREADS 32

static int process_dir(const char *unit_path, const char *name, const char* suffix, char** path)
{
    assert (path);

    *path = strjoin(unit_path, "/", name, suffix, NULL);
    if (!path) {
        log_warning("Error: cannot find the shutdown.boost in %s", *path);
        return -1;
    }

    return access(*path, F_OK);
}

static char* fetch_quick_shutdown_path(Manager* m)
{
    char *path, **p;
    int r;

    assert(m != NULL);

    STRV_FOREACH(p, m->lookup_paths.unit_path) {
        r = process_dir(*p, SPECIAL_SHUTDOWN_TARGET, ".wants/shutdown.boost", &path);
        if (r == 0) {
            log_warning("Find the config file: %s", path);
            break;
        }
    }

    if (r != 0) {
        path = NULL;
    }

    return path;
}

static int run_cmd(void* arg)
{
    char* cmd = NULL;

    assert(arg != NULL);

    cmd = (char*)arg;
    
    return system(cmd);
}

static int parse_line(char* l, char** rval)
{
	int n = strlen(EXEC_START);
        char* p = NULL;

	assert(l);

        //TODO: check the start suffix of "ExecStart=";
       
	if ((p=strstr(l, EXEC_START)) == NULL) {
		log_warning("Invalid command line, ignore it.");
		return -1;
        }

	*rval = p+n;

	return 0;
}

static int parse_context(char* context, Manager* m)
{
    char *line, *rval = NULL;
    char* p, *s;
    int len = 0;
    struct QuickCmd *qc = NULL;
	
    s = p = context;
    while(*p != '\0') {
        while (*p != '\n') {
            p++;
        }
	len = p - s + 1;
                
        if (len != 0) {
            line = (char*)malloc(sizeof(char)*(len+1));
            assert(line);

            strncpy(line, s, len);
            line[len] = '\0';

            if (parse_line(line, &rval) == 0) {                   
                qc = (struct QuickCmd*)malloc(sizeof(struct QuickCmd));
                assert(qc);

                qc->exec_cmd = rval;
                LIST_PREPEND(struct QuickCmd, cmd_list, m->cmd_queue, qc);
            }
        }
            
	p++;
        s = p;
		
    }

        /*
        //Check the prepend result;
        LIST_FOREACH(cmd_list, qc, m->cmd_queue) {
            log_warning("%s", qc->exec_cmd);
        }
        */
    return 0;
}

static int parse_quickshutdown_file(const char* fn, Manager* m)
{
    char* context;

    if (read_full_file(fn, &context, NULL) < 0) {
        return -1;
    }

    parse_context(context, m);

    free(context);
    context = NULL;

    return 0;
}

static void clear_cmd_queue(Manager* m)
{
    struct QuickCmd* ptr = NULL;
    
    while ((ptr = m->cmd_queue)) {
        if (ptr->exec_cmd != NULL) {
            free(ptr->exec_cmd);
        }

        LIST_REMOVE(struct QuickCmd, cmd_list, m->cmd_queue, ptr);
        free(ptr);
    }

    return;
}

int manager_load_boost_file(Manager* m)
{
    int r;
    char* full_name = NULL;

    assert(m);

    full_name = fetch_quick_shutdown_path(m);

    assert (full_name);

    r = parse_quickshutdown_file(full_name, m);

    if (full_name != NULL) free(full_name);

    return r;
}

//Run the cmds inside cmd_list in multithreads.
int manager_run_boost_cmds(Manager* m)
{
    struct QuickCmd* ptr = NULL;
    char* cmd_str = NULL;
    pid_t child, wpids[MAX_THREADS];
    int status = 0, i = -1;   

    assert(m != NULL);

    //For each cmd in cmd_queue, create a thread to run it.
    for (ptr = m->cmd_queue; ptr != NULL; ptr = ptr->cmd_list_next) {
        i++;
        cmd_str = ptr->exec_cmd;

        //if (system(cmd_str) != 0) {
        //    log_warning("Error in running cmd %s", cmd_str);
        //}

        //Fork
        child = fork();
        if (child == -1) {
            log_warning("Failed to create child process to run cmds.");
            return -1;
        }

        if (child == 0) {
            //one child, run the cmd;
            run_cmd((void*)cmd_str);
            exit(0);
        } else {
            wpids[i] = child;
        }
    }

    log_warning("%d threads to run cmds for quick shutdown", i+1);
    
    //Wait for all threads completion.
    while (i >= 0) {
        waitpid(wpids[i], &status, 0);
        i--;
    }

    //clear_cmd_queue(m);

    //log_warning("Complete quick shutdown cmds %s %d", __FILE__, __LINE__);

    return 0;	
}
