/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <getopt.h>
#include <pthread.h>

#include "cynara.h"
#include "proxy.h"

#define ENABLE_CYNARA

#ifdef ENABLE_CYNARA
#include <cynara-client-async.h>
#include <cynara-session.h>
#endif

struct BusCynara {
        int ref_count;

        char *session_id;

        pthread_mutex_t lock;
#ifdef ENABLE_CYNARA
        cynara_async *cynara;
#endif
        int fd;
        int block_fd;
        int wakeup_fd;
        int events;
        pid_t pid;
};

struct PolicyDeferredMessageId {
#ifdef ENABLE_CYNARA
        cynara_check_id p_check_id;
#endif
};
#ifdef ENABLE_CYNARA
static void status_callback(int old_fd,
                            int new_fd,
                            cynara_async_status status,
                            void *user_status_data);

static void bus_cynara_check_response_callback (cynara_check_id check_id,
                                                cynara_async_call_cause cause,
                                                int response,
                                                void *user_response_data);
static void cynara_wakeup(BusCynara *cynara) {
        char dummy_byte;
        int r;

        assert(cynara);        

        r = write(cynara->wakeup_fd, &dummy_byte, 1);
        if (r < 0)
                log_debug("Cynara: cannot wakeup cynara- write error: %d",r);
        log_debug("Cynara: wakeup");
}
#endif
static BusCynara* cynara_bus_acquire(BusCynara *cynara) {
        int r;
        r = pthread_mutex_lock(&cynara->lock);
        assert(!r);
        return cynara;        
}

static void cynara_bus_release(BusCynara *cynara) {
        int r;
        r = pthread_mutex_unlock(&cynara->lock);
        assert(!r);
}

PolicyMessageCheckHistory* cynara_deferred_check_history_acquire(PolicyMessageCheckHistory *d, bool only_for_read) {
        int r;
        
        if (only_for_read) 
                r = pthread_rwlock_rdlock(&d->history_lock); 
        else
                r = pthread_rwlock_wrlock(&d->history_lock);
        log_debug("Cynara: deferred list lock (%p), read_only=%u, result=%d", d, only_for_read, r);
        assert(!r);  
        return d;        
}

void cynara_deferred_check_history_release(PolicyMessageCheckHistory *d) {
        int r;

        log_debug("Cynara: deferred list unlock (%p), result=%d", d, r);
        r = pthread_rwlock_unlock(&d->history_lock);
        assert(!r);
}

int cynara_deferred_message_new(PolicyDeferredMessage **d, PolicyCheckResult result) {
        PolicyDeferredMessage *dm;

        dm = new0(PolicyDeferredMessage, 1);

        if (!dm)
                return log_oom();
        
        dm->id = new0(PolicyDeferredMessageId,1);        
        if (!(dm->id)) {
                free(dm);
                return log_oom();
        }
        
        dm->result = result;
        *d = dm;
        return 1;
}

int cynara_deferred_message_new_append(PolicyDeferredMessage **d,
                                PolicyCheckResult result,
                                PolicyDeferredMessage **list) {
        PolicyDeferredMessage *dm;
        int r;

        dm = NULL;
        r = cynara_deferred_message_new(&dm, result); 

        if (r <= 0) 
                return r;
        
        LIST_APPEND(items, *list, dm);

        return 1;
}

PolicyDeferredMessage* cynara_deferred_message_append(PolicyDeferredMessage *d,PolicyDeferredMessage *a) {
        assert(a);

        if (d == NULL)
                return a;

        LIST_INSERT_AFTER(items, d, d, a);
        return a;
}

PolicyDeferredMessage* cynara_deferred_message_free(PolicyDeferredMessage *d) {
        if (d == NULL)
                return NULL;
        log_debug("Cynara: free deferred message (%s, %lu, %s)", d->label, (long unsigned int)d->uid, d->privilege);

        free(d->name);
        free(d->interface);
        free(d->path);
        free(d->member);
        free(d->label);
        free(d->privilege);
        if (d->mutex) {
                pthread_mutex_destroy(d->mutex);
                pthread_cond_destroy(d->condition);
                free(d->mutex);
                free(d->condition);
        }
        free(d->id);
        free(d);
        return NULL;
}

void cynara_deferred_message_list_free(PolicyDeferredMessage *d) {
        PolicyDeferredMessage *i;

        while ((i = d)) {
                LIST_REMOVE(items, d, i);
                cynara_deferred_message_free(i);
        }
}

int cynara_message_check_history_new(PolicyMessageCheckHistory  **d, sd_bus_message *message, PolicyCheckResult result, PolicyDeferredMessage *history) {
        int r;
        PolicyMessageCheckHistory *dh;

        assert(d);
        dh = new0(PolicyMessageCheckHistory, 1);
        if (!dh) 
                return log_oom();
        


        r = pthread_rwlock_init(&dh->history_lock, NULL);
        if (r < 0) {
                log_error_errno(r, "Cannot initialize deferred message history rwlock: %m");
                free(dh); 
                return r;
        }

        if (message)
                dh->message = sd_bus_message_ref(message);   

        dh->history = history;
        dh->result = result; 
        *d = dh;
        return 1;
}

PolicyMessageCheckHistory* cynara_message_check_history_free(PolicyMessageCheckHistory *dh, BusCynara *cynara) {
        PolicyDeferredMessage *i;

        if (!dh)
                return NULL;
        
        while ((i = dh->history)) {
                if (i->result == POLICY_RESULT_LATER) {
#ifdef ENABLE_CYNARA
                        cynara = cynara_bus_acquire(cynara);
                        if (i->result == POLICY_RESULT_LATER) {
                                cynara_async_cancel_request(cynara->cynara, i->id->p_check_id);
                                cynara_wakeup(cynara);
                        }
                        //here wlocks is not necessary.
                        //reason: cynara mutex guards against using freed structure 
                        LIST_REMOVE(items, dh->history, i);
                        cynara_deferred_message_free(i);
                        cynara_bus_release(cynara);
#endif
                } else {
                        LIST_REMOVE(items, dh->history, i);
                        cynara_deferred_message_free(i);
                } 
        }
        
        sd_bus_message_unref(dh->message);
        pthread_rwlock_destroy(&dh->history_lock);
        free(dh);
        return NULL;
}

static const char* cynara_bus_get_session_id(BusCynara *bus_cynara) {
        if (!bus_cynara->session_id)
                bus_cynara->session_id = cynara_session_from_pid(bus_cynara->pid);
        return bus_cynara->session_id;
}

static int cynara_check_request_generate_internal(BusCynara *cynara, int wakeup_fd, PolicyDeferredMessage *deferred_message, sd_bus_message *message, PolicyMessageCheckHistory **out, bool replace) {
#ifndef ENABLE_CYNARA
        return 1;
#else
        PolicyDeferredMessage *i;
        PolicyMessageCheckHistory *dh = NULL;
        int r;
        int requested_count = 0;
        bool is_repeat_policy= false;
        char user[32];
        const char *session_id;

        assert(out);
        assert(cynara);

        cynara_bus_acquire(cynara);
        session_id = cynara_bus_get_session_id(cynara);
        if (replace && *out) {
                /** preparing replace + clear old history*/
                dh = *out;
                if (dh->history) {
                        wakeup_fd = dh->history->wakeup_fd;
                        while ((i = dh->history)) {
                                if (i->result == POLICY_RESULT_LATER) { 
                                        cynara_async_cancel_request(cynara->cynara, i->id->p_check_id);
                                        cynara_wakeup(cynara);
                                }
                        
                                LIST_REMOVE(items, dh->history, i);
                                cynara_deferred_message_free(i);
                        }
                }
        } else {
                r = cynara_message_check_history_new(&dh, message, POLICY_RESULT_LATER, deferred_message);
                if (r < 0) {
                        log_error("Cynara: cannot create check history structure (%d).", r);
                        return r;
                }
        }

        /* generating new cynara requests and update wakeup_fd*/
	LIST_FOREACH(items, i, deferred_message) {
		i->wakeup_fd = wakeup_fd;
                i->guard = dh;
                if (!is_repeat_policy && i->is_repeat_policy_check_needed)
                        is_repeat_policy = true;

                snprintf(user, sizeof(user), "%lu", (long unsigned int)i->uid);
                r = cynara_async_create_request(cynara->cynara, i->label, session_id, user, i->privilege, &((i->id)->p_check_id), bus_cynara_check_response_callback, i);
                if (r != CYNARA_API_SUCCESS) {
                        log_error("Cynara request error: %d (label=%s,session=%s,uwer=%s,privilege=%s).", r, i->label, session_id, user, i->privilege);
                        r = -EAGAIN;
                        cynara_bus_release(cynara);
                        return r;
                }
                cynara_wakeup(cynara);
                log_debug("Cynara: created request (%s:%s:%s:%s).", i->label, session_id, user, i->privilege);
                requested_count++;
	}
        cynara_bus_release(cynara);

        if (replace && dh) {
                dh->history = deferred_message;
                dh->result = POLICY_RESULT_LATER;
                dh->is_repeat_policy_check_needed = is_repeat_policy;
        } else {
                
                dh->is_repeat_policy_check_needed = is_repeat_policy;
                *out = dh;
                dh = NULL;
        }
        
        return 1;
#endif
}



int cynara_message_check_history_replace(PolicyMessageCheckHistory *dh, PolicyDeferredMessage *history, BusCynara* cynara) {
        int r;
        r = cynara_check_request_generate_internal(cynara, 0, history, NULL, &dh, true);
        return r;
}

int bus_cynara_new(BusCynara **bus_cynara) {
        int r;
        int fds[2];
        BusCynara *cynara;
        
        cynara = new0(BusCynara, 1);
        if (!cynara)
                return log_oom(); 

        cynara->fd = -1;
        cynara->events = POLLIN|POLLOUT;

#ifdef ENABLE_CYNARA
        r = pipe(fds);
        if (r < 0){
                bus_cynara_free(cynara);
                return r;
        }
        cynara->wakeup_fd = fds[1];
        cynara->block_fd = fds[0];

        r = fd_nonblock(cynara->wakeup_fd, true);
        if (r < 0) {
                
                bus_cynara_free(cynara);
                return r;
        }

        r = fd_nonblock(cynara->block_fd, true);
        if (r < 0) {
                bus_cynara_free(cynara);
                return r;
        }

        log_debug("Cynara connecting to cynara daemon");
        r = cynara_async_initialize(&(cynara->cynara), NULL, &status_callback, cynara);
        if (r != CYNARA_API_SUCCESS) {
                bus_cynara_free(cynara);
                log_error("Cannot connect to cynara daemon");
                return -EAGAIN;
        }         
        
#endif

        cynara->pid = getpid();
        cynara->ref_count = 1;
        *bus_cynara = cynara;
        return 1;
}

BusCynara* bus_cynara_free(BusCynara *bus_cynara) {        
        if (!bus_cynara)
                return NULL;
     
#ifdef ENABLE_CYNARA           
        close(bus_cynara->wakeup_fd);
        close(bus_cynara->block_fd);
        if (bus_cynara->cynara)
                cynara_async_finish(bus_cynara->cynara);
#endif
        free(bus_cynara->session_id);
        pthread_mutex_destroy(&(bus_cynara->lock));
        free(bus_cynara);
        return NULL;
}


BusCynara* cynara_bus_unref(BusCynara *cynara) {
        BusCynara* c;
        if (!cynara)
                return NULL;
        
        c = cynara_bus_acquire(cynara);
        assert(c->ref_count > 0);
        --(c->ref_count);
        if (c->ref_count > 0) {
                cynara_bus_release(c);
                return NULL;
        }
        cynara_bus_release(c);
        bus_cynara_free(c);
        return NULL;
}

BusCynara* cynara_bus_ref(BusCynara* c) {
        cynara_bus_acquire(c);
        c->ref_count++;
        cynara_bus_release(c);
        return c;
}

int cynara_bus_get_fd(BusCynara *cynara) {
        int fd;
        cynara_bus_acquire(cynara);
        fd = cynara->fd;
        cynara_bus_release(cynara);
        return fd;
}

int cynara_bus_get_events(BusCynara *cynara) {
        int events;
        cynara_bus_acquire(cynara);
        events = cynara->events;
        cynara_bus_release(cynara);
        return events;
}

int cynara_bus_get_block_fd(BusCynara *cynara) {
        int fd;
        cynara_bus_acquire(cynara);
        fd = cynara->block_fd;
        cynara_bus_release(cynara);
        return fd;
}



static void cynara_fill_deferred_message(PolicyDeferredMessage* dm,
                                PolicyItem *item, 
                                const PolicyCheckFilter *filter) {
        assert(dm);
        assert(item);
        assert(filter);

        dm->uid = filter->uid;
        dm->gid = filter->gid;
        dm->class = item->class;
        dm->message_type = item->message_type;

        free(dm->label);
        if (!(filter->label))
                dm->label = strdup("");
        else
                dm->label = strdup(filter->label);


        free(dm->privilege);
        if (!(item->privilege))
                dm->privilege = strdup("");
        else
                dm->privilege = strdup(item->privilege);

        free(dm->name);
        if (!(filter->name))
                dm->name = strdup("");
        else
                dm->name = strdup(filter->name);

        free(dm->interface);
        if (!(filter->interface))
                dm->interface = strdup("");
        else
                dm->interface = strdup(filter->interface);

        free(dm->path);
        if (!(filter->path))
                dm->path = strdup("");
        else
                dm->path = strdup(filter->path);

        free(dm->member);
        if (!(filter->member))
                dm->member = strdup("");
        else
                dm->member = strdup(filter->member);
}

CynaraPolicyResult cynara_check_privilege(BusCynara *cynara, 
                                PolicyItem *item, 
                                const PolicyCheckFilter *filter, 
                                PolicyDeferredMessage **deferred_message) {
#ifdef ENABLE_CYNARA
        PolicyDeferredMessage *dm = NULL;
        char user[32];
        const char *session_id;
        int r;

        cynara_bus_acquire(cynara);
        session_id = cynara_bus_get_session_id(cynara);
        snprintf(user, sizeof(user), "%lu", (long unsigned int)filter->uid);
        r = cynara_async_check_cache(cynara->cynara, filter->label, session_id, user, item->privilege);
        cynara_bus_release(cynara);

        switch (r) {
        case CYNARA_API_ACCESS_ALLOWED:
                log_debug("Cynara: rule exists in cache (%s:%s:%s:%s). ALLOWED", filter->label, session_id, user, item->privilege);
                return CYNARA_RESULT_ALLOW;
        break;
        case  CYNARA_API_CACHE_MISS:
                log_debug("Cynara: rule does not exist in cache (%s:%s:%s:%s). Preparing deferred message.", filter->label, session_id, user, item->privilege);
                if (*deferred_message) {
                        //replace data
                        cynara_fill_deferred_message(*deferred_message, item, filter);
                } else {
                        //create new data
                        r = cynara_deferred_message_new(&dm,POLICY_RESULT_LATER);
                        if (r < 0) {
                                log_error("Cynara: cannot create deferred message");
                                return CYNARA_RESULT_ERROR;
                        }
                        cynara_fill_deferred_message(dm, item, filter);
                        *deferred_message = dm;
                }
                return POLICY_RESULT_LATER;
        break;
        }
        log_debug("Cynara: rule exists in cache (%s:%s:%s:%s). DENY", filter->label, session_id, user, item->privilege);
        return CYNARA_RESULT_DENY;
#else
        return CYNARA_RESULT_ALLOW;
#endif
}

int cynara_check_request_generate(BusCynara *cynara, int wakeup_fd, PolicyDeferredMessage *deferred_message, sd_bus_message *message, PolicyMessageCheckHistory **out) {
        int r;
        r = cynara_check_request_generate_internal(cynara, wakeup_fd, deferred_message, message, out, false);
        if (r < 0)
                cynara_message_check_history_free(*out, cynara);
        return r;
}
#ifdef ENABLE_CYNARA
static void status_callback(int old_fd,
                            int new_fd,
                            cynara_async_status status,
                            void *user_status_data) {
        BusCynara *cynara;

        cynara = user_status_data;
        log_debug("Cynara status callback: %d %d %d", old_fd, new_fd, (int)status);
        if (new_fd != -1 && new_fd!=old_fd) {
                log_debug("Cynara new fd: %u", new_fd);
                cynara->fd = new_fd;        
                switch (status) {
                case CYNARA_STATUS_FOR_READ:
                        cynara->events = POLLIN;
                break;
                case CYNARA_STATUS_FOR_RW:
                        cynara->events = POLLIN|POLLOUT; 
                break;
                default:
                        log_debug("Cynara passed unknown status value: 0x%08X\n", (unsigned int)status); 
                }
        }

        return;
}
#endif
PolicyCheckResult cynara_wait_for_answer(PolicyDeferredMessage *message) {
        int r;
#ifdef ENABLE_CYNARA
        return POLICY_RESULT_ALLOW;
#endif
        cynara_deferred_check_history_acquire(message->guard, false);
        if (message->result != POLICY_RESULT_LATER) {
                cynara_deferred_check_history_release(message->guard);
                return message->result;
        } else {
                message->mutex = new0(pthread_mutex_t, 1);
                if (!(message->mutex)) {
                        cynara_deferred_check_history_release(message->guard);
                        log_oom();
                        return POLICY_RESULT_DENY;
                }

                message->condition = new0(pthread_cond_t, 1);
                if (!(message->condition)) {
                        cynara_deferred_check_history_release(message->guard);
                        log_oom();
                        return POLICY_RESULT_LATER;
                }

                r = pthread_mutex_init(message->mutex, NULL);
                assert(!r);

                r = pthread_cond_init(message->condition, NULL);
                assert(!r);
        }

        cynara_deferred_check_history_release(message->guard);
        pthread_mutex_lock(message->mutex);
        if (message->result != POLICY_RESULT_LATER)
                goto finish;
        log_debug("Cynara: client waits(blocked) for answer: check_id=%u, request=(%s, %lu, %s)",
        (unsigned int)message->id->p_check_id, message->label, (long unsigned int)message->uid, message->privilege);

        pthread_cond_wait(message->condition, message->mutex);
        
finish:
        log_debug("Cynara: client gets(unblocked) answer: check_id=%u, request=(%s, %lu, %s)",
        (unsigned int)message->id->p_check_id, message->label, (long unsigned int)message->uid, message->privilege);

        pthread_mutex_unlock(message->mutex);
        return message->result;
}

int cynara_run_process(BusCynara *cynara) {
        int r;
#ifdef ENABLE_CYNARA
        cynara_bus_acquire(cynara);
        r = cynara_async_process(cynara->cynara); 
        cynara_bus_release(cynara);
        
        if (r != CYNARA_API_SUCCESS) {
                log_error("Cynara async process error: %u", r);
                return -EAGAIN;
        }
#endif
        return 0;
}
#ifdef ENABLE_CYNARA
static void cynara_response_received(PolicyCheckResult result, PolicyDeferredMessage *deferred_message) {
        char dummy_byte;
        int r;        
        cynara_deferred_check_history_acquire(deferred_message->guard, false);
        deferred_message->result = result;
        if (deferred_message->mutex) { 
                //wakeup blocked thread by signaling
                log_debug("Cynara received message- wakeup client thread by mutex: check_id=%u, request=(%s, %lu, %s)",
                (unsigned int)deferred_message->id->p_check_id, deferred_message->label, (long unsigned int)deferred_message->uid, deferred_message->privilege);
                pthread_mutex_lock(deferred_message->mutex);
                pthread_cond_broadcast(deferred_message->condition);
                pthread_mutex_unlock(deferred_message->mutex);
        } else if (deferred_message->wakeup_fd != -1) {
                //wakeup blocked thread on ppoll
                log_debug("Cynara received message- wakeup client thread by pipe: check_id=%u, request=(%s, %lu, %s)",
                (unsigned int)deferred_message->id->p_check_id, deferred_message->label, (long unsigned int)deferred_message->uid, deferred_message->privilege);
                r = write(deferred_message->wakeup_fd, &dummy_byte, 1);
                log_debug("cynara rest value: %d %d",r, deferred_message->wakeup_fd);  
                assert(r >= 0);
        }
        cynara_deferred_check_history_release(deferred_message->guard);
}

static void bus_cynara_check_response_callback (cynara_check_id check_id,
                                                cynara_async_call_cause cause,
                                                int response,
                                                void *user_response_data) {
        PolicyDeferredMessage *deferred_message = user_response_data;
        PolicyCheckResult result;

        log_debug("Cynara callback: check_id=%u, cause=%d response=%i response_data=%p",
                (unsigned int)check_id, (int)cause, response, user_response_data);

        if (deferred_message == NULL)
                return;

        if (cause == CYNARA_CALL_CAUSE_ANSWER && response == CYNARA_API_ACCESS_ALLOWED) {
                result = POLICY_RESULT_ALLOW;
        } else if (cause == CYNARA_CALL_CAUSE_ANSWER) {
                result = POLICY_RESULT_DENY;
        }

        cynara_response_received(result, deferred_message);
}
#endif
