/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include "policy.h"
#include "bus-message.h"


typedef struct PolicyDeferredMessage PolicyDeferredMessage;
typedef struct PolicyMessageCheckHistory PolicyMessageCheckHistory; 
typedef struct ProxyContext ProxyContext;
typedef struct PolicyDeferredMessageId PolicyDeferredMessageId;  

typedef enum CynaraPolicyResult {
        CYNARA_RESULT_ALLOW,
        CYNARA_RESULT_DENY,
        CYNARA_RESULT_LATER,
        CYNARA_RESULT_ERROR,
} CynaraPolicyResult;

struct PolicyDeferredMessage {
        PolicyCheckResult result;
        PolicyDeferredMessageType type;
        char is_repeat_policy_check_needed:1;

        PolicyItemClass class;
        uid_t uid;
        gid_t gid;
        int message_type;
        char *name;
        char *interface;
        char *path;
        char *member;
        char *label;
        char *privilege;

        /** fields filled by cynara layer */
        PolicyDeferredMessageId *id;
        /** flieds filled by higher level */
        int wakeup_fd;
        PolicyMessageCheckHistory *guard;
        pthread_mutex_t *mutex;
        pthread_cond_t *condition;

        LIST_FIELDS(PolicyDeferredMessage, items);
};

struct PolicyMessageCheckHistory { 
        sd_bus_message *message; 
        PolicyCheckResult result;
	int proxy_state;
        bool is_repeat_policy_check_needed;
        LIST_HEAD(PolicyDeferredMessage, history);
        pthread_rwlock_t history_lock;

        LIST_FIELDS(PolicyMessageCheckHistory, items);
};

int cynara_deferred_message_new(PolicyDeferredMessage **d, PolicyCheckResult result);
PolicyDeferredMessage* cynara_deferred_message_free(PolicyDeferredMessage *d);
void cynara_deferred_message_list_free(PolicyDeferredMessage *d); 
int cynara_deferred_message_new_append(PolicyDeferredMessage **d, PolicyCheckResult result, PolicyDeferredMessage **list);
PolicyDeferredMessage* cynara_deferred_message_append(PolicyDeferredMessage *d,PolicyDeferredMessage *a);

DEFINE_TRIVIAL_CLEANUP_FUNC(PolicyDeferredMessage*, cynara_deferred_message_free);

int cynara_message_check_history_new(PolicyMessageCheckHistory  **d, sd_bus_message *message, PolicyCheckResult result, PolicyDeferredMessage *history);
PolicyMessageCheckHistory* cynara_message_check_history_free(PolicyMessageCheckHistory *dh, BusCynara *cynara);



PolicyMessageCheckHistory* cynara_deferred_check_history_acquire(PolicyMessageCheckHistory *d, bool only_for_read);
void cynara_deferred_check_history_release(PolicyMessageCheckHistory *d); 

int bus_cynara_new(BusCynara **bus_cynara);
BusCynara* bus_cynara_free(BusCynara *bus_cynara);

int cynara_bus_get_fd(BusCynara *cynara);
int cynara_bus_get_events(BusCynara *cynara);

BusCynara* cynara_bus_ref(BusCynara *c);
BusCynara* cynara_bus_unref(BusCynara* c);

DEFINE_TRIVIAL_CLEANUP_FUNC(BusCynara*, bus_cynara_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(BusCynara*, cynara_bus_unref);


CynaraPolicyResult cynara_check_privilege(BusCynara *cynara, PolicyItem *item, const PolicyCheckFilter *filter, PolicyDeferredMessage **deferred_message); 

int cynara_check_request_generate(BusCynara *cynara, int wakeup_fd, PolicyDeferredMessage *deferred_message, sd_bus_message *message, PolicyMessageCheckHistory **out); 
int cynara_message_check_history_replace(PolicyMessageCheckHistory *dh, PolicyDeferredMessage *history, BusCynara* cynara);

int cynara_run_process(BusCynara *cynara);
PolicyCheckResult cynara_wait_for_answer(PolicyDeferredMessage *message);
