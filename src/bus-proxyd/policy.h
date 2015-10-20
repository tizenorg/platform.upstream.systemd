/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright (c) 2015 Samsung Electronics, Ltd.
  Kazimierz Krosman <k.krosman@samsung.com>

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

#include <inttypes.h>
#include <pthread.h>

#include "list.h"
#include "hashmap.h"
#include "set.h"

typedef pthread_t ptid_t;

typedef struct BusCynara BusCynara;
typedef struct PolicyDeferredMessage PolicyDeferredMessage;
typedef struct PolicyMessageCheckHistory PolicyMessageCheckHistory;
typedef struct ProxyContext ProxyContext;

typedef enum PolicyItemType {
        _POLICY_ITEM_TYPE_UNSET = 0,
        POLICY_ITEM_ALLOW,
        POLICY_ITEM_DENY,
        POLICY_ITEM_CHECK,
        _POLICY_ITEM_TYPE_MAX,
        _POLICY_ITEM_TYPE_INVALID = -1,
} PolicyItemType;

typedef enum PolicyItemClass {
        _POLICY_ITEM_CLASS_UNSET = 0,
        POLICY_ITEM_SEND,
        POLICY_ITEM_RECV,
        POLICY_ITEM_OWN,
        POLICY_ITEM_OWN_PREFIX,
        POLICY_ITEM_USER,
        POLICY_ITEM_GROUP,
        POLICY_ITEM_IGNORE,
        _POLICY_ITEM_CLASS_MAX,
        _POLICY_ITEM_CLASS_INVALID = -1,
} PolicyItemClass;

typedef enum PolicyCheckResult {
        POLICY_RESULT_DENY = 0,
        POLICY_RESULT_ALLOW,
        POLICY_RESULT_LATER,
} PolicyCheckResult;

typedef struct PolicyItem PolicyItem;

struct PolicyItem {
        PolicyItemType type;
        PolicyItemClass class;
        char *interface;
        char *member;
        char *error;
        char *path;
        char *name;
        uint8_t message_type;
        uid_t uid;
        gid_t gid;
        char* privilege;

        bool uid_valid, gid_valid;

        LIST_FIELDS(PolicyItem, items);
};

typedef struct Policy {
        LIST_HEAD(PolicyItem, default_items);
        LIST_HEAD(PolicyItem, mandatory_items);
        LIST_HEAD(PolicyItem, on_console_items);
        LIST_HEAD(PolicyItem, no_console_items);
        Hashmap *user_items;
        Hashmap *group_items;
} Policy;


typedef struct PolicyCheckFilter {
        PolicyItemClass class;
        uid_t uid;
        gid_t gid;
        int message_type;
        const char *name;
        const char *interface;
        const char *path;
        const char *member;
        const char *label;
} PolicyCheckFilter;

typedef enum PolicyDeferredMessageType {
        POLICY_DEFERRED_MESSAGE_TYPE_NONE = 0,
        POLICY_DEFERRED_MESSAGE_TYPE_RECV,
        POLICY_DEFERRED_MESSAGE_TYPE_SEND,
        POLICY_DEFERRED_MESSAGE_TYPE_OWN,
        POLICY_DEFERRED_MESSAGE_TYPE_HELLO
} PolicyDeferredMessageType;


